"""用户自定义识别规则: 正则模板 + Python 代码模板。

面向 DSH 等 agent 接入: 用户(或 agent)只需写一个 JSON/Python 文件声明规则,
无需改动引擎源码。文件路径通过环境变量 PII_DSH_CUSTOM_RULES 或
Engine(custom_rules=...) 注入, preset.json 的 config.custom_rules_path 同源。

规则文件格式 (JSON, 支持两种规则, 可混用):

[
  {
    "name": "employee_id",              // 规则名, 唯一即可
    "entity_type": "EMPLOYEE_ID",       // 产出实体类型 (占位符 ⟦PII:EMPLOYEE_ID:0001⟧)
    "pattern": "工号[:：\\s]*([A-Z]\\d{6})",  // 正则; 若含捕获组则取组1
    "score": 0.9,                        // 可选, 默认 0.8
    "context_hint": ["工号", "编号"],    // 可选: 匹配前方 20 字符内需含任一提示词才生效
    "negative_hint": ["示例", "如"]      // 可选: 前方 20 字符内含任一词则跳过
  },
  {
    "name": "member_no",
    "entity_type": "MEMBER_ID",
    "pattern": "VIP-\\d{8}",
    "validator": "rules_validators.py:check_member"  // 可选: python 模块:函数名
  }
]

代码规则: 单独的 .py 文件, 定义 analyze(text) -> list[tuple[int,int]] (或
list[(start, end, score)]), 及可选 ENTITY_TYPE 常量:

    ENTITY_TYPE = "ORDER_NO"
    def analyze(text):
        ...

代码规则在受控目录下加载: 只信任 PII_DSH_CUSTOM_RULES 明确指向的文件,
import 即执行其中代码 —— 规则文件应与配置一样受访问控制保护。

坐标注意: 正则在原文上匹配 (不经过归一化), 代码规则返回的坐标也应是原文坐标。
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .chinese_recognizers import LightRecognizer, RecognizerResult

_CUSTOM_ENV = "PII_DSH_CUSTOM_RULES"

_CONTEXT_WINDOW = 20  # context_hint / negative_hint 向前看的字符数


class RulesLoadError(Exception):
    """严格模式下规则加载失败 (文件缺失/非法规则/零规则)。"""


def _warn(msg: str) -> None:
    print(f"[custom_rules] {msg}", file=sys.stderr)


@dataclass(frozen=True)
class RuleSpec:
    """一条自定义规则的声明。"""
    name: str
    entity_type: str
    score: float = 0.80
    context_hint: Tuple[str, ...] = ()
    negative_hint: Tuple[str, ...] = ()


class RegexRuleRecognizer(LightRecognizer):
    """由 JSON 模板生成的正则识别器。

    与内置识别器同走 LightRecognizer 通道, 自动获得归一化坐标映射、
    白名单豁免与冲突仲裁, 无需特殊处理。
    """

    def __init__(self, spec: RuleSpec, regex_str: str,
                 validator: Optional[Callable[[str], bool]] = None):
        super().__init__(spec.entity_type, regex_str, score=spec.score,
                         validator=validator)
        self.name = spec.name
        self.spec = spec
        self.wants_raw = True  # 自定义规则按文档约定在原文上匹配 (坐标即原文坐标)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in self.regex.finditer(text):
            # 有捕获组时实体取组 1 (允许 "工号: E123456" 只脱敏号码本身);
            # 组存在但未参与匹配 (None) 时才回退整段
            if m.groups() and m.group(1) is not None:
                s, e = m.start(1), m.end(1)
            else:
                s, e = m.start(), m.end()
            if self.validator and not self.validator(m.group()):
                continue
            if spec_hints_reject(self.spec, text, s):
                continue
            out.append(RecognizerResult(s, e, self.entity_type, self.score))
        return out


def spec_hints_reject(spec: RuleSpec, text: str, start: int) -> bool:
    """根据 context/negative hint 判定该匹配是否应被跳过。"""
    ctx = text[max(0, start - _CONTEXT_WINDOW):start]
    if spec.negative_hint and any(h in ctx for h in spec.negative_hint):
        return True
    if spec.context_hint and not any(h in ctx for h in spec.context_hint):
        return True
    return False


class CodeRuleRecognizer:
    """由 Python 文件加载的代码规则, 约定 analyze(text) 接口。"""

    def __init__(self, module):
        self.module = module
        self.name = getattr(module, "RULE_NAME", module.__name__)
        self.entity_type = getattr(module, "ENTITY_TYPE", "CUSTOM")
        self.score = float(getattr(module, "SCORE", 0.80))
        self.wants_raw = True  # 同正则模板: 原文匹配, 原文坐标
        self._warned = False

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        try:
            items = self.module.analyze(text)
            if items is None:
                raise TypeError("analyze() 返回 None, 应为坐标列表")
            for item in items:
                if len(item) == 3:
                    s, e, score = item
                else:
                    s, e, score = item[0], item[1], self.score
                if s < 0 or e > len(text) or s >= e:
                    continue  # 非法坐标直接丢弃, 不让规则文件弄崩引擎
                out.append(RecognizerResult(s, e, self.entity_type, score))
        except Exception as exc:  # noqa: BLE001 - 用户代码, 单条规则失败不得中断整条流水线
            if not self._warned:
                self._warned = True
                _warn(f"代码规则 {self.name} 执行失败, 后续跳过: "
                      f"{type(exc).__name__}: {exc}")
            return []
        return out


def load_json_rules(path: Path, strict: bool = False) -> List:
    """从 JSON 文件加载正则规则。

    strict=True 时任一规则非法即抛 RulesLoadError (显式指定规则却部分丢失,
    在脱敏场景等同漏检); 默认宽松模式跳过非法规则并写 stderr。
    """
    rules: List = []
    errors: List[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        if strict:
            raise RulesLoadError(f"{path}: {exc}") from exc
        _warn(f"规则文件读取失败 {path}: {exc}")
        return []
    for item in data:
        try:
            spec = RuleSpec(
                name=item["name"],
                entity_type=item["entity_type"],
                score=float(item.get("score", 0.80)),
                context_hint=tuple(item.get("context_hint", ())),
                negative_hint=tuple(item.get("negative_hint", ())),
            )
            validator = _resolve_validator(item.get("validator"), path.parent)
            rules.append(RegexRuleRecognizer(spec, item["pattern"], validator))
        except (KeyError, re.error, ValueError, TypeError, ImportError,
                AttributeError, OSError) as exc:
            msg = f"跳过非法规则 {item.get('name', '?') if isinstance(item, dict) else '?'}: {exc}"
            if strict:
                errors.append(msg)
            else:
                _warn(msg)
    if strict and errors:
        raise RulesLoadError("; ".join(errors))
    return rules


def _resolve_validator(ref: Optional[str], base_dir: Path) -> Optional[Callable]:
    """解析 "模块路径:函数名" 形式的校验函数引用 (相对路径按规则文件目录)。"""
    if not ref:
        return None
    mod_name, _, func_name = ref.partition(":")
    if not func_name:
        raise ValueError(f"validator 需为 '模块路径:函数名' 形式: {ref}")
    mod = _import_path(mod_name, base_dir)
    fn = getattr(mod, func_name)
    if not callable(fn):
        raise TypeError(f"{ref} 不是可调用对象")
    return fn


def _import_path(path_str: str, base_dir: Optional[Path] = None):
    """按路径导入 Python 模块。

    相对路径依次尝试 base_dir (规则文件所在目录) 与当前工作目录,
    与 "规则文件旁放校验模块" 的常见布局一致。
    """
    p = Path(path_str)
    if not p.is_absolute():
        candidates = ([base_dir / p] if base_dir else []) + [Path.cwd() / p]
        p = next((c for c in candidates if c.exists()), candidates[0])
    mod_name = f"pii_custom_{abs(hash(str(p.resolve())))}"
    spec = importlib.util.spec_from_file_location(mod_name, p)
    if spec is None or spec.loader is None:
        raise ImportError(f"无法加载模块: {p}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # pickle / typing 等场景需要模块可查
    try:
        spec.loader.exec_module(mod)  # noqa: S102 - 仅加载用户显式指定的规则文件
    except BaseException:
        sys.modules.pop(mod_name, None)
        raise
    return mod


def load_code_rules(path: Path, strict: bool = False) -> List[CodeRuleRecognizer]:
    try:
        mod = _import_path(str(path))
    except Exception as exc:  # noqa: BLE001 - 规则文件 import 期错误统一处理
        if strict:
            raise RulesLoadError(f"{path}: {type(exc).__name__}: {exc}") from exc
        _warn(f"代码规则加载失败 {path}: {type(exc).__name__}: {exc}")
        return []
    if not callable(getattr(mod, "analyze", None)):
        msg = f"代码规则 {path} 缺少 analyze(text) 函数"
        if strict:
            raise RulesLoadError(msg)
        _warn(msg)
        return []
    return [CodeRuleRecognizer(mod)]


def load_custom_rules(value: Optional[str] = None, strict: bool = False) -> List:
    """入口: 解析 PII_DSH_CUSTOM_RULES (或显式传入) 并加载全部规则。

    支持分号/逗号分隔多个文件, 按扩展名分发: .json -> 正则模板, .py -> 代码规则。
    strict=True 时任何文件缺失、类型不支持或规则全部非法都会抛 RulesLoadError,
    用于 CLI --rules 等显式指定场景; 环境变量走宽松模式, 避免 hook 初始化即崩溃。
    """
    raw = value if value is not None else os.environ.get(_CUSTOM_ENV)
    if not raw:
        return []
    rules: List = []
    errors: List[str] = []
    for part in re.split(r"[;,]", raw):
        part = part.strip()
        if not part:
            continue
        p = Path(part)
        if not p.exists():
            msg = f"规则文件不存在: {part}"
            if strict:
                errors.append(msg)
            else:
                _warn(msg)
            continue
        try:
            if p.suffix.lower() == ".json":
                rules.extend(load_json_rules(p, strict=strict))
            elif p.suffix.lower() == ".py":
                rules.extend(load_code_rules(p, strict=strict))
            else:
                raise RulesLoadError(f"不支持的规则文件类型: {part}")
        except RulesLoadError as exc:
            if strict:
                errors.append(str(exc))
            else:
                _warn(str(exc))
    if strict and errors:
        raise RulesLoadError("; ".join(errors))
    return rules
