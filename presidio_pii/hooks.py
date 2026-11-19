"""DSH 钩子实现: before_llm / after_llm + 结构化流程日志。

会话语义:
  - session_id 由 conversation_id 派生 (稳定哈希), 同一会话多轮共享还原映射表;
    未传入时按日期派生, 同一天内共享。
  - before_llm 返回脱敏文本; after_llm 用同一 session_id 还原占位符。
  - 每次调用均写入结构化 JSONL 日志, 只记元数据 (实体类型/数量、内容指纹哈希),
    **不记录原文或还原后文本**; 旧字段 raw/transformed 已移除。

环境变量:
  PII_DSH_DB_PATH    覆盖映射库路径
  PII_DSH_LOG_PATH   覆盖日志路径 (设为 "0" 关闭日志)
  PII_DSH_LOG_MAX_BYTES  日志轮转上限 (字节, 默认 10 MB; 0 表示不限额)
  PII_DSH_WHITELIST  白名单文件路径 (每行一个关键词, 命中的区域不脱敏)
  PII_DSH_CUSTOM_RULES  自定义规则文件 (分号分隔多个, .json=正则模板, .py=代码规则)
  PII_DSH_RULES_RELOAD  规则热更新检查间隔 (秒, 默认 1; 0/off 关闭自动检查)
  PII_DSH_PRESET     覆盖 preset.json 路径

配置优先级: 环境变量 > preset.json 的 config 段 > 内置默认值。
preset.json 支持 db_path / whitelist_path / custom_rules_path /
rules_reload_interval 四个字段, 相对路径按仓库根目录解析。
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Tuple

from .db import _harden
from .engine import PresidioPIIEngine
from .journal import DEFAULT_MAX_BYTES, JsonlJournal

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DB = _REPO_ROOT / ".pii_presidio_store" / "sessions.db"
_DEFAULT_LOG = _REPO_ROOT / ".pii_presidio_store" / "hook_log.jsonl"
_DEFAULT_PRESET = _REPO_ROOT / ".agent-presets" / "presidio-pii" / "preset.json"

_ENGINE: PresidioPIIEngine | None = None
_JOURNAL: JsonlJournal | None = None


def _preset_file() -> Path:
    return Path(os.environ.get("PII_DSH_PRESET", str(_DEFAULT_PRESET)))


def _preset_config(strict: bool = False) -> dict:
    """读取 DSH preset.json 的 config 段 (路径可用 PII_DSH_PRESET 覆盖)。

    环境变量优先级高于 preset 配置; 文件缺失时返回空字典 (合法的「全部启用」)。
    文件存在但读不出来时: strict=True 抛 PresetUnreadable (供热更新保留旧值),
    否则告警并返回空字典 (首次加载走安全默认值)。
    """
    fp = _preset_file()
    if not fp.exists():
        return {}
    try:
        data = json.loads(fp.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        if strict:
            raise PresetUnreadable(f"{fp}: {exc}") from exc
        print(f"[pii] preset 配置读取失败 ({fp}): {exc}", file=sys.stderr)
        return {}
    cfg = data.get("config")
    return cfg if isinstance(cfg, dict) else {}


def _preset_path(key: str, strict: bool = False) -> str | None:
    """取 preset 配置中的路径字段。

    相对路径优先按仓库根目录解析 (与默认 db_path 一致), 不存在时再按
    preset.json 所在目录解析 (支持把规则文件与 preset 放一起)。
    strict=True 时读取失败抛 PresetUnreadable。
    """
    value = _preset_config(strict=strict).get(key)
    if not value:
        return None
    p = Path(value)
    if p.is_absolute():
        return str(p)
    candidates = [_REPO_ROOT / p, _preset_file().parent / p]
    return str(next((c for c in candidates if c.exists()), candidates[0]))


def _db_path() -> Path:
    return Path(os.environ.get("PII_DSH_DB_PATH")
                or _preset_path("db_path") or _DEFAULT_DB)


def _whitelist_file(strict: bool = False) -> str | None:
    return (os.environ.get("PII_DSH_WHITELIST")
            or _preset_path("whitelist_path", strict=strict))


def _custom_rules_spec() -> str | None:
    return (os.environ.get("PII_DSH_CUSTOM_RULES")
            or _preset_path("custom_rules_path"))


def _parse_interval(raw, default: float = 1.0) -> float:
    """解析热更新间隔: 秒数, 0/off/false 表示关闭自动检查。"""
    if raw is None:
        return default
    if isinstance(raw, bool):
        return default if raw else 0.0
    if isinstance(raw, (int, float)):
        return max(0.0, float(raw))
    text = str(raw).strip().lower()
    if not text:
        return default
    if text in ("0", "off", "false", "no", "none"):
        return 0.0
    try:
        return max(0.0, float(text))
    except ValueError:
        print(f"[pii] 无法解析规则热更新间隔 {raw!r}, 使用默认 {default}s",
              file=sys.stderr)
        return default


def _rules_reload_interval() -> float:
    """规则热更新检查间隔: 环境变量 > preset 配置 > 默认 1 秒。"""
    raw = os.environ.get("PII_DSH_RULES_RELOAD")
    if raw is None:
        raw = _preset_config().get("rules_reload_interval")
    return _parse_interval(raw)


def _whitelist(strict: bool = False) -> list:
    """从白名单文件读取关键词 (每行一个词, # 注释)。

    文件不存在是合法的「清空白名单」, 仍返回 []。文件存在但读不出来时,
    strict=True 抛 PresetUnreadable (供热更新保留旧值)。
    """
    raw = _whitelist_file(strict=strict)
    if not raw:
        return []
    fp = Path(raw)
    if not fp.exists():
        return []
    try:
        text = fp.read_text(encoding="utf-8-sig")
    except OSError as exc:
        if strict:
            raise PresetUnreadable(f"白名单文件 {fp}: {exc}") from exc
        print(f"[pii] 白名单文件读取失败 ({fp}): {exc}", file=sys.stderr)
        return []
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


class PresetUnreadable(Exception):
    """preset.json 存在但读不出来（解析失败/IO 错误）。

    与「字段缺失」必须区分：字段缺失是合法的「全部启用」，而读不出来是
    异常状态，调用方要么保留旧值（热更新），要么走安全的默认值（首次加载）。
    如果不区分，一次写坏 preset 就会把用户收窄的类型集合悄悄重置成全开。
    """


def _entity_types() -> list:
    """启用的实体类型白名单: env > preset 顶层 entity_types > 全部启用。

    preset.json 里 entity_types 是顶层字段（与 hooks 同级），不是 config 段
    的成员——设置页勾选的就是它。空列表/缺失都表示全部类型启用。

    文件存在但解析失败时抛 PresetUnreadable，绝不静默返回空列表。
    """
    raw = os.environ.get("PII_DSH_ENTITY_TYPES")
    if raw is None:
        fp = _preset_file()
        if fp.exists():
            try:
                data = json.loads(fp.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                raise PresetUnreadable(f"{fp}: {exc}") from exc
            raw = data.get("entity_types")
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [t for t in raw.replace(";", ",").split(",")]
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(t).strip() for t in raw if str(t).strip()]


_PRESET_SIG: tuple | None = None


def _preset_signature() -> tuple | None:
    """preset.json 的 (mtime_ns, size) 签名; 文件不存在时返回 None。"""
    try:
        st = _preset_file().stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _maybe_reload_preset(engine: PresidioPIIEngine) -> None:
    """preset.json 变了就热更新实体类型与白名单, 无需重启 DSH。

    UI 改勾选/白名单路径后写 preset.json, 下次调用即生效。只比对 mtime+size,
    一次 stat 的开销可忽略。

    读取失败时**保留旧值**（宁可沿用上一次已知good配置，也不把用户收窄的
    集合静默重置成全开）。实体类型与白名单分开 try, 互不影响。
    """
    global _PRESET_SIG
    sig = _preset_signature()
    if sig == _PRESET_SIG:
        return
    try:
        engine.set_entity_types(_entity_types())
    except PresetUnreadable as exc:
        print(f"[pii] preset 实体类型读取失败, 保留旧值: {exc}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — 热更新失败不得中断脱敏
        print(f"[pii] 实体类型热更新失败, 保留旧值: {exc}", file=sys.stderr)

    try:
        # strict=True: preset 写坏 / 白名单文件读不出来时抛 PresetUnreadable,
        # 让下面的异常路径真正「保留旧值」, 而不是把白名单静默清空。
        engine.set_whitelist(_whitelist(strict=True))
    except PresetUnreadable as exc:
        print(f"[pii] 白名单读取失败, 保留旧值: {exc}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print(f"[pii] 白名单热更新失败, 保留旧值: {exc}", file=sys.stderr)

    # 即使读取失败也推进签名: 坏状态只告警一次, 不刷屏;
    # 用户修好文件后 mtime+size 变化会再次触发.
    _PRESET_SIG = sig


def _get_engine() -> PresidioPIIEngine:
    global _ENGINE, _PRESET_SIG
    if _ENGINE is None:
        # 传规则来源字符串而非已加载列表, 让引擎能按文件签名热更新;
        # 来源已在此处合并 (env > preset)
        try:
            entity_types = _entity_types()
        except PresetUnreadable as exc:
            # 首次加载读不出 preset 时回退到「全部启用」——这是多脱敏方向,
            # 宁可过度脱敏也不能因为配置坏了就漏脱敏.
            print(f"[pii] preset 实体类型读取失败, 暂时启用全部类型: {exc}",
                  file=sys.stderr)
            entity_types = []
        _ENGINE = PresidioPIIEngine(
            db_path=_db_path(), whitelist=_whitelist(),
            custom_rules=_custom_rules_spec(),
            rules_check_interval=_rules_reload_interval(),
            entity_types=entity_types)
        _PRESET_SIG = _preset_signature()
    else:
        _maybe_reload_preset(_ENGINE)
    return _ENGINE


def reload_rules(force: bool = True) -> int:
    """显式重载自定义规则, 返回当前规则条数。

    agent 改完规则文件后可立即调用; force=False 时仍受检查间隔节流。
    """
    return _get_engine().reload_custom_rules(force=force)


def get_journal() -> JsonlJournal | None:
    """获取流程日志器; 环境变量 PII_DSH_LOG_PATH=0 时关闭。"""
    global _JOURNAL
    if _JOURNAL is None:
        raw = os.environ.get("PII_DSH_LOG_PATH", str(_DEFAULT_LOG))
        _JOURNAL = None if raw == "0" else JsonlJournal(raw, max_bytes=_log_max_bytes())
    return _JOURNAL


def _log_max_bytes() -> int:
    """日志轮转上限: 环境变量 PII_DSH_LOG_MAX_BYTES, 默认 10 MB, 0=不限额。"""
    raw = (os.environ.get("PII_DSH_LOG_MAX_BYTES") or "").strip()
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        print(f"[pii] 无法解析日志上限 {raw!r}, 使用默认 {DEFAULT_MAX_BYTES}",
              file=sys.stderr)
        return DEFAULT_MAX_BYTES


def reset_singleton() -> None:
    """测试辅助: 清空引擎/日志单例 (环境变量变更后调用)。"""
    global _ENGINE, _JOURNAL, _HMAC_KEY, _PRESET_SIG
    _ENGINE = None
    _JOURNAL = None
    _HMAC_KEY = None
    _PRESET_SIG = None


def session_id(conversation_id: str | None) -> str:
    if conversation_id:
        return hashlib.sha1(conversation_id.encode("utf-8")).hexdigest()[:12]
    today = _dt.date.today().isoformat()
    return "daily-" + hashlib.sha1(today.encode("utf-8")).hexdigest()[:8]


def _entity_counts(placeholders: dict) -> dict:
    counts: dict = {}
    for ph in placeholders:
        ptype = ph.strip("⟦⟧").split(":")[1]
        counts[ptype] = counts.get(ptype, 0) + 1
    return counts


_HMAC_KEY: bytes | None = None


def _hmac_key() -> bytes:
    """日志指纹密钥: PII_DSH_LOG_HMAC_KEY > 映射库同目录的 journal_hmac.key > 首次生成。

    密钥与映射库同目录（默认 .pii_presidio_store/），已在 .gitignore 内。
    生成用 0600 权限（Windows 上按当前用户 ACL 收紧），避免同机其他账号读取。
    """
    global _HMAC_KEY
    if _HMAC_KEY is not None:
        return _HMAC_KEY
    env = os.environ.get("PII_DSH_LOG_HMAC_KEY")
    if env:
        _HMAC_KEY = env.encode("utf-8")
        return _HMAC_KEY
    key_file = _db_path().parent / "journal_hmac.key"
    try:
        data = key_file.read_bytes()
        if data:
            # 既有文件也要收紧: 历史版本只做了 chmod, Windows 上 ACL 仍然宽松,
            # 这里统一用 db._harden 补上 (幂等, 失败只告警不阻断)。
            _harden(key_file, directory=False)
            _HMAC_KEY = data
            return _HMAC_KEY
    except OSError:
        pass
    secret = secrets.token_bytes(32)
    try:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(secret)
        # Windows 上 os.chmod(0o600) 只改只读位、不动 ACL, 同机其他账号仍可读;
        # 复用 db._harden (Windows icacls / POSIX chmod 0600) 真正收紧到本人可读写。
        _harden(key_file, directory=False)
    except OSError as exc:
        # 落盘失败时退回进程内密钥: 日志仍不可反查, 但重启后指纹不再一致
        print(f"[pii] 无法写入日志密钥 ({key_file}): {exc}", file=sys.stderr)
    _HMAC_KEY = secret
    return _HMAC_KEY


def _fingerprint(text: str) -> str:
    """内容指纹: HMAC-SHA256 前 16 位, 无密钥不可反查。

    裸 SHA256 对短文本（如 11 位手机号、18 位身份证）可被暴力枚举反推原文,
    因此改用带本地密钥的 HMAC: 没有 ``journal_hmac.key`` 就算拿到日志也无法
    逐条试出原文。密钥首次使用时随机生成并落到映射库同目录（已被 .gitignore
    排除）；``PII_DSH_LOG_HMAC_KEY`` 可显式指定, 便于多机比对同一批日志。
    """
    return hmac.new(_hmac_key(), text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _id_fingerprint(value: str | None) -> str | None:
    """会话/文档标识指纹; 文件名、会话号可能含 PII, 日志只留哈希。"""
    if not value:
        return None
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def before_llm(prompt: str, conversation_id: str | None = None,
               doc_id: str = "prompt") -> str:
    """发送给 LLM 之前调用: 脱敏并登记映射。返回脱敏后的文本。"""
    engine = _get_engine()
    sid = session_id(conversation_id)
    rd = engine.redact(prompt, sid, doc_id)
    journal = get_journal()
    if journal:
        journal.record("before_llm",
                       conv_sha1=_id_fingerprint(conversation_id),
                       session_id=sid,
                       doc_sha1=_id_fingerprint(doc_id),
                       n_replaced=rd.n_replaced,
                       entities=rd.entity_counts,
                       redacted_sha256=_fingerprint(rd.text),
                       chars=len(prompt))
    return rd.text


def after_llm(response: str, conversation_id: str | None = None,
              doc_id: str = "prompt") -> Tuple[str, dict]:
    """LLM 响应返回后调用: 还原占位符。

    返回 (还原后文本, 统计字典)。DSH 若只接受单返回值, 取 [0] 即可。
    """
    engine = _get_engine()
    sid = session_id(conversation_id)
    rs = engine.restore(response, sid, doc_id)
    stats = {"n_restored": len(rs.restored), "n_unrestored": len(rs.unrestored)}
    journal = get_journal()
    if journal:
        journal.record("after_llm",
                       conv_sha1=_id_fingerprint(conversation_id),
                       session_id=sid,
                       doc_sha1=_id_fingerprint(doc_id),
                       n_restored=stats["n_restored"],
                       n_unrestored=stats["n_unrestored"],
                       entities=_entity_counts(rs.restored),
                       response_sha256=_fingerprint(response),
                       chars=len(response))
    return rs.text, stats
