"""门禁 #14 (Python 端): 生产配置下的实体类型接线检查。

事故背景: Phase 0 补齐 7 类扩展字段后, golden 与门禁 #1 全绿, 但真实启动报
    [pii] 忽略未知实体类型 ["AGE", ..., "IM_ACCOUNT"]
原因: 门禁 #1 在测试里显式传 custom_rules, 断言了一套生产不用的配置; 运行时的
hooks 层只加载 preset 的 custom_rules_path, 内置规则库缺席。
同一时期还发现 Python 端 _known_entity_types 不含 _PRIO, 把 MAC_ADDRESS 判成
未知类型并从白名单里静默剔除。

本检查只走生产路径: preset.json -> hooks -> 引擎。
退出码 0 = PASS; 打印一行 JSON 供门禁采集。
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

PRESET = REPO / ".agent-presets" / "presidio-pii" / "preset.json"

SAMPLE = "\n".join([
    "年龄 45 周岁，身体健康。",
    "出生日期：1990-03-07。",
    "性别：男，民族：汉族。",
    "学历：硕士研究生。",
    "微信：zhangsan2024 常联系。",
    "工号：EMP-000123 请登记。",
    "联系电话 13800138000，身份证 110101199003077890。",
    "MAC 地址 00:1A:2B:3C:4D:5E。",
])
EXPECT_TYPES = ["AGE", "BIRTH_DATE", "GENDER", "ETHNICITY", "EDUCATION",
                "IM_ACCOUNT", "EMPLOYEE_ID", "MAC_ADDRESS"]


def main() -> int:
    declared = json.loads(PRESET.read_text(encoding="utf-8-sig")).get("entity_types") or []
    result = {"declared": len(declared), "missing": [], "unproduced": [],
              "unknown_warning": False, "error": None}

    tmp = tempfile.mkdtemp(prefix="pii-gate14-")
    os.environ["PII_DSH_PRESET"] = str(PRESET)
    os.environ["PII_DSH_DB_PATH"] = str(Path(tmp) / "sessions.db")
    os.environ["PII_DSH_LOG_PATH"] = "0"
    os.environ.pop("PII_DSH_CUSTOM_RULES", None)
    os.environ.pop("PII_DSH_WHITELIST", None)

    from presidio_pii import hooks  # noqa: E402  (需先设好环境变量)

    buf = io.StringIO()
    hooks.reset_singleton()
    try:
        with contextlib.redirect_stderr(buf):
            engine = hooks._get_engine()
            known = engine._known_entity_types(engine._rule_set)
            result["missing"] = sorted(t for t in declared if t not in known)
            rd = engine.redact(SAMPLE, "gate14", "prompt")
            counts = dict(rd.entity_counts)
            result["unproduced"] = sorted(t for t in EXPECT_TYPES if t not in counts)
    except Exception as exc:  # noqa: BLE001 - 门禁需要把异常转成失败证据
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        hooks.reset_singleton()

    captured = buf.getvalue()
    result["unknown_warning"] = "忽略未知实体类型" in captured
    if result["unknown_warning"]:
        result["warning_text"] = captured.strip()[:400]

    ok = (not result["error"] and not result["missing"] and not result["unproduced"]
          and not result["unknown_warning"])
    result["ok"] = ok
    print("RUNTIME_TYPES " + json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
