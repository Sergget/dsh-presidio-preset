"""字段覆盖 Phase 0 行为契约。规则 pattern 使用 Python/JS 公共子集。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.engine import PresidioPIIEngine
from presidio_pii.chinese_recognizers import get_chinese_recognizers

RULES = str(Path(__file__).parent.parent / "rule_libraries" / "extended-fields.json")


@pytest.fixture()
def engine(tmp_path):
    return PresidioPIIEngine(db_path=tmp_path / "extended.db", custom_rules=RULES)


@pytest.mark.parametrize("text, value, etype", [
    ("年龄：45岁。", "45岁", "AGE"),
    ("现年 36 周岁", "36 周岁", "AGE"),
    ("出生日期：1990-03-07", "1990-03-07", "BIRTH_DATE"),
    ("生于1985年12月", "1985年12月", "BIRTH_DATE"),
    ("性别：男，民族：汉族", "男", "GENDER"),
    ("性别：男，民族：汉族", "汉族", "ETHNICITY"),
    ("学历：硕士研究生", "硕士研究生", "EDUCATION"),
    ("微信号：zhangsan_2026", "zhangsan_2026", "IM_ACCOUNT"),
    ("工号：EMP-00927", "EMP-00927", "EMPLOYEE_ID"),
])
def test_extended_fields(engine, text, value, etype):
    found = engine.analyze(text)
    assert any(r.entity_type == etype and text[r.start:r.end] == value for r in found), (
        text, [(r.entity_type, text[r.start:r.end]) for r in found])


@pytest.mark.parametrize("text", [
    "适用年龄：20岁以上",
    "招聘年龄：3岁以下",
    "今年有 45 岁树龄的古树",
    "性别平等是基本原则",
    "民族政策持续完善",
    "学历教育研究中心",
])
def test_extended_fields_negative(engine, text):
    found = [r for r in engine.analyze(text) if r.entity_type in {
        "AGE", "BIRTH_DATE", "GENDER", "ETHNICITY", "EDUCATION", "IM_ACCOUNT", "EMPLOYEE_ID"}]
    assert found == [], (text, [(r.entity_type, text[r.start:r.end]) for r in found])


def _entities(text):
    rs = PresidioPIIEngine._resolve_overlaps(
        [r for rec in get_chinese_recognizers() for r in rec.analyze(text)])
    return [(r.entity_type, text[r.start:r.end]) for r in rs]


def test_person_employee_weak_context():
    assert ("PERSON", "范志强") in _entities("员工范志强，男，45岁。")


def test_address_includes_room_number():
    assert ("LOCATION", "天府大道88号3单元501室") in _entities("住址：天府大道88号3单元501室")


def test_organization_excludes_pronoun():
    ents = _entities("他是公司总经理")
    assert ("ORGANIZATION", "他是公司") not in ents


def test_native_place_includes_city():
    assert ("LOCATION", "山东济南") in _entities("籍贯：山东济南")

# ---- 生产配置回归: hooks 必须把内置规则库一起加载 ----
# 事故: 只读 preset 的 custom_rules_path -> 扩展字段库缺席 -> 7 类字段静默失效。
def test_hooks_custom_rules_spec_includes_builtin_library():
    from presidio_pii import hooks
    spec = hooks._custom_rules_spec()
    assert spec, "规则来源不应为空"
    parts = [p.strip() for p in spec.split(";") if p.strip()]
    assert any(p.endswith("extended-fields.json") for p in parts), parts
    assert any("rule_libraries" in p.replace("\\", "/") for p in parts), parts


def test_hooks_engine_knows_all_preset_types(tmp_path, monkeypatch):
    """用生产配置(preset)建引擎, 而不是测试里显式塞规则。"""
    import json
    from presidio_pii import hooks

    repo = Path(__file__).resolve().parents[1]
    preset = repo / ".agent-presets" / "presidio-pii" / "preset.json"
    declared = json.loads(preset.read_text(encoding="utf-8-sig"))["entity_types"]

    monkeypatch.setenv("PII_DSH_PRESET", str(preset))
    monkeypatch.setenv("PII_DSH_DB_PATH", str(tmp_path / "sessions.db"))
    monkeypatch.delenv("PII_DSH_CUSTOM_RULES", raising=False)
    monkeypatch.delenv("PII_DSH_WHITELIST", raising=False)
    hooks.reset_singleton()
    try:
        engine = hooks._get_engine()
        known = engine._known_entity_types(engine._rule_set)
        missing = [t for t in declared if t not in known]
        assert not missing, f"未识别: {missing}"

        sample = "\n".join([
            "年龄 45 周岁，身体健康。",
            "出生日期：1990-03-07。",
            "性别：男，民族：汉族。",
            "学历：硕士研究生。",
            "微信：zhangsan2024 常联系。",
            "工号：EMP-000123 请登记。",
        ])
        rd = engine.redact(sample, "runtime-test", "prompt")
        for t in ("AGE", "BIRTH_DATE", "GENDER", "ETHNICITY", "EDUCATION",
                  "IM_ACCOUNT", "EMPLOYEE_ID"):
            assert t in rd.entity_counts, f"{t} 未命中: {rd.entity_counts}"
    finally:
        hooks.reset_singleton()
