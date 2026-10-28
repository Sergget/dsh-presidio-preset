"""回归测试: 识别器切分边界 + 引擎 redact/restore round-trip。

运行: pytest tests/ -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.chinese_recognizers import get_chinese_recognizers
from presidio_pii.engine import PresidioPIIEngine


@pytest.fixture()
def engine(tmp_path):
    return PresidioPIIEngine(db_path=tmp_path / "test.db")


def _spans(text, etype):
    """返回某实体类型在 demo 分析中的 (start, end, matched_text) 列表。"""
    results = PresidioPIIEngine._resolve_overlaps(
        [r for rec in get_chinese_recognizers() for r in rec.analyze(text)])
    return [(r.start, r.end, text[r.start:r.end])
            for r in results if r.entity_type == etype]


def _all_entities(text):
    results = PresidioPIIEngine._resolve_overlaps(
        [r for rec in get_chinese_recognizers() for r in rec.analyze(text)])
    return {text[r.start:r.end]: r.entity_type for r in results}


# --------------------------------------------------------------------------- #
# 单项识别
# --------------------------------------------------------------------------- #
def test_id_number_valid_checksum():
    ents = _all_entities("身份证号 110101199003077890 请核对")
    assert ents.get("110101199003077890") == "ID_NUMBER"


def test_id_number_invalid_checksum_still_redacted():
    # 校验位错误但行政区划位有效 -> 降分保留 (召回优先)
    ents = _all_entities("证件号 110101199003077899")
    assert ents.get("110101199003077899") == "ID_NUMBER"


def test_id_number_invalid_region_skipped():
    # 行政区划位无效 (99 开头) -> 不按身份证处理
    ents = _all_entities("编号 990101199003077890")
    assert "990101199003077890" not in ents or \
        ents["990101199003077890"] != "ID_NUMBER"


def test_mobile_number():
    ents = _all_entities("手机13800138000联系")
    assert ents.get("13800138000") == "PHONE_NUMBER"


def test_email():
    ents = _all_entities("发送到 a.b@example.com 即可")
    assert ents.get("a.b@example.com") == "EMAIL_ADDRESS"


def test_credit_code_with_letter_check_digit():
    ents = _all_entities("统一代码 91110000123456787H 已登记")
    assert ents.get("91110000123456787H") == "CREDIT_CODE"


# --------------------------------------------------------------------------- #
# 人名边界 (历史回归用例)
# --------------------------------------------------------------------------- #
def test_person_trailing_particle_stripped():
    # "张伟是" 不应把 "是" 吞进人名
    assert ("张伟是中国" , "ORGANIZATION") not in _all_entities("张伟是中国人").items()
    spans = _spans("张伟是中国人", "PERSON")
    assert any(t == "张伟" for _, _, t in spans)


def test_person_not_cut_from_place_name():
    # "渝北区经纪" 内部不应切出 "北区经" 假人名
    assert "北区经" not in _all_entities("重庆市渝北区经纪有限公司")


def test_person_simple_names():
    for text, name in [("李明在开会", "李明"), ("电话留给李飞", "李飞")]:
        spans = _spans(text, "PERSON")
        assert any(t == name for _, _, t in spans), (text, spans)


# --------------------------------------------------------------------------- #
# 地点 / 职务
# --------------------------------------------------------------------------- #
def test_location_beijing_chaoyang():
    ents = _all_entities("张伟是中国银行北京市朝阳区支行行长")
    assert ents.get("北京市朝阳区") == "LOCATION"


def test_job_title():
    ents = _all_entities("他担任总经理一职")
    assert ents.get("总经理") == "JOB_TITLE"


# --------------------------------------------------------------------------- #
# 引擎 redact/restore
# --------------------------------------------------------------------------- #
DEMO_TEXT = """张伟是中国银行北京市朝阳区支行行长, 身份证 110101199003077890,
手机号 13800138000, 邮箱 a.b@bank.com, 统信社 91110000123456787H。
李明在重庆市渝北区经纪有限公司担任总经理, 电话留给李飞。"""


def test_redact_replaces_all_pii(engine):
    sid = engine.registry.create_session()
    rd = engine.redact(DEMO_TEXT, sid, "t1")
    assert rd.n_replaced >= 7
    # 脱敏后文本不应残留明文 PII
    for pii in ["110101199003077890", "13800138000", "a.b@bank.com",
                "张伟", "李明", "李飞"]:
        assert pii not in rd.text, pii
    # 占位符格式正确
    assert "⟦PII:PERSON:0001⟧" in rd.text


def test_restore_round_trip_lossless(engine):
    sid = engine.registry.create_session()
    rd = engine.redact(DEMO_TEXT, sid, "t1")
    rs = engine.restore(rd.text, sid, "t1")
    assert rs.text == DEMO_TEXT
    assert not rs.unrestored
    assert len(rs.restored) == rd.n_replaced


def test_placeholder_seq_follows_text_order(engine):
    sid = engine.registry.create_session()
    rd = engine.redact("张伟和李明开会", sid)
    assert rd.text.index("⟦PII:PERSON:0001⟧") < rd.text.index("⟦PII:PERSON:0002⟧")
    assert rd.restored["⟦PII:PERSON:0001⟧"] == "张伟"
    # "李明开" 属召回优先的过度脱敏 (宁可多脱不可漏), 只断言前缀
    assert rd.restored["⟦PII:PERSON:0002⟧"].startswith("李明")


def test_overlap_priority_person_beats_organization(engine):
    # "张伟" 被机构正则整体覆盖时, PERSON 优先级更高, 应单独脱敏
    sid = engine.registry.create_session()
    rd = engine.redact("张伟是员工", sid)
    assert "⟦PII:PERSON:" in rd.text
    assert "张伟" not in rd.text


def test_no_false_positive_plain_text(engine):
    sid = engine.registry.create_session()
    rd = engine.redact("今天天气很好, 我们去公园散步吧。", sid)
    assert rd.n_replaced == 0


def test_session_isolation(engine):
    sid1 = engine.registry.create_session()
    sid2 = engine.registry.create_session()
    rd = engine.redact("李明的手机号是13800138000", sid1)
    # 另一个 session 没有映射, 无法还原任何内容
    rs = engine.restore(rd.text, sid2)
    assert rs.text == rd.text  # 占位符原样保留
    assert len(rs.restored) == 0
    assert "13800138000" not in rs.text
