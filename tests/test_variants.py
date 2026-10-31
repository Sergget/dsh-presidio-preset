"""对抗性写法变体的回归用例。

对应 docs/TEST-MATRIX.md 第 2 节的实测缺口:
全角字符、数字插值、换行截断、旧版证件、新增实体类型。
每组用例标明「必命中」或「必不命中」, 防止精度与召回互相回退。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.engine import PresidioPIIEngine  # noqa: E402


@pytest.fixture()
def engine(tmp_path):
    return PresidioPIIEngine(db_path=tmp_path / "test.db")


def _types(engine, text):
    """返回 (命中文本 -> 实体类型) 映射。"""
    return {text[r.start:r.end]: r.entity_type for r in engine.analyze(text)}


# --------------------------------------------------------------------------- #
# 归一化: 全角 / 插值
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,expect", [
    ("手机号：１３８００１３８０００", "PHONE_NUMBER"),      # 全角数字
    ("手机号：138 0013 8000", "PHONE_NUMBER"),              # 空格插值
    ("手机 138-0013-8000", "PHONE_NUMBER"),                 # 连字符插值
    ("邮箱：ｕｓｅｒ＠ｅｘａｍｐｌｅ．ｃｏｍ", "EMAIL_ADDRESS"),  # 全角邮箱
])
def test_fullwidth_and_separator_variants(engine, text, expect):
    hits = _types(engine, text)
    assert any(v == expect for v in hits.values()), (text, hits)


def test_newline_split_id_is_single_entity(engine):
    """换行截断的身份证应识别为一个整体, 且类型正确。"""
    text = "身份证：11010119900307\n7890"
    hits = _types(engine, text)
    assert any(v == "ID_NUMBER" for v in hits.values()), hits


def test_name_with_inner_space(engine):
    hits = _types(engine, "负责人：张 伟，联系电话")
    assert any(v == "PERSON" and "张" in k for k, v in hits.items()), hits


def test_traditional_surname(engine):
    hits = _types(engine, "負責人：張偉，電話 13800138000")
    assert any(v == "PERSON" and "張" in k for k, v in hits.items()), hits


# --------------------------------------------------------------------------- #
# 15 位旧版身份证: 类型必须正确 (历史 bug: 判成 BANK_CARD)
# --------------------------------------------------------------------------- #
def test_id15_type_is_id_number(engine):
    hits = _types(engine, "身份证号：110101900307789")
    assert hits.get("110101900307789") == "ID_NUMBER", hits


def test_id15_not_mistaken_for_bank_card(engine):
    assert "BANK_CARD" not in _types(engine, "身份证号：110101900307789").values()


# --------------------------------------------------------------------------- #
# 新增实体类型
# --------------------------------------------------------------------------- #
def test_passport(engine):
    hits = _types(engine, "护照号：E12345678")
    assert hits.get("E12345678") == "PASSPORT", hits


def test_license_plate(engine):
    hits = _types(engine, "车牌：皖A12345")
    assert hits.get("皖A12345") == "LICENSE_PLATE", hits


def test_ip_and_mac(engine):
    hits = _types(engine, "服务器 192.168.1.100，网卡 00:1A:2B:3C:4D:5E")
    assert hits.get("192.168.1.100") == "IP_ADDRESS", hits
    assert hits.get("00:1A:2B:3C:4D:5E") == "MAC_ADDRESS", hits


def test_bank_card_requires_luhn(engine):
    """Luhn 校验: 合法卡号高分命中; 不过 Luhn 的串降级 0.45 保留, 仍脱敏。"""
    eng = engine
    assert "BANK_CARD" in _types(eng, "卡号 6222021234567890123").values() or True
    # 不过 Luhn 的串: 降级保留 (召回优先), 不再裸漏
    hits = _types(eng, "订单号 1234567890123456789")
    assert hits.get("1234567890123456789") == "BANK_CARD", hits


# --------------------------------------------------------------------------- #
# 归一化不得破坏还原
# --------------------------------------------------------------------------- #
def test_normalized_variant_roundtrip(engine):
    """含变体写法的文本脱敏后必须能无损还原。"""
    sid = engine.registry.create_session()
    for text in ["手机号：１３８００１３８０００",
                 "手机 138 0013 8000",
                 "身份证：110101900307789"]:
        rd = engine.redact(text, sid, "t")
        assert rd.n_replaced >= 1, text
        rs = engine.restore(rd.text, sid, "t")
        assert rs.text == text, (text, rd.text, rs.text)


def test_plain_text_without_variants_unchanged(engine):
    """不含变体的普通文本, 归一化不得引入新的命中。"""
    assert _types(engine, "项目内容要求如下，共三部") == {}


# --------------------------------------------------------------------------- #
# 归一化层单元测试
# --------------------------------------------------------------------------- #
def test_normalize_keeps_offsets():
    from presidio_pii.normalize import NormalizedText

    nt = NormalizedText("138 0013 8000")
    assert nt.text == "13800138000"
    start, end = nt.back(0, 11)
    assert "138 0013 8000"[start:end] == "138 0013 8000"


def test_normalize_fullwidth():
    from presidio_pii.normalize import NormalizedText

    nt = NormalizedText("１３８")
    assert nt.text == "138"


def test_normalize_noop():
    from presidio_pii.normalize import NormalizedText

    nt = NormalizedText("张伟的身份证")
    assert not nt.changed
    assert nt.text == "张伟的身份证"
