"""名单型人名识别器回归测试（全合成值，不含真实 PII）。

对应缺陷：常规 ChinesePersonRecognizer 的「非人名字」黑名单 + jieba 词性
会把显式名单链里的罕见姓 / 3 字名 / 复姓 / 带学号后缀的名字整条漏掉：
    「邝也」「陈敬之」「杨同初（26）」「欧阳娜娜」

ChineseRosterPersonRecognizer 以「名单引导词 + 冒号 + 顿号链」为强上下文，
在名单内放宽用字过滤，同时用「每项 2-4 纯汉字 + 首字为姓 + 非停用词/常用词」
与「整行无负样本词」压住误报。
"""
from __future__ import annotations

import re

import pytest

from presidio_pii import segmentation
from presidio_pii.chinese_recognizers import ChineseRosterPersonRecognizer
from presidio_pii.engine import PresidioPIIEngine


@pytest.fixture
def engine(tmp_path):
    return PresidioPIIEngine(db_path=tmp_path / "roster.db", custom_rules=[])


def _spans(text):
    return [r for r in ChineseRosterPersonRecognizer().analyze(text)
            if r.entity_type == "PERSON"]


def _entities(text):
    return {text[r.start:r.end] for r in _spans(text)}


# ---- 正向：历史漏检的四个形态 ----
def test_roster_line_covers_hard_names(engine):
    text = ("- **原班级学号名单（28人）**："
            "张三、李四、王五、赵六、邝也、陈敬之、杨同初（26）、欧阳娜娜、孙七。")
    sid = engine.registry.create_session()
    rd = engine.redact(text, sid, "roster")
    rs = engine.restore(rd.text, sid, "roster")
    for name in ("邝也", "陈敬之", "杨同初", "欧阳娜娜"):
        assert name not in rd.text, f"漏检: {name}"
    assert rd.entity_counts.get("PERSON", 0) >= 8
    assert re.findall(r"\s+", rd.text) == re.findall(r"\s+", text)
    assert rs.text == text
    assert rs.unrestored == {}


def test_roster_recognizer_spans_exclude_student_id():
    text = "名单：张三、杨同初（26）、李四、欧阳娜娜。"
    got = _entities(text)
    assert {"张三", "杨同初", "李四", "欧阳娜娜"} <= got
    # 只 emit 名字本身，不含「（26）」学号后缀
    assert "杨同初（26）" not in got
    assert "（26）" not in got


def test_roster_restore_keeps_student_id(engine):
    text = "名单：张三、杨同初（26）、李四。"
    sid = engine.registry.create_session()
    rd = engine.redact(text, sid, "span")
    assert "（26）" in rd.text
    assert engine.restore(rd.text, sid, "span").text == text


def test_roster_compound_surnames():
    text = "花名册：欧阳娜娜、司马相如、诸葛小明、上官婉儿。"
    got = _entities(text)
    assert {"欧阳娜娜", "司马相如", "诸葛小明", "上官婉儿"} <= got


# ---- 负向：名单识别器不得在普通文本上产出 PERSON ----
PURE_NEGATIVE = [
    "以上均不含身份证、手机号、银行卡、人名等个人信息。",   # 3 个顿号，最危险
    "本项目内容要求分三个部分：第一部讲架构，第二部讲实施，第三部讲运维。",
    "内容要求如下", "本项目分为第一部", "资金约 100 万元", "系统已经成熟",
    "第三方服务", "所有部门都要参与", "按照每个部门的要求", "关键在于第三章",
    "用户数量达到百万级", "原则上不允许", "成品软件采购", "政协委员履职管理",
    "今天天气很好, 我们去公园散步吧。",
    "张伟和李明开会",                       # 「和」不是名单分隔符
    "张伟和李明的手机号 13800138000",
]


@pytest.mark.parametrize("text", PURE_NEGATIVE)
def test_roster_no_false_positive(text):
    assert _spans(text) == [], text


@pytest.mark.parametrize("text", PURE_NEGATIVE[:15])
def test_roster_pure_negative_whole_engine(engine, text):
    sid = engine.registry.create_session()
    rd = engine.redact(text, sid, "pneg")
    assert rd.entity_counts.get("PERSON", 0) == 0, text


# ---- 双模式：装 jieba 与无 jieba 各跑一次（agent.md:82）----
def test_roster_without_jieba(engine, monkeypatch):
    monkeypatch.setattr(segmentation, "_HAS_JIEBA", False)
    text = "名单：张三、邝也、陈敬之、杨同初（26）、欧阳娜娜。"
    got = _entities(text)
    assert {"邝也", "陈敬之", "杨同初", "欧阳娜娜"} <= got
    sid = engine.registry.create_session()
    rd = engine.redact(text, sid, "nojieba")
    for name in ("邝也", "陈敬之", "杨同初", "欧阳娜娜"):
        assert name not in rd.text, name
    assert engine.restore(rd.text, sid, "nojieba").text == text
