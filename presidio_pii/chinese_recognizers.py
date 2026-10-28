"""自定义中文 PII 识别器 (轻量, 零 spaCy 依赖)。

对接 Microsoft Presidio 概念模型:
  Recognizer.analyze(text) -> List[RecognizerResult(start, end, entity_type)]

覆盖类别:
  - ID_NUMBER       : 身份证号 (含校验位) / 手机号 / 邮箱 / 信用代码 / 银行卡
  - PERSON          : 中文人名 (姓 + 1-2 字名)
  - LOCATION        : 县级行政区 (词表匹配)
  - ORGANIZATION    : 单位机构 (后缀匹配)
  - JOB_TITLE       : 职务/职衔 (词表匹配)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .db import SessionRegistry  # noqa: F401 (engine.py 聚合时顺便导入)

_ASSETS_DIR = Path(__file__).parent / "assets"

# --------------------------------------------------------------------------- #
# 身份证号校验位 (GB/T 8168-2006)
# --------------------------------------------------------------------------- #
_CITY_CODES = {
    "11": "北京", "12": "天津", "13": "河北", "14": "山西", "15": "内蒙",
    "21": "辽宁", "22": "吉林", "23": "黑龙江", "31": "上海", "32": "江苏",
    "33": "浙江", "34": "安徽", "35": "福建", "36": "江西", "37": "山东",
    "41": "河南", "42": "湖北", "43": "湖南", "44": "广东", "45": "广西",
    "46": "海南", "50": "重庆", "51": "四川", "52": "贵州", "53": "云南",
    "54": "西藏", "61": "陕西", "62": "甘肃", "63": "青海", "64": "宁夏",
    "65": "新疆",
}
_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 5, 7, 9, 10, 5, 8, 4, 2, 1]
_MOD_MAP = "10X98765432"

# 18 位身份证号 (含最后一位校验)
_RE_ID = re.compile(r"[1-9]\d{16}[\dXx]")
# 手机号
_RE_MOBILE = re.compile(r"\b1[3-9]\d{9}\b")
# 邮箱
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# 统一社会信用代码 (宽松: 18/21位数字或字母)
_RE_CREDIT = re.compile(r"\b[91]\d{17}\b")
# 银行卡 (13-19 位数字, 可能包含分隔符)
_RE_BANK = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _id_valid(s: str) -> bool:
    if not re.fullmatch(r"[1-9]\d{16}[\dXx]", s):
        return False
    if s[:2] not in _CITY_CODES:
        return False
    total = sum(int(s[i]) * _WEIGHTS[i] for i in range(18))
    return s[17].upper() == _MOD_MAP[total % 11]


# --------------------------------------------------------------------------- #
# 词表加载
# --------------------------------------------------------------------------- #
def _load_lines(name: str) -> List[str]:
    fp = _ASSETS_DIR / name
    if not fp.exists():
        return []
    return [ln.strip() for ln in fp.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")]


SURNAMES = set(_load_lines("surnames.txt"))
SURNAME_RE = re.compile("^[" + re.escape("".join(SURNAMES)) + r"]")
_CH_NAME = re.compile(r"[\u4e00-\u9fa5]+")


# --------------------------------------------------------------------------- #
# Result dataclass (Presidio RecognizerResult 概念兼容)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RecognizerResult:
    start: int
    end: int
    entity_type: str
    score: float = 1.0


class LightRecognizer:
    """基于正则的轻量识别器 (Presidio Recognizer 概念兼容)。"""

    def __init__(self, entity_type: str, regex_str: str = "", score: float = 1.0,
                 validator=None):
        self.entity_type = entity_type
        self.regex = re.compile(regex_str) if regex_str else None
        self.score = score
        self.validator = validator  # callable(text)->bool

    def analyze(self, text: str) -> List[RecognizerResult]:
        if not self.regex:
            return []
        out = []
        for m in self.regex.finditer(text):
            s, e = m.start(), m.end()
            val = m.group()
            if self.validator and not self.validator(val):
                continue
            out.append(RecognizerResult(s, e, self.entity_type, self.score))
        return out


# --------------------------------------------------------------------------- #
# 身份证识别器 (带校验位验证)
# --------------------------------------------------------------------------- #
class ChineseIDRecognizer(LightRecognizer):
    def __init__(self):
        super().__init__("ID_NUMBER", r"[1-9]\d{16}[\dXx]", score=0.95,
                         validator=_id_valid)


# --------------------------------------------------------------------------- #
# 手机号 / 邮箱 / 信用代码 / 银行卡
# --------------------------------------------------------------------------- #
class ChineseContactRecognizer(LightRecognizer):
    def __init__(self):
        # 用 | 把多个模式合并, 在 analyze 时逐一匹配
        super().__init__("ID_NUMBER", score=0.85)
        self.patterns = [
            (re.compile(r"\b1[3-9]\d{9}\b"), 0.88),                 # 手机号
            (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), 0.85),  # 邮箱
            (re.compile(r"\b[91]\d{17}\b"), 0.85),                  # 信用代码
            (re.compile(r"\b(?:\d[ -]?){13,19}\b"), 0.60),          # 银行卡
        ]

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for pat, score in self.patterns:
            for m in pat.finditer(text):
                out.append(RecognizerResult(m.start(), m.end(),
                                            self.entity_type, score))
        return out


# --------------------------------------------------------------------------- #
# 人名 (姓 + 1-2 字名)
# --------------------------------------------------------------------------- #
class ChinesePersonRecognizer(LightRecognizer):
    def __init__(self):
        self._surname_chars = re.escape("".join(SURNAMES))
        # 严格限制: 姓 + 1-2 字名, 且不能紧跟在特定词后面
        super().__init__("PERSON",
                         r"(?<![中行市区])[" + self._surname_chars + r"][\u4e00-\u9fa5]{1,2}",
                         score=0.75)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in self.regex.finditer(text):
            start, end = m.start(), m.end()
            name = m.group()
            # 必须全中文且首字在姓氏表中
            if not (re.fullmatch(r"[\u4e00-\u9fa5]{2,3}", name) and name[0] in SURNAMES):
                continue
            out.append(RecognizerResult(start, end, self.entity_type, self.score))
        return out


# --------------------------------------------------------------------------- #
# 县级地名 (词表)
# --------------------------------------------------------------------------- #
class ChineseLocationRecognizer(LightRecognizer):
    def __init__(self):
        areas = sorted(_load_lines("admin_areas.txt"), key=len, reverse=True)
        pattern = r"|".join(re.escape(a) for a in areas) if areas else r"[\u4e00-\u9fa5]{2,5}[区县]"
        super().__init__("LOCATION", pattern, score=0.85)


# --------------------------------------------------------------------------- #
# 组织机构 (机构后缀)
# --------------------------------------------------------------------------- #
class ChineseOrganizationRecognizer(LightRecognizer):
    def __init__(self):
        super().__init__(
            "ORGANIZATION",
            r"[\u4e00-\u9fa5]{2,12}?(?:公司|集团|局|部|处|院|所|大学|学院|医院|"
            r"银行|商行|中心|股份有限公司|有限公司|研发|经纪有限公司)",
            score=0.80)


# --------------------------------------------------------------------------- #
# 职务/职衔
# --------------------------------------------------------------------------- #
class ChineseJobTitleRecognizer(LightRecognizer):
    def __init__(self):
        titles = sorted(_load_lines("titles.txt"), key=len, reverse=True)
        pat = r"(?:" + "|".join(re.escape(t) for t in titles) + r")" if titles else r"(?:经理|主任|处长|局长|科长|总监|董事长|教授|工程师|顾问|管理员)"
        super().__init__("JOB_TITLE", pat, score=0.75)


# --------------------------------------------------------------------------- #
# 注册入口
# --------------------------------------------------------------------------- #
def get_chinese_recognizers():
    return [
        ChineseIDRecognizer(),
        ChineseContactRecognizer(),
        ChinesePersonRecognizer(),
        ChineseLocationRecognizer(),
        ChineseOrganizationRecognizer(),
        ChineseJobTitleRecognizer(),
    ]
