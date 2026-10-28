"""自定义中文 PII 识别器 (轻量, 零 spaCy 依赖)。

对接 Microsoft Presidio 概念模型:
  Recognizer.analyze(text) -> List[RecognizerResult(start, end, entity_type)]

覆盖类别:
  - ID_NUMBER       : 身份证号 (含校验位验证)
  - PHONE_NUMBER    : 大陆手机号
  - EMAIL_ADDRESS   : 邮箱
  - CREDIT_CODE     : 统一社会信用代码 (GB 32100 字符集)
  - BANK_CARD       : 银行卡 (13-19 位, 可能含分隔符)
  - PERSON          : 中文人名 (姓 + 1-2 字名, 去除尾部虚词)
  - LOCATION        : 县级行政区 (词表匹配)
  - ORGANIZATION    : 单位机构 (后缀匹配)
  - JOB_TITLE       : 职务/职衔 (词表匹配)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

_ASSETS_DIR = Path(__file__).parent / "assets"

# --------------------------------------------------------------------------- #
# 身份证号校验位 (GB/T 11643-1999)
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

# 18 位身份证号 (含最后一位校验); 用 lookaround 而非 \b,
# 因为 Python re 中汉字属于 \w, \b 在 "号110101..." 这类数字紧邻汉字处会失效
_RE_ID = r"(?<![0-9Xx])[1-9]\d{16}[\dXx](?![0-9Xx])"
# 大陆手机号
_RE_MOBILE = r"(?<!\d)1[3-9]\d{9}(?!\d)"
# 邮箱
_RE_EMAIL = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
# 统一社会信用代码 (GB 32100-2015 字符集: 排除 I/O/S/V/Z, 首位为 1/5/9/Y)
_RE_CREDIT = r"(?<![0-9A-Z])[159Y][0-9A-HJ-NPQRTUWXY]\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Z])"
# 银行卡 (13-19 位数字, 可能包含空格/连字符分隔)
_RE_BANK = r"(?<![\d\-])\d(?:[ -]?\d){12,18}(?![\d\-])"


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

# 人名尾部虚词/常用单字: 匹配到的候选若以这些字结尾则逐字回退
_PERSON_TAIL_STOP = set("是在和与的了于向从被把对给到等也都就还及或并让使为以至会能要该此说"
                        "告叫跟但很之")
# 人名前方阻断字: 紧邻这些字 (多为行政区划/机构词尾) 时不视为人名起始
_PERSON_PRE_BLOCK = set("省市区县镇乡村路街巷道号栋室层楼门司中行")
# 行政区划后缀字: 候选人名第 2 字若为这些字 (如 "北区经" 出自 "渝北区"),
# 大概率是地名内部切分, 予以拒绝
_PLACE_CHARS = set("省市区县镇乡村旗盟路街巷道号栋室楼门")

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
# 身份证识别器 (带校验位验证; 校验失败但行政区划位有效时降级保留, 保证召回)
# --------------------------------------------------------------------------- #
class ChineseIDRecognizer(LightRecognizer):
    def __init__(self):
        super().__init__("ID_NUMBER", _RE_ID, score=0.95)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in re.finditer(_RE_ID, text):
            s = m.group()
            if s[:2] not in _CITY_CODES:
                continue  # 行政区划位无效, 视为普通长数字串
            full_valid = _id_valid(s)
            out.append(RecognizerResult(m.start(), m.end(), self.entity_type,
                                        0.95 if full_valid else 0.70))
        return out


# --------------------------------------------------------------------------- #
# 人名 (姓 + 1-2 字名)
# --------------------------------------------------------------------------- #
class ChinesePersonRecognizer(LightRecognizer):
    def __init__(self):
        self._surname_chars = re.escape("".join(SURNAMES))
        # 姓 + 1-2 字名; 前方阻断字排除行政区划/机构词内部切分
        super().__init__("PERSON",
                         r"(?<![" + re.escape("".join(_PERSON_PRE_BLOCK)) + r"])"
                         r"[" + self._surname_chars + r"][\u4e00-\u9fa5]{1,2}",
                         score=0.75)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in self.regex.finditer(text):
            name = m.group()
            # 回退尾部虚词: "张伟是" -> "张伟"
            while len(name) > 2 and name[-1] in _PERSON_TAIL_STOP:
                name = name[:-1]
            if not (2 <= len(name) <= 3
                    and re.fullmatch(r"[\u4e00-\u9fa5]+", name)
                    and name[0] in SURNAMES):
                continue
            # 第 2 字为行政区划后缀 -> 大概率是地名内部切分 ("北区经" 出自 "渝北区")
            if len(name) >= 2 and name[1] in _PLACE_CHARS:
                continue
            out.append(RecognizerResult(m.start(), m.start() + len(name),
                                        self.entity_type, self.score))
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
            r"[\u4e00-\u9fa5]{2,12}?(?:股份有限公司|有限公司|公司|集团|局|部|处|"
            r"院|所|大学|学院|医院|银行|商行|中心)",
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
        LightRecognizer("PHONE_NUMBER", _RE_MOBILE, score=0.88),
        LightRecognizer("EMAIL_ADDRESS", _RE_EMAIL, score=0.85),
        LightRecognizer("CREDIT_CODE", _RE_CREDIT, score=0.85),
        LightRecognizer("BANK_CARD", _RE_BANK, score=0.60),
        ChinesePersonRecognizer(),
        ChineseLocationRecognizer(),
        ChineseOrganizationRecognizer(),
        ChineseJobTitleRecognizer(),
    ]
