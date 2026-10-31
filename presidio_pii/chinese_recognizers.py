"""自定义中文 PII 识别器 (轻量, 零 spaCy 依赖)。

对接 Microsoft Presidio 概念模型:
  Recognizer.analyze(text) -> List[RecognizerResult(start, end, entity_type)]

覆盖类别:
  - ID_NUMBER       : 身份证号 (含校验位验证)
  - PHONE_NUMBER    : 大陆手机号
  - EMAIL_ADDRESS   : 邮箱
  - CREDIT_CODE     : 统一社会信用代码 (GB 32100 字符集)
  - BANK_CARD       : 银行卡 (13-19 位, 可能含分隔符)
  - PERSON          : 中文人名 (姓 + 1-2 字名, 带左右上下文与用字过滤)
  - LOCATION        : 省/市/县/区地名 (词表 + 通名规则)
  - ORGANIZATION    : 单位机构 (后缀匹配 + 右边界 + 虚词剥离)
  - JOB_TITLE       : 职务/职衔 (词表匹配 + 右边界)

中文没有空格分词, 纯字符正则会把 "内容要求" 里的 "容要求"、把 "部门" 切出的 "部"
误判成实体。因此除人名外, 所有规则都要求**右边界** (实体后紧跟标点/空白/句末),
人名则要求**左边界** (前面是标点/空白, 或"由/和/给"这类引导字) 并用非人名字过滤,
以在保持召回的同时压掉大部分误报。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

from . import segmentation

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
# 15 位旧版身份证 (1999 年前签发, 无校验位)
_RE_ID15 = r"(?<![0-9])[1-9]\d{14}(?![0-9])"
# 大陆手机号
_RE_MOBILE = r"(?<!\d)1[3-9]\d{9}(?!\d)"
# 座机: 区号(0xx / 0xxx) + 7-8 位, 允许连字符或空格分隔
_RE_LANDLINE = r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)"
# 邮箱
_RE_EMAIL = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
# 统一社会信用代码 (GB 32100-2015 字符集: 排除 I/O/S/V/Z, 首位为 1/5/9/Y)
_RE_CREDIT = r"(?<![0-9A-Z])[159Y][0-9A-HJ-NPQRTUWXY]\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Z])"
# 银行卡 (13-19 位数字); 由 Luhn 校验兜底, 避免长数字串一律判成卡号
_RE_BANK = r"(?<![\d\-])\d(?:[ -]?\d){12,18}(?![\d\-])"
# 护照 / 港澳通行证: 字母前缀 + 8 位数字 (E=电子护照, G/M=旧版, C/H=港澳)
_RE_PASSPORT = r"(?<![0-9A-Za-z])[EGMDCHS][A-Z0-9]?\d{8}(?![0-9A-Za-z])"
# 中国大陆车牌: 省份简称 + 发牌机关字母 + 5 位序号 (含新能源)
_PLATE_PROVINCE = ("京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新")
_RE_PLATE = (r"(?<![0-9A-Za-z一-龥])[" + _PLATE_PROVINCE + r"][A-HJ-NP-Z]"
             r"[A-HJ-NP-Z0-9]{4}[A-HJ-NP-Z0-9挂学警港澳领](?![0-9A-Za-z])")
# IPv4 (lookahead/lookbehind 只排除数字与点, 避免 "1.2.3.4.5" 与版本号误判)
_RE_IPV4 = (r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
# MAC 地址
_RE_MAC = (r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")


def _id_valid(s: str) -> bool:
    if not re.fullmatch(r"[1-9]\d{16}[\dXx]", s):
        return False
    if s[:2] not in _CITY_CODES:
        return False
    # 前 17 位加权求和, 第 18 位为校验位 (可能是 X)
    total = sum(int(s[i]) * _WEIGHTS[i] for i in range(17))
    return s[17].upper() == _MOD_MAP[total % 11]


def _id15_valid(s: str) -> bool:
    """15 位旧版身份证: 无校验位, 仅校验行政区划与出生日期段。"""
    if not re.fullmatch(r"[1-9]\d{14}", s):
        return False
    if s[:2] not in _CITY_CODES:
        return False
    year, month, day = int(s[6:8]), int(s[8:10]), int(s[10:12])
    # 1900-1999 年间签发; 月份与日期做范围校验
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    return year <= 99


def _luhn(s: str) -> bool:
    """Luhn 校验 (银行卡号)。"""
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


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

# 繁体姓氏 -> 简体: 港澳台与海外文档常见, 不做转换会整批漏检
_T2S_SURNAME = {
    "張": "张", "劉": "刘", "陳": "陈", "楊": "杨", "黃": "黄", "趙": "赵",
    "吳": "吴", "周": "周", "徐": "徐", "孫": "孙", "馬": "马", "朱": "朱",
    "胡": "胡", "郭": "郭", "何": "何", "高": "高", "林": "林", "羅": "罗",
    "鄭": "郑", "梁": "梁", "謝": "谢", "宋": "宋", "唐": "唐", "許": "许",
    "韓": "韩", "馮": "冯", "鄧": "邓", "曹": "曹", "彭": "彭", "曾": "曾",
    "蕭": "萧", "田": "田", "董": "董", "袁": "袁", "潘": "潘", "於": "于",
    "蔣": "蒋", "蔡": "蔡", "餘": "余", "杜": "杜", "葉": "叶", "程": "程",
    "蘇": "苏", "魏": "魏", "呂": "吕", "丁": "丁", "任": "任", "瀋": "沈",
    "姚": "姚", "盧": "卢", "薑": "姜", "崔": "崔", "鐘": "钟", "譚": "谭",
    "陸": "陆", "汪": "汪", "範": "范", "金": "金", "石": "石", "廖": "廖",
    "賈": "贾", "夏": "夏", "韋": "韦", "付": "付", "方": "方", "白": "白",
    "鄒": "邹", "孟": "孟", "熊": "熊", "秦": "秦", "邱": "邱", "江": "江",
    "尹": "尹", "薛": "薛", "閻": "闫", "段": "段", "雷": "雷", "侯": "侯",
    "龍": "龙", "史": "史", "陶": "陶", "黎": "黎", "賀": "贺", "顧": "顾",
    "毛": "毛", "郝": "郝", "龔": "龚", "邵": "邵", "萬": "万", "錢": "钱",
    "嚴": "严", "覃": "覃", "武": "武", "戴": "戴", "莫": "莫", "孔": "孔",
    "湯": "汤", "溫": "温", "康": "康", "施": "施", "文": "文", "牛": "牛",
    "樊": "樊", "葛": "葛", "邢": "邢", "安": "安", "齊": "齐", "易": "易",
    "喬": "乔", "伍": "伍", "龐": "庞", "顏": "颜", "倪": "倪", "莊": "庄",
    "聶": "聂", "章": "章", "魯": "鲁", "嶽": "岳", "翟": "翟", "殷": "殷",
    "詹": "詹", "申": "申", "歐": "欧", "耿": "耿", "關": "关", "蘭": "兰",
    "焦": "焦", "俞": "俞", "左": "左", "柳": "柳", "甘": "甘", "祝": "祝",
    "包": "包", "寧": "宁", "尚": "尚", "符": "符", "舒": "舒", "阮": "阮",
    "柯": "柯", "紀": "纪", "梅": "梅", "童": "童", "凌": "凌", "畢": "毕",
    "單": "单", "季": "季", "裴": "裴", "霍": "霍", "塗": "涂", "成": "成",
    "苗": "苗", "穀": "谷", "盛": "盛", "曲": "曲", "翁": "翁", "冉": "冉",
    "駱": "骆", "藍": "蓝", "路": "路", "遊": "游", "辛": "辛", "管": "管",
    "柴": "柴", "矇": "蒙", "鮑": "鲍", "華": "华", "喻": "喻", "祁": "祁",
    "蒲": "蒲", "房": "房", "滕": "滕", "屈": "屈", "饒": "饶", "解": "解",
    "牟": "牟", "艾": "艾", "尤": "尤", "陽": "阳", "時": "时", "穆": "穆",
    "農": "农", "司": "司", "卓": "卓", "古": "古", "吉": "吉", "繆": "缪",
    "簡": "简", "車": "车", "項": "项", "連": "连", "蘆": "芦", "麥": "麦",
    "褚": "褚", "婁": "娄", "竇": "窦", "戚": "戚", "岑": "岑", "景": "景",
    "黨": "党", "宮": "宫", "費": "费", "蔔": "卜", "冷": "冷", "晏": "晏",
    "席": "席", "衛": "卫", "米": "米", "柏": "柏", "宗": "宗", "瞿": "瞿",
    "桂": "桂", "全": "全", "佟": "佟", "應": "应", "臧": "臧", "閔": "闵",
    "苟": "苟", "鄔": "邬", "邊": "边", "卞": "卞", "姬": "姬", "師": "师",
    "仇": "仇", "欒": "栾", "隋": "隋", "商": "商", "刁": "刁", "沙": "沙",
    "榮": "荣", "巫": "巫", "寇": "寇", "桑": "桑", "郎": "郎", "甄": "甄",
    "叢": "丛", "仲": "仲", "虞": "虞", "敖": "敖", "鞏": "巩", "明": "明",
    "佘": "佘", "池": "池", "查": "查", "麻": "麻", "苑": "苑", "遲": "迟",
    "鄺": "邝", "封": "封", "樂": "乐", "禹": "禹", "羊": "羊", "慕": "慕",
    "薩": "萨", "南": "南", "宦": "宦", "傅": "傅", "洪": "洪", "閻": "阎",
    "鬱": "郁", "邰": "邰", "戶": "户", "貴": "贵", "郗": "郗", "伊": "伊",
    "虎": "虎", "冀": "冀", "籍": "籍", "鐵": "铁", "芮": "芮", "原": "原",
    "郜": "郜", "樓": "楼", "貢": "贡",
}
# 姓氏匹配用的字符集合: 简体姓 + 繁体姓
_SURNAME_CHARS = SURNAMES | set(_T2S_SURNAME)

# --------------------------------------------------------------------------- #
# 通用边界工具
# --------------------------------------------------------------------------- #
_CJK_LO, _CJK_HI = "一", "龥"


def _is_cjk(ch: str) -> bool:
    return _CJK_LO <= ch <= _CJK_HI


def _next_is_boundary(text: str, end: int) -> bool:
    """右边界: 实体之后是句末/空白/标点 (不是汉字)。"""
    return end >= len(text) or not _is_cjk(text[end])


_NUMERALS = set("一二三四五六七八九十百千万亿零两0123456789")
# 数量词前缀: 后接数字时说明是数量表达而非机构 ("共三部"/"分两处")
_QUANTITY_PREFIX = set("共分设含计约由")

# 人名前方引导字: 前面是这些字时, 候选更可能是独立人名而非词语片段
# (介词/称谓/常见谓语动词, 如 "由张三负责" "再查李明" "通知王伟")
_PRE_NAME_CHARS = set(
    "由是给和与及对向请让叫为找从把将被跟同替帮约见通知告转交在据按依随陪人长户员士生家老总"
    "查问说讲谈派邀带领提醒询报送收转达委托推荐介绍接待拜访探望看慰问采调研审批签盖任聘升调选"
)

# 人名内部不应出现的字 (虚词/抽象语素/量词/数字/行政区划通名/常见谓语动词)。
# 这些字几乎不会出现在真实姓名里, 却能大量出现在 "内容要求/单位概况/第一章/万元/张伟是" 中。
_NON_NAME_CHARS = set(
    "的了是在和与及或等中上下内外前后时间性化度量级类者员部门位务项目分之所有无不可"
    "会能要该此其各每些么什怎为以于对向从由把被将给让使按依据根本也都还就又再才只更"
    "最很太较比如若则因故但而且并既虽果数据信息统素值况概章键际联测规范需功任应创贯"
    "谋计情均编历名盖自身调展参整后方案费发期单件求品软熟面层楼门司行省市区县镇乡村"
    "路街巷道号栋室元万亿百千零两第号年月日次条个家位名种样项类份批期届"
    "一二三四五六七八九十至说告叫跟但很之同先女开做拿放送交收查看听问答想知打回转陪随帮替约见找"
    "体现报存储相徽码融括询含确急档围额格述效修填用理表落等值程题配商技术费估算指标全多履哪关"
)

# 词性标注已确认是人名 (nr) 时放宽数字限制: "张三/李四/丁一" 这类名字合法
_NON_NAME_CHARS_NR = _NON_NAME_CHARS - set("一二三四五六七八九十百千万亿零两")

# 极少数仍会漏过上述规则的常用词 (词频高且首字为姓)
_PERSON_STOPWORDS = {
    "封面", "周期", "成熟", "成本", "成为", "万元", "亿元", "百级", "万级", "百万",
    "原则", "原来", "方向", "方案", "方式", "用户", "单位", "内容", "要求", "数据",
    "关系", "场景", "项目", "关键", "位置", "第三方", "第一篇", "第一批",
}


def _left_context_ok(text: str, start: int) -> bool:
    """左边界: 句首/空白/标点, 或 "由/和/给/是" 这类引导字之后。"""
    if start == 0:
        return True
    prev = text[start - 1]
    if not _is_cjk(prev):
        return True
    return prev in _PRE_NAME_CHARS


# 强上下文: 人名紧跟在称谓字后, 且其后是标点/句末。
# 用于兜住分词器切错的场合 ("法定代表人马晓东，" 被切成 "人马/晓东")。
_ROLE_TAIL_CHARS = set("人长员士生家老总")


def _strong_context(text: str, start: int, end: int) -> bool:
    left_ok = (start == 0 or not _is_cjk(text[start - 1])
               or text[start - 1] in _ROLE_TAIL_CHARS)
    right_ok = end >= len(text) or not _is_cjk(text[end])
    return left_ok and right_ok


def _strip_leading(text: str, chars: set) -> str:
    """剥掉实体前缀里粘连的虚词 (如 "在工业和信息化部" 的 "在")。"""
    i = 0
    while i < len(text) - 1 and text[i] in chars:
        i += 1
    return text[i:]


# 机构/地名前缀里常见的粘连虚词
_FUNCTION_CHARS = set(
    "的了是在和与及或等对向从由把被将给让使按依据于以经着地得各每该本此其这那哪些"
    "上下内外中前后可不会能要也还就都只更最很太较比如若则因故但而且并既虽然全"
)


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


class ChineseID15Recognizer(LightRecognizer):
    """15 位旧版身份证 (无校验位)。

    必须与 18 位分开: 混合正则会让 15 位被 BANK_CARD 抢走 (13-19 位数字),
    导致脱敏了但类型错误, 影响下游统计与还原策略。
    """

    def __init__(self):
        super().__init__("ID_NUMBER", _RE_ID15, score=0.80)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in re.finditer(_RE_ID15, text):
            s = m.group()
            # 18 位身份证的前 15 位不应重复计数
            if re.match(r"[1-9]\d{16}[\dXx]", text[m.start():m.start() + 18] or ""):
                continue
            if _id15_valid(s):
                out.append(RecognizerResult(m.start(), m.end(), self.entity_type,
                                            self.score))
        return out


class BankCardRecognizer(LightRecognizer):
    """银行卡: 13-19 位数字且通过 Luhn。

    Luhn 是关键过滤: 不加校验时任意长数字串 (订单号/流水号) 都会被判成卡号。
    """

    def __init__(self):
        super().__init__("BANK_CARD", _RE_BANK, score=0.60)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in re.finditer(_RE_BANK, text):
            raw = m.group()
            digits = re.sub(r"[ \-]", "", raw)
            if not _luhn(digits):
                continue
            out.append(RecognizerResult(m.start(), m.end(), self.entity_type, 0.80))
        return out


class PassportRecognizer(LightRecognizer):
    """护照 / 港澳通行证: 字母前缀 + 8 位数字。"""

    def __init__(self):
        super().__init__("PASSPORT", _RE_PASSPORT, score=0.85)


class PlateRecognizer(LightRecognizer):
    """中国大陆车牌: 省份简称 + 发牌机关字母 + 5 位序号。"""

    def __init__(self):
        super().__init__("LICENSE_PLATE", _RE_PLATE, score=0.80)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in re.finditer(_RE_PLATE, text):
            # 排除纯字母序号里形似单词的情况 (如 "京A" + "BCDEF" 无意义串)
            out.append(RecognizerResult(m.start(), m.end(), self.entity_type, self.score))
        return out


class IpMacRecognizer(LightRecognizer):
    """IPv4 与 MAC 地址。

    IP 只在看起来像网络标识时才收: 排除版本号 (1.2.3.4 形式) 与常见私有网段之外的
    纯数字点分串。这里保守处理: 命中即收, 由白名单兜底。
    """

    def __init__(self):
        self._re_v4 = re.compile(_RE_IPV4)
        self._re_mac = re.compile(_RE_MAC)
        self.entity_type = "IP_ADDRESS"
        self.score = 0.75

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        for m in self._re_v4.finditer(text):
            out.append(RecognizerResult(m.start(), m.end(), "IP_ADDRESS", 0.75))
        for m in self._re_mac.finditer(text):
            out.append(RecognizerResult(m.start(), m.end(), "MAC_ADDRESS", 0.80))
        return out


# --------------------------------------------------------------------------- #
# 人名 (姓 + 1-2 字名)
# --------------------------------------------------------------------------- #
class ChinesePersonRecognizer(LightRecognizer):
    """姓 + 1-2 字名。

    三重过滤:
      1. 左边界 — 前面必须是标点/空白/句首, 或 "由/和/给/是" 等引导字,
         否则 "内容要求" 会从 "容" 开始切出假人名;
      2. 用字 — 第 2/3 字不得是虚词/量词/数字/行政区划通名,
         否则 "第一部/万元/成熟/单位" 会被当成名字;
      3. 尾部回退 — 吞进来的虚词 ("张伟是" 的 "是") 逐字吐回。
    """

    def __init__(self):
        self._surname_chars = re.escape("".join(SURNAMES))
        super().__init__("PERSON",
                         r"[" + self._surname_chars + r"][一-龥]{1,2}",
                         score=0.75)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        covered = set()

        # 分词模式 (1): 直接采用词性标注为 nr (人名) 的词。
        # 姓名常常本身就在 jieba 词典里 (如 "王建国"), 因此这里不查常用词表。
        tokens = segmentation.pos_tokens(text)
        if tokens is not None:
            for word, s, e, flag in tokens:
                if flag != "nr" or not 2 <= len(word) <= 3:
                    continue
                if word[0] not in SURNAMES:
                    continue
                if any(c in _NON_NAME_CHARS_NR for c in word[1:]):
                    continue
                if word in _PERSON_STOPWORDS:
                    continue
                # jieba 的 HMM 会把 "应体现/申报书" 这类三字短语标成 nr,
                # 用左边界再卡一道: 真名通常出现在标点或 "由/和/给" 之后
                if not _left_context_ok(text, s):
                    continue
                out.append(RecognizerResult(s, e, self.entity_type, 0.85))
                covered.add((s, e))

        # 分词模式 (2) / 回退模式: 姓 + 1-2 字, 与词边界对齐且不是词典常用词
        bounds = segmentation.boundaries(text)  # 无 jieba 时为 None
        n = len(text)
        for i, ch in enumerate(text):
            if ch not in _SURNAME_CHARS:
                continue
            # 长名优先, 但每个起点都要试 3 字和 2 字:
            # 贪婪正则会把 "客户张伟" 从 "户" 起切成 "户张伟", 从而错过真正的起点
            for length in (3, 2):
                if i + length > n:
                    continue
                name = text[i:i + length]
                # 姓名内部的空格/全角空格 ("张 伟") 允许, 但需保留原文区间
                if " " in name or "　" in name:
                    compact = name.replace(" ", "").replace("　", "")
                    if not (2 <= len(compact) <= 3):
                        continue
                    probe = compact
                else:
                    probe = name
                if not all(_is_cjk(c) for c in probe):
                    continue
                if any(c in _NON_NAME_CHARS for c in probe[1:]):
                    continue
                if probe in _PERSON_STOPWORDS:
                    continue
                end = i + length
                if (i, end) in covered:
                    break
                if not _left_context_ok(text, i):
                    continue
                if bounds is not None:
                    if i not in bounds or end not in bounds:
                        # 分词器可能把 "法定代表人马晓东" 切成 "人马/晓东",
                        # 此时靠称谓字 + 右标点兜底
                        if not _strong_context(text, i, end):
                            continue
                    if segmentation.is_common_word(name):
                        continue
                else:
                    # 3 字名只在后面是标点/句末时采纳, 避免 "李明开" 吞掉谓语
                    if length == 3 and end < n and _is_cjk(text[end]):
                        continue
                out.append(RecognizerResult(i, end, self.entity_type, self.score))
                break
        return out


# --------------------------------------------------------------------------- #
# 地名 (词表 + 省/市/县/区通名)
# --------------------------------------------------------------------------- #
# 行政区划通名后接这些字时, 说明是泛称/层级词 ("市级/区县/城镇") 而非具体地名
_LOC_CONT_CHARS = set("级域民场长区县市省镇乡村划界内外部门")
# 以这些词结尾的是通用区域名, 不是可定位的具体地名
_LOC_BLACKLIST_SUFFIX = ("城市", "都市", "城区", "郊区", "市区", "社区", "园区",
                         "区域", "辖区", "小区", "地区", "城区", "县区", "省市")
# 街道门牌: "黄山路600号" / "天府大道北段1700号" / "人民路12号"
_RE_ADDR = re.compile(
    r"[一-龥]{1,12}(?:路|街|大道|巷|弄|胡同)(?:[东西南北中][段路街])?\d+号"
    r"(?:[0-9]+(?:栋|单元|室|楼))?")

_LOC_BLACKLIST = {"开发区", "高新区", "经开区", "示范区", "试验区", "工业区",
                  "商业区", "住宅区", "风景区", "旅游区", "保税区", "城镇",
                  "乡镇", "城区", "郊区", "市区", "社区", "园区", "区域",
                  "辖区", "小区", "地区"}
# 国家/泛称不是需要脱敏的具体地点
_LOC_COUNTRY = {"中国", "美国", "日本", "英国", "法国", "德国", "俄罗斯", "印度",
                "韩国", "朝鲜", "加拿大", "澳大利亚", "新加坡", "欧盟",
                "全国", "全省", "全市", "全县", "全区"}
# 通名左侧允许出现的字 (介词/动词/上级行政区), 其余汉字视为词内延伸
_LOC_LEFT_OK = set("在到由从向于与和及为是、，。（）：") | set("市省县区镇乡村")
# 省级地名常不带通名, 单独列一份; 其余 2 字词必须带通名才认 (避免 "新建/日志" 被 jieba 误标 ns)
_PROVINCES = {"北京", "上海", "天津", "重庆", "河北", "山西", "辽宁", "吉林", "黑龙江",
              "江苏", "浙江", "安徽", "福建", "江西", "山东", "河南", "湖北", "湖南",
              "广东", "海南", "四川", "贵州", "云南", "陕西", "甘肃", "青海", "台湾",
              "内蒙古", "广西", "西藏", "宁夏", "新疆", "香港", "澳门"}
_LOC_SUFFIX_CHARS = ("省", "市", "县", "区", "州", "盟", "旗", "镇", "乡")


class ChineseLocationRecognizer(LightRecognizer):
    """省/市/县/区地名: 词表命中, 或 "≥2 字专名 + 通名" 且不是泛称。

    词表与通名规则分开跑: 通名规则可能先匹配到 "银行北京市" 这类跨词片段,
    分跑后由重叠消解按长度择优, "北京市朝阳区" 不会被切碎。
    """

    def __init__(self):
        areas = sorted(_load_lines("admin_areas.txt"), key=len, reverse=True)
        self._re_known = re.compile(r"|".join(re.escape(a) for a in areas)) if areas else None
        self._re_generic = re.compile(r"[一-龥]{2,4}(?:省|市|县|区)")
        self.entity_type = "LOCATION"
        self.score = 0.85

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        bounds = segmentation.boundaries(text)

        # 街道门牌地址: 与分词无关, 直接按模式识别
        for m in _RE_ADDR.finditer(text):
            out.append(RecognizerResult(m.start(), m.end(), self.entity_type, 0.85))

        if bounds is not None:
            # 分词模式: 只认词性为 ns (地名) 的词, 泛称 "全省/项目在" 不会再被拼进地名
            tokens = segmentation.pos_tokens(text)
            if tokens is not None:
                for word, s, e, flag in tokens:
                    if flag != "ns" or len(word) < 2:
                        continue
                    if word in _LOC_BLACKLIST or word in _LOC_COUNTRY:
                        continue
                    # jieba 的 ns 标注会把 "之日起/新建/日志" 也标成地名,
                    # 因此必须带行政区划通名, 或属于省级地名白名单
                    if not (word.endswith(_LOC_SUFFIX_CHARS) or word in _PROVINCES):
                        continue
                    out.append(RecognizerResult(s, e, self.entity_type, 0.88))
                if self._re_known is not None:
                    for m in self._re_known.finditer(text):
                        out.append(RecognizerResult(m.start(), m.end(),
                                                    self.entity_type, 0.90))
                return out

        if self._re_known is not None:
            for m in self._re_known.finditer(text):
                out.append(RecognizerResult(m.start(), m.end(),
                                            self.entity_type, 0.90))

        for m in self._re_generic.finditer(text):
            name = _strip_leading(m.group(), _FUNCTION_CHARS)
            end = m.end()
            start = end - len(name)
            if len(name) < 3:
                continue
            if name in _LOC_BLACKLIST or name.endswith(_LOC_BLACKLIST_SUFFIX):
                continue
            # 通名后接 "级/县/区/镇..." 说明是泛称或更大行政区 ("市级/区县/城镇")
            if end < len(text) and text[end] in _LOC_CONT_CHARS:
                continue
            # 左侧不得是词内延伸 ("银行北京市" 的 "行")
            if start > 0 and _is_cjk(text[start - 1]) and text[start - 1] not in _LOC_LEFT_OK:
                continue
            # 专名部分不得以虚词收尾 ("构筑全省" 的 "全")
            if len(name) > 3 and name[-2] in _FUNCTION_CHARS:
                continue
            out.append(RecognizerResult(start, end, self.entity_type, self.score))
        return out


# --------------------------------------------------------------------------- #
# 组织机构 (机构后缀 + 右边界)
# --------------------------------------------------------------------------- #
_ORG_SUFFIX = (r"(股份有限公司|有限责任公司|有限公司|公司|集团|大学|学院|医院|银行|"
               r"管理委员会|委员会|管理局|办公厅|办公室|研究院|研究所|事务所|"
               r"信息中心|服务中心|管理中心|指挥中心|政务中心|大数据中心|"
               r"派出所|办事处|管理处|局|厅|委|办|部|院)")
# 机构主体允许全角/半角括号 (如 "中科云谷（合肥）数据科技有限公司")
_RE_ORG = re.compile(r"([一-龥（）()·]{2,14}?)" + _ORG_SUFFIX)
# 机构名之后允许紧跟的字 (其余汉字视为词内延伸, 如 "部门/部署/处理")
_ORG_RIGHT_OK = set("的等和与及、，。；：）】》」』\"'")
# 机构主体不应以这些字收尾 ("企业和政府内" 的 "内")
_ORG_BODY_TAIL_BAD = set("的和与及或等各每该本此其这那哪些上下内外中前后可不为无")
# 通用词作机构主体时一律拒绝
_ORG_BODY_BLACKLIST = {"所有", "多个", "每个", "各个", "这个", "那个", "其他", "其它",
                       "某些", "哪些", "上级", "下级", "内部", "外部", "相关", "有关",
                       "本级", "各级", "必要", "上述", "如下", "本项", "该项"}
# 机构主体以这些字收尾时, 后面的后缀只是词尾而非机构通名 ("含部委" 的 "部")
# 只保留 "部": "院/局/厅" 等收尾是正常机构名 ("国务院办公厅")
_ORG_SUFFIX_TAIL_CHARS = set("部")
# 机构名后缀的延长词: 单字后缀后面若紧跟这些词, 应整体算作机构名
# ("国务院" + "办公厅" -> "国务院办公厅")
_ORG_SUFFIX_EXT = ("股份有限公司", "有限责任公司", "有限公司", "公司", "集团", "大学",
                   "学院", "医院", "银行", "管理委员会", "委员会", "管理局", "办公厅",
                   "办公室", "研究院", "研究所", "事务所", "信息中心", "服务中心",
                   "管理中心", "指挥中心", "政务中心", "大数据中心", "派出所", "办事处",
                   "管理处")
# 通用部门名不是可定位机构, 单独出现时不脱敏 ("研发部/法务部" 这类表格列值)
_ORG_GENERIC_NAMES = {
    "办公室", "综合处", "财务处", "人事处", "技术部", "研发部", "数据资源科", "信息中心",
    "运维部", "市场部", "法务部", "采购部", "审计处", "监察室", "项目办", "规划处",
    "政策法规处", "政务服务科", "网络科", "安全科", "应用推广科", "标准规范科",
    "档案室", "后勤保障部", "客户服务部", "开户银行", "所在地人民法院", "人民法院",
}
# 机构主体不应以这些字收尾 (动词/副词, 如 "智能速办" 的 "速");
# 只保留几乎不会出现在机构名末尾的字, 避免误伤 "城建局/交通局" 这类
_ORG_BODY_TAIL_VERB = set("速快代承")
# 机构名前缀词: 命中时从该词起算, 剥掉前面的动词短语 ("项目由国家数据局" -> "国家数据局")
_ORG_PREFIX_WORDS = ("国家", "中国", "中华", "国务院", "中央", "全国")


class ChineseOrganizationRecognizer(LightRecognizer):
    """机构名: 至少 2 字主体 + 机构后缀, 且后缀后是边界。

    右边界是关键: "所有部门" 会先匹配出 "所有部", 但后面跟着 "门",
    说明是词内切分, 直接丢弃; "工业和信息化部。" 后面是句号, 予以保留。
    """

    def __init__(self):
        super().__init__("ORGANIZATION", _RE_ORG.pattern, score=0.80)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        bounds = segmentation.boundaries(text)
        tokens = segmentation.pos_tokens(text)
        for m in _RE_ORG.finditer(text):
            body_raw, suffix = m.group(1), m.group(2)
            end = m.end()
            # 单字后缀后若紧跟更长的机构后缀词, 整体延长 ("国务院" + "办公厅")
            if len(suffix) == 1:
                for ext in _ORG_SUFFIX_EXT:
                    if text.startswith(ext, end):
                        end += len(ext)
                        break
            if bounds is not None:
                # 分词模式: 机构名必须收在词边界上 ("所有部|门" 的 "部" 不在边界)
                if end not in bounds:
                    continue
            elif not _next_ok(text, end):
                continue
            body = _strip_leading(body_raw, _FUNCTION_CHARS)
            if len(body) < 2 or body in _ORG_BODY_BLACKLIST:
                continue
            # "第一部/第三章" 这类序数词不是机构
            if body[0] == "第" and body[1] in _NUMERALS:
                continue
            if body[-1] == "第" or (len(body) >= 2 and body[-2] == "第"
                                    and body[-1] in _NUMERALS):
                continue
            # "共三部"/"分两处" 这类数量表达不是机构
            if (body[0] in _QUANTITY_PREFIX and len(body) >= 2
                    and body[1] in _NUMERALS):
                continue
            if body[-1] in _ORG_BODY_TAIL_BAD:
                continue
            # 主体本身以机构后缀字收尾, 说明后缀只是词尾 ("含部委" 的 "部")
            if body[-1] in _ORG_SUFFIX_TAIL_CHARS:
                continue
            # 主体以动词收尾, 说明后缀只是词尾 ("智能速办" 的 "速")
            if body[-1] in _ORG_BODY_TAIL_VERB:
                continue
            start = m.start(1) + (len(body_raw) - len(body))
            # 机构名里含地名/国家前缀时从那里起算 ("项目由国家数据局" -> "国家数据局")
            start = _trim_org_start(body, start, end, tokens)
            if len(text[start:m.start(2)]) < 2:   # 主体至少 2 字
                continue
            # 通用部门名单独出现时不算机构
            if text[start:end] in _ORG_GENERIC_NAMES:
                continue
            if bounds is not None and start not in bounds:
                continue
            out.append(RecognizerResult(start, end, self.entity_type, self.score))
        return out


def _trim_org_start(body: str, start: int, end: int, tokens) -> int:
    """把机构名起点挪到地名或已知前缀词上, 剥掉 "项目由/承建单位" 这类动词短语。"""
    if tokens:
        for _word, s, e, flag in tokens:
            if s < start or e > end:
                continue
            if flag == "ns" and end - s >= 3:
                return s
    for word in _ORG_PREFIX_WORDS:
        idx = body.find(word)
        if idx > 0 and len(body) - idx >= 4:
            return start + idx
    return start


def _next_ok(text: str, end: int) -> bool:
    """机构名右边界: 句末/非汉字, 或允许的尾随虚词。"""
    return end >= len(text) or (not _is_cjk(text[end]) or text[end] in _ORG_RIGHT_OK)


# --------------------------------------------------------------------------- #
# 职务/职衔
# --------------------------------------------------------------------------- #
# 职衔后允许紧跟的字 ("总经理一职" 的 "一", "主任的" 的 "的")
_JOB_RIGHT_OK = set("一的等了和与及兼、，。；：）】》\"'")


class ChineseJobTitleRecognizer(LightRecognizer):
    """职务词表匹配 + 右边界。

    "政协委员履职" 里的 "委员" 后面跟着 "履", 属于词内切分, 不算职务。
    """

    def __init__(self):
        titles = sorted(_load_lines("titles.txt"), key=len, reverse=True)
        pat = r"(?:" + "|".join(re.escape(t) for t in titles) + r")" if titles else r"(?:经理|主任|处长|局长|科长|总监|董事长|教授|工程师|顾问|管理员)"
        super().__init__("JOB_TITLE", pat, score=0.75)

    def analyze(self, text: str) -> List[RecognizerResult]:
        out = []
        bounds = segmentation.boundaries(text)
        for m in self.regex.finditer(text):
            start, end = m.start(), m.end()
            if bounds is not None:
                # "政协委员" 是一个词, 内部的 "委员" 不与边界对齐 -> 丢弃
                if start not in bounds or end not in bounds:
                    continue
            elif end < len(text) and _is_cjk(text[end]) and text[end] not in _JOB_RIGHT_OK:
                continue
            out.append(RecognizerResult(start, end, self.entity_type, self.score))
        return out


# --------------------------------------------------------------------------- #
# 注册入口
# --------------------------------------------------------------------------- #
def get_chinese_recognizers():
    return [
        ChineseIDRecognizer(),
        ChineseID15Recognizer(),
        LightRecognizer("PHONE_NUMBER", _RE_MOBILE, score=0.88),
        LightRecognizer("PHONE_NUMBER", _RE_LANDLINE, score=0.85),
        LightRecognizer("EMAIL_ADDRESS", _RE_EMAIL, score=0.85),
        LightRecognizer("CREDIT_CODE", _RE_CREDIT, score=0.85),
        BankCardRecognizer(),
        PassportRecognizer(),
        PlateRecognizer(),
        IpMacRecognizer(),
        ChinesePersonRecognizer(),
        ChineseLocationRecognizer(),
        ChineseOrganizationRecognizer(),
        ChineseJobTitleRecognizer(),
    ]
