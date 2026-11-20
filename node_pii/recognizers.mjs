// node_pii/recognizers.mjs
// 逐字对齐 presidio_pii/chinese_recognizers.py（942 行）。
// 基准模式：Python「无 jieba fallback」——boundaries()/pos_tokens() 恒 null，
// is_common_word() 恒 false；人名/地名/机构/职务全部走 fallback 分支。
// 仅用 Node 标准库。JS 字符串索引 = Python 字符索引（中文均在 BMP，无代理对跨越）。

import fs from "node:fs";
import path from "node:path";

// --------------------------------------------------------------------------- #
// Result
// --------------------------------------------------------------------------- #
export class RecognizerResult {
  constructor(start, end, entityType, score, recognizer) {
    this.start = start;
    this.end = end;
    this.entity_type = entityType;
    this.score = score;
    if (recognizer !== undefined) this.recognizer = recognizer;
  }
}

// --------------------------------------------------------------------------- #
// 身份证校验位 (GB/T 11643-1999)
// --------------------------------------------------------------------------- #
const CITY_CODES = new Set([
  "11", "12", "13", "14", "15",
  "21", "22", "23", "31", "32", "33", "34", "35", "36", "37",
  "41", "42", "43", "44", "45", "46",
  "50", "51", "52", "53", "54",
  "61", "62", "63", "64", "65",
]);
const WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 5, 7, 9, 10, 5, 8, 4, 2, 1];
const MOD_MAP = "10X98765432";

const RE_ID = /(?<![0-9Xx])[1-9]\d{16}[\dXx](?![0-9Xx])/g;
const RE_ID15 = /(?<![0-9])[1-9]\d{14}(?![0-9])/g;
const RE_MOBILE = /(?<!\d)1[3-9]\d{9}(?!\d)/g;
const RE_LANDLINE = /(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)/g;
const RE_EMAIL = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const RE_CREDIT = /(?<![0-9A-Z])[159Y][0-9A-HJ-NPQRTUWXY]\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Z])/g;
const RE_BANK = /(?<![0-9A-Za-z_\-])\d(?:[ -]?\d){12,18}(?![0-9A-Za-z_\-])/g;
const EPOCH_MS = [1_000_000_000_000, 4_102_444_800_000];
const RE_PASSPORT = /(?<![0-9A-Za-z])[EGMDCHS][A-Z0-9]?\d{8}(?![0-9A-Za-z])/g;
const PLATE_PROVINCE = "京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新";
const RE_PLATE = new RegExp(
  "(?<![0-9A-Za-z一-龥])[" + PLATE_PROVINCE + "][A-HJ-NP-Z]" +
  "[A-HJ-NP-Z0-9]{4}[A-HJ-NP-Z0-9挂学警港澳领](?![0-9A-Za-z])", "g");
const RE_IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g;
const RE_MAC = /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])/g;

function idValid(s) {
  if (!/^[1-9]\d{16}[\dXx]$/.test(s)) return false;
  if (!CITY_CODES.has(s.slice(0, 2))) return false;
  let total = 0;
  for (let i = 0; i < 17; i++) total += Number(s[i]) * WEIGHTS[i];
  return s[17].toUpperCase() === MOD_MAP[total % 11];
}

function id15Valid(s) {
  if (!/^[1-9]\d{14}$/.test(s)) return false;
  if (!CITY_CODES.has(s.slice(0, 2))) return false;
  const year = Number(s.slice(6, 8));
  const month = Number(s.slice(8, 10));
  const day = Number(s.slice(10, 12));
  if (!(month >= 1 && month <= 12 && day >= 1 && day <= 31)) return false;
  return year <= 99;
}

function luhn(s) {
  const digits = [...s].filter((c) => isDigitChar(c)).map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  let total = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits[digits.length - 1 - i];
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  }
  return total % 10 === 0;
}

function isDigitChar(c) {
  return c >= "0" && c <= "9";
}

// --------------------------------------------------------------------------- #
// 词表加载（逐字对齐 _load_lines：strip，去空行，去 # 注释行，去 BOM）
// --------------------------------------------------------------------------- #
function loadLines(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, "utf8").replace(/^\uFEFF/, "");
  return text.split(/\r?\n/)
    .map((ln) => ln.trim())
    .filter((ln) => ln && !ln.startsWith("#"));
}

/** 读 <repoDir>/presidio_pii/assets/{surnames,admin_areas,titles}.txt */
export function loadAssets(repoDir) {
  const dir = path.join(repoDir, "presidio_pii", "assets");
  return {
    surnames: loadLines(path.join(dir, "surnames.txt")),
    adminAreas: loadLines(path.join(dir, "admin_areas.txt")),
    titles: loadLines(path.join(dir, "titles.txt")),
  };
}

// 繁体姓氏 -> 简体（逐字对齐 _T2S_SURNAME）
const T2S_SURNAME = {
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
};

//  surnameChars 由 assets 注入（见 getChineseRecognizers）；词表按 assets 引用
// 缓存在 SURNAME_SETS（WeakMap registrar）中：同一 assets 复用同一集合、不重复
// 重建；模块级 SURNAMES/SURNAME_CHARS 始终指向最近注入的集合，供各工厂函数读取。
const SURNAME_SETS = new WeakMap(); // assets -> { surnames, surnameChars }
let SURNAMES = new Set();
let SURNAME_CHARS = new Set();
let T2S_KEYS = Object.keys(T2S_SURNAME);

// --------------------------------------------------------------------------- #
// 通用边界工具
// --------------------------------------------------------------------------- #
const CJK_LO = "一", CJK_HI = "龥";
function isCjk(ch) { return !!ch && CJK_LO <= ch && ch <= CJK_HI; }
function nextIsBoundary(text, end) { return end >= text.length || !isCjk(text[end]); }

const NUMERALS = new Set("一二三四五六七八九十百千万亿零两0123456789");
const QUANTITY_PREFIX = new Set("共分设含计约由");

const PRE_NAME_CHARS = new Set(
  "由是给和与及对向请让叫为找从把将被跟同替帮约见通知告转交在据按依随陪人长户员士生家老总" +
  "查问说讲谈派邀带领提醒询报送收转达委托推荐介绍接待拜访探望看慰问采调研审批签盖任聘升调选" +
  "获"
);
const NON_NAME_CHARS = new Set(
  "的了是在和与及或等中上下内外前后时间性化度量级类者员部门位务项目分之所有无不可" +
  "会能要该此其各每些么什怎为以于对向从由把被将给让使按依据根本也都还就又再才只更" +
  "最很太较比如若则因故但而且并既虽果数据信息统素值况概章键际联测规范需功任应创贯" +
  "谋计情均编历名盖自身调展参整后方案费发期单件求品软熟面层楼门司行省市区县镇乡村" +
  "路街巷道号栋室元万亿百千零两第号年月日次条个家位名种样项类份批期届" +
  "一二三四五六七八九十至说告叫跟但很之同先女开做拿放送交收查看听问答想知打回转陪随帮替约见找" +
  "体现报存储相徽码融括询含确急档围额格述效修填用理表落等值程题配商技术费估算指标全多履哪关"
);
const NUMBER_CHARS = new Set("一二三四五六七八九十百千万亿零两");
const NON_NAME_CHARS_NR = new Set([...NON_NAME_CHARS].filter((c) => !NUMBER_CHARS.has(c)));

const PERSON_STOPWORDS = new Set([
  "封面", "周期", "成熟", "成本", "成为", "万元", "亿元", "百级", "万级", "百万",
  "原则", "原来", "方向", "方案", "方式", "用户", "单位", "内容", "要求", "数据",
  "关系", "场景", "项目", "关键", "位置", "第三方", "第一篇", "第一批",
  "荣获", "余人", "明白", "文明", "阳光", "王朝", "陆军", "卫星", "雷达", "荣誉",
  "古老", "冷笑", "武林", "明星", "宫殿", "师傅", "师兄", "高潮", "洪水", "顾客",
  "辛勤", "胡子", "桂林", "柏林", "石英", "谢谢", "康复", "沙滩", "梅花", "吉祥",
  "范畴", "孙子", "蓝天", "温泉", "白宫", "万人", "万余",
]);

const COMPOUND_SURNAMES = new Set([
  "欧阳", "司马", "诸葛", "上官", "令狐", "慕容", "司徒", "端木",
  "皇甫", "尉迟", "长孙", "宇文", "轩辕", "东方", "独孤", "南宫",
  "夏侯", "百里", "呼延", "东郭", "南门", "左丘", "羊舌", "梁丘",
  "万俟", "闻人",
]);
// 名单引导词（长词在前，正则从左到右逐位置匹配）
const RE_ROSTER_LEAD = /(学号名单|花名册|名单|名册|参会人员|与会人员|人员|成员|学生|幼儿|同学|专家)[^\n:：]{0,24}[:：]/g;
const RE_ROSTER_TAIL_NUM = /[（(]\s*\d{1,3}\s*[)）]\s*$/;
const ROSTER_NEGATIVE = [
  "身份证", "手机号", "银行卡", "个人信息", "内容要求", "本项目",
  "第一部", "第二部", "第三部", "万元", "成熟", "方面", "原则",
  "数据", "单位", "部门", "用户", "第三方", "封面", "周期", "概况",
];

function leftContextOk(text, start) {
  if (start === 0) return true;
  const prev = text[start - 1];
  if (!isCjk(prev)) {
    // 数字/ASCII 字母前驱：人名紧贴数字/字母的概率极低，一律拒绝
    if (isDigitChar(prev) || (/[A-Za-z]/.test(prev) && prev.charCodeAt(0) < 128)) return false;
    return true;
  }
  if (DIGIT_PREFIX.has(prev)) return false;
  return PRE_NAME_CHARS.has(prev);
}
const ROLE_TAIL_CHARS = new Set("人长员士生家老总");
const DIGIT_PREFIX = new Set("余万多几成");
function strongContext(text, start, end) {
  const leftOk = start === 0 || !isCjk(text[start - 1]) || ROLE_TAIL_CHARS.has(text[start - 1]);
  const rightOk = end >= text.length || !isCjk(text[end]);
  return leftOk && rightOk;
}
function stripLeading(chars, charSet) {
  let i = 0;
  while (i < chars.length - 1 && charSet.has(chars[i])) i++;
  return chars.slice(i);
}
const FUNCTION_CHARS = new Set(
  "的了是在和与及或等对向从由把被将给让使按依据于以经着地得各每该本此其这那哪些" +
  "上下内外中前后可不会能要也还就都只更最很太较比如若则因故但而且并既虽然全"
);

// 固定无 jieba：boundaries()/pos_tokens() 恒 null，is_common_word() 恒 false
const boundaries = () => null;
const posTokens = () => null;
const isCommonWord = () => false;

// --------------------------------------------------------------------------- #
// 轻量通用识别器（等价 LightRecognizer）
// --------------------------------------------------------------------------- #
class LightRecognizer {
  constructor(entityType, regexStr = "", score = 1.0, validator = null, name = null) {
    this.entity_type = entityType;
    this.score = score;
    this.validator = validator;
    this.name = name || entityType;
    this.supportedEntities = [entityType];
    this.regex = regexStr ? new RegExp(regexStr, "g") : null;
    this.entities = (text) => this.analyze(text);
  }
  analyze(text) {
    if (!this.regex) return [];
    const out = [];
    for (const m of text.matchAll(this.regex)) {
      const s = m.index;
      const e = s + m[0].length;
      const val = m[0];
      if (this.validator && !this.validator(val)) continue;
      out.push(new RecognizerResult(s, e, this.entity_type, this.score, this.name));
    }
    return out;
  }
}

// --------------------------------------------------------------------------- #
// 身份证识别器（校验位验证 + 行政区划有效时降级保留）
// --------------------------------------------------------------------------- #
function makeIdRecognizer() {
  return {
    name: "ChineseIDRecognizer",
    supportedEntities: ["ID_NUMBER"],
    entities(text) {
      const out = [];
      for (const m of text.matchAll(RE_ID)) {
        const s = m[0];
        if (!CITY_CODES.has(s.slice(0, 2))) continue;
        out.push(new RecognizerResult(m.index, m.index + s.length, "ID_NUMBER",
          idValid(s) ? 0.95 : 0.70, "ChineseIDRecognizer"));
      }
      return out;
    },
  };
}
function makeId15Recognizer() {
  return {
    name: "ChineseID15Recognizer",
    supportedEntities: ["ID_NUMBER"],
    entities(text) {
      const out = [];
      for (const m of text.matchAll(RE_ID15)) {
        const s = m[0];
        // 18 位身份证的前 15 位不应重复计数
        if (/^[1-9]\d{16}[\dXx]/.test(text.slice(m.index, m.index + 18))) continue;
        if (id15Valid(s)) {
          out.push(new RecognizerResult(m.index, m.index + s.length, "ID_NUMBER", 0.80,
            "ChineseID15Recognizer"));
        }
      }
      return out;
    },
  };
}
function makeBankCardRecognizer() {
  return {
    name: "BankCardRecognizer",
    supportedEntities: ["BANK_CARD"],
    entities(text) {
      const out = [];
      for (const m of text.matchAll(RE_BANK)) {
        const raw = m[0];
        const digits = raw.replace(/[ \-]/g, "");
        if (digits.length === 13) {
          const num = Number(digits);
          if (num >= EPOCH_MS[0] && num <= EPOCH_MS[1]) continue;
        }
        if (digits.length < 16 && !luhn(digits)) continue;
        const score = luhn(digits) ? 0.80 : 0.45;
        out.push(new RecognizerResult(m.index, m.index + raw.length, "BANK_CARD", score,
          "BankCardRecognizer"));
      }
      return out;
    },
  };
}
function makePassportRecognizer() {
  const lr = new LightRecognizer("PASSPORT", RE_PASSPORT.source, 0.85, null, "PassportRecognizer");
  return lr;
}
function makePlateRecognizer() {
  const lr = new LightRecognizer("LICENSE_PLATE", RE_PLATE.source, 0.80, null, "PlateRecognizer");
  return lr;
}
function makeIpMacRecognizer() {
  return {
    name: "IpMacRecognizer",
    supportedEntities: ["IP_ADDRESS", "MAC_ADDRESS"],
    entities(text) {
      const out = [];
      for (const m of text.matchAll(RE_IPV4)) {
        out.push(new RecognizerResult(m.index, m.index + m[0].length, "IP_ADDRESS", 0.75,
          "IpMacRecognizer"));
      }
      for (const m of text.matchAll(RE_MAC)) {
        out.push(new RecognizerResult(m.index, m.index + m[0].length, "MAC_ADDRESS", 0.80,
          "IpMacRecognizer"));
      }
      return out;
    },
  };
}

// --------------------------------------------------------------------------- #
// 人名（姓 + 1-2 字名）；固定无 jieba → 只走 fallback 分支
// --------------------------------------------------------------------------- #
function makePersonRecognizer() {
  return {
    name: "ChinesePersonRecognizer",
    supportedEntities: ["PERSON"],
    entities(text) {
      const out = [];
      const covered = new Set();
      // 分词模式 (1)：tokens = pos_tokens(text) 恒 null（无 jieba），跳过
      const tokens = posTokens(text);
      if (tokens !== null) { /* 不会执行；保留分支以对齐源码结构 */ }

      // 回退模式
      const bounds = boundaries(text); // 恒 null
      const n = text.length;
      for (let i = 0; i < n; i++) {
        const ch = text[i];
        if (!SURNAME_CHARS.has(ch)) continue;
        // 长名优先，但每个起点都要试 3 字和 2 字
        for (const length of [3, 2]) {
          if (i + length > n) continue;
          const name = text.slice(i, i + length).replace(/\s+$/u, "");
          if (!name || /\s/u.test(name[0])) continue;
          let probe;
          if (name.includes(" ") || name.includes("　")) {
            const compact = name.replace(/ /g, "").replace(/　/g, "");
            if (!(compact.length >= 2 && compact.length <= 3)) continue;
            probe = compact;
          } else {
            probe = name;
          }
          if (![...probe].every(isCjk)) continue;
          if ([...probe].slice(1).some((c) => NON_NAME_CHARS.has(c))) continue;
          if (PERSON_STOPWORDS.has(probe)) continue;
          if (length === 3 && probe.length === 3 && PERSON_STOPWORDS.has(probe.slice(0, 2))) continue;
          const end = i + name.length;
          if (covered.has(`${i},${end}`)) break;
          if (!leftContextOk(text, i)) continue;
          if (bounds !== null) {
            // 无 jieba 时不会进入
            if (!bounds.has(i) || !bounds.has(end)) {
              if (!(end < n && /\s/u.test(text[end])) && !strongContext(text, i, end)) continue;
            }
            if (isCommonWord(name)) continue;
          } else {
            // 3 字名只在后面是标点/句末时采纳，避免 "李明开" 吞掉谓语
            if (length === 3 && end < n && isCjk(text[end])) continue;
          }
          out.push(new RecognizerResult(i, end, "PERSON", 0.75, "ChinesePersonRecognizer"));
          break;
        }
      }
      return out;
    },
  };
}

// --------------------------------------------------------------------------- #
// 名单型人名（显式名单链）
// --------------------------------------------------------------------------- #
function makeRosterPersonRecognizer() {
  const SEP = "、,，";
  const sepSet = new Set([...SEP]);
  const patSplit = new RegExp(`([${SEP.split("").map(escapeRegex).join("")}])`, "g");
  function validItem(item) {
    if (!(item.length >= 2 && item.length <= 4) || ![...item].every(isCjk)) return false;
    if (PERSON_STOPWORDS.has(item)) return false;
    if (COMPOUND_SURNAMES.has(item.slice(0, 2))) return item.length >= 3;
    return SURNAME_CHARS.has(item[0]);
  }
  return {
    name: "ChineseRosterPersonRecognizer",
    supportedEntities: ["PERSON"],
    entities(text) {
      const out = [];
      for (const lead of text.matchAll(RE_ROSTER_LEAD)) {
        const startLine = lead.index + lead[0].length;
        let endLine = text.indexOf("\n", startLine);
        if (endLine < 0) endLine = text.length;
        let body = text.slice(startLine, endLine);
        let itemBase = startLine;
        if (!body.trim()) {
          itemBase = endLine + 1;
          endLine = text.indexOf("\n", itemBase);
          if (endLine < 0) endLine = text.length;
          body = text.slice(itemBase, endLine);
        }
        if (ROSTER_NEGATIVE.some((neg) => text.slice(Math.max(0, lead.index), endLine).includes(neg))) continue;
        const parts = body.split(patSplit);
        if (parts.length < 5) continue;
        let pos = itemBase;
        const items = [];
        let ok = true;
        for (const part of parts) {
          if (part.length === 1 && sepSet.has(part)) { pos += part.length; continue; }
          if (!part.trim()) { pos += part.length; continue; }
          const leadWs = part.length - part.replace(/^\s+/u, "").length;
          let core = part.trim().replace(/[。．.;；:： ]+$/u, "");
          core = core.replace(RE_ROSTER_TAIL_NUM, "").replace(/\s+$/u, "");
          if (!core || !validItem(core)) { ok = false; break; }
          const s = pos + leadWs;
          items.push([s, s + core.length]);
          pos += part.length;
        }
        if (!ok || items.length < 3) continue;
        for (const [s, e] of items) {
          out.push(new RecognizerResult(s, e, "PERSON", 0.80, "ChineseRosterPersonRecognizer"));
        }
      }
      return out;
    },
  };
}

// --------------------------------------------------------------------------- #
// 地名（词表 + 省/市/县/区通名）
// --------------------------------------------------------------------------- #
const LOC_CONT_CHARS = new Set("级域民场长区县市省镇乡村划界内外部门");
const LOC_BLACKLIST_SUFFIX = ["城市", "都市", "城区", "郊区", "市区", "社区", "园区",
  "区域", "辖区", "小区", "地区", "城区", "县区", "省市"];
const RE_ADDR = /[一-龥]{1,12}(?:路|街|大道|巷|弄|胡同)(?:[东西南北中][段路街])?\d+号(?:[0-9]+(?:栋|单元|室|楼))?/g;
const LOC_BLACKLIST = new Set(["开发区", "高新区", "经开区", "示范区", "试验区", "工业区",
  "商业区", "住宅区", "风景区", "旅游区", "保税区", "城镇",
  "乡镇", "城区", "郊区", "市区", "社区", "园区", "区域",
  "辖区", "小区", "地区"]);
const LOC_COUNTRY = new Set(["中国", "美国", "日本", "英国", "法国", "德国", "俄罗斯", "印度",
  "韩国", "朝鲜", "加拿大", "澳大利亚", "新加坡", "欧盟",
  "全国", "全省", "全市", "全县", "全区"]);
const LOC_LEFT_OK = new Set("在到由从向于与和及为是、，。（）：市省县区镇乡村");
const PROVINCES = new Set(["北京", "上海", "天津", "重庆", "河北", "山西", "辽宁", "吉林", "黑龙江",
  "江苏", "浙江", "安徽", "福建", "江西", "山东", "河南", "湖北", "湖南",
  "广东", "海南", "四川", "贵州", "云南", "陕西", "甘肃", "青海", "台湾",
  "内蒙古", "广西", "西藏", "宁夏", "新疆", "香港", "澳门"]);
const LOC_SUFFIX_CHARS = ["省", "市", "县", "区", "州", "盟", "旗", "镇", "乡"];

function makeLocationRecognizer(assets) {
  const areas = [...assets.adminAreas].sort((a, b) => b.length - a.length);
  const reKnown = areas.length ? new RegExp(areas.map(escapeRegex).join("|"), "g") : null;
  const reGeneric = /[一-龥]{2,4}(?:省|市|县|区)/g;
  return {
    name: "ChineseLocationRecognizer",
    supportedEntities: ["LOCATION"],
    entities(text) {
      const out = [];
      const bounds = boundaries(text); // 恒 null
      // 街道门牌地址
      for (const m of text.matchAll(RE_ADDR)) {
        out.push(new RecognizerResult(m.index, m.index + m[0].length, "LOCATION", 0.85,
          "ChineseLocationRecognizer"));
      }
      // bounds 非 null 的 jieba ns 分支不会执行（固定无 jieba）
      if (reKnown !== null) {
        for (const m of text.matchAll(reKnown)) {
          out.push(new RecognizerResult(m.index, m.index + m[0].length, "LOCATION", 0.90,
            "ChineseLocationRecognizer"));
        }
      }
      for (const m of text.matchAll(reGeneric)) {
        const name = stripLeading(m[0], FUNCTION_CHARS);
        const end = m.index + m[0].length;
        const start = end - name.length;
        if (name.length < 3) continue;
        if (LOC_BLACKLIST.has(name) || LOC_BLACKLIST_SUFFIX.some((s) => name.endsWith(s))) continue;
        if (end < text.length && LOC_CONT_CHARS.has(text[end])) continue;
        if (start > 0 && isCjk(text[start - 1]) && !LOC_LEFT_OK.has(text[start - 1])) continue;
        if (name.length > 3 && FUNCTION_CHARS.has(name[name.length - 2])) continue;
        out.push(new RecognizerResult(start, end, "LOCATION", 0.85, "ChineseLocationRecognizer"));
      }
      return out;
    },
  };
}

// --------------------------------------------------------------------------- #
// 组织机构（机构后缀 + 右边界）
// --------------------------------------------------------------------------- #
const ORG_SUFFIX = "(股份有限公司|有限责任公司|有限公司|公司|集团|大学|学院|医院|银行|" +
  "管理委员会|委员会|管理局|办公厅|办公室|研究院|研究所|事务所|" +
  "信息中心|服务中心|管理中心|指挥中心|政务中心|大数据中心|" +
  "派出所|办事处|管理处|局|厅|委|办|部|院)";
const RE_ORG = new RegExp("([一-龥（）()·]{2,14}?)" + ORG_SUFFIX, "g");
const ORG_RIGHT_OK = new Set("的等和与及、，。；：）】》」』\"'");
const ORG_BODY_TAIL_BAD = new Set("的和与及或等各每该本此其这那哪些上下内外中前后可不为无");
const ORG_BODY_BLACKLIST = new Set(["所有", "多个", "每个", "各个", "这个", "那个", "其他", "其它",
  "某些", "哪些", "上级", "下级", "内部", "外部", "相关", "有关",
  "本级", "各级", "必要", "上述", "如下", "本项", "该项"]);
const ORG_SUFFIX_TAIL_CHARS = new Set("部");
const ORG_SUFFIX_EXT = ["股份有限公司", "有限责任公司", "有限公司", "公司", "集团", "大学",
  "学院", "医院", "银行", "管理委员会", "委员会", "管理局", "办公厅",
  "办公室", "研究院", "研究所", "事务所", "信息中心", "服务中心",
  "管理中心", "指挥中心", "政务中心", "大数据中心", "派出所", "办事处",
  "管理处"];
const ORG_GENERIC_NAMES = new Set([
  "办公室", "综合处", "财务处", "人事处", "技术部", "研发部", "数据资源科", "信息中心",
  "运维部", "市场部", "法务部", "采购部", "审计处", "监察室", "项目办", "规划处",
  "政策法规处", "政务服务科", "网络科", "安全科", "应用推广科", "标准规范科",
  "档案室", "后勤保障部", "客户服务部", "开户银行", "所在地人民法院", "人民法院",
]);
const ORG_BODY_TAIL_VERB = new Set("速快代承");
const ORG_PREFIX_WORDS = ["国家", "中国", "中华", "国务院", "中央", "全国"];

function nextOk(text, end) {
  return end >= text.length || (!isCjk(text[end]) || ORG_RIGHT_OK.has(text[end]));
}
function trimOrgStart(body, start, end, tokens) {
  // tokens 恒 null（无 jieba），ns 分支不会执行
  if (tokens) {
    for (const _word of tokens) {
      const s = _word[1], e = _word[2], flag = _word[3];
      if (s < start || e > end) continue;
      if (flag === "ns" && end - s >= 3) return s;
    }
  }
  for (const word of ORG_PREFIX_WORDS) {
    const idx = body.indexOf(word);
    if (idx > 0 && body.length - idx >= 4) return start + idx;
  }
  return start;
}
function makeOrganizationRecognizer() {
  return {
    name: "ChineseOrganizationRecognizer",
    supportedEntities: ["ORGANIZATION"],
    entities(text) {
      const out = [];
      const bounds = boundaries(text); // 恒 null
      const tokens = posTokens(text);  // 恒 null
      for (const m of text.matchAll(RE_ORG)) {
        const bodyRaw = m[1];
        const suffix = m[2];
        let end = m.index + m[0].length;
        if (suffix.length === 1) {
          for (const ext of ORG_SUFFIX_EXT) {
            if (text.startsWith(ext, end)) { end += ext.length; break; }
          }
        }
        if (bounds !== null) { /* 无 jieba 时不会进入 */ }
        else if (!nextOk(text, end)) continue;
        const body = stripLeading(bodyRaw, FUNCTION_CHARS);
        if (body.length < 2 || ORG_BODY_BLACKLIST.has(body)) continue;
        if (body[0] === "第" && NUMERALS.has(body[1])) continue;
        if (body[body.length - 1] === "第" ||
            (body.length >= 2 && body[body.length - 2] === "第" && NUMERALS.has(body[body.length - 1]))) continue;
        if (QUANTITY_PREFIX.has(body[0]) && body.length >= 2 && NUMERALS.has(body[1])) continue;
        if (ORG_BODY_TAIL_BAD.has(body[body.length - 1])) continue;
        if (ORG_SUFFIX_TAIL_CHARS.has(body[body.length - 1])) continue;
        if (ORG_BODY_TAIL_VERB.has(body[body.length - 1])) continue;
        const suffixStart = m.index + m[0].length - suffix.length;
        // _RE_ORG 的 group1 即整个匹配起点：m.start(1) === m.index
        let start = m.index + (bodyRaw.length - body.length);
        start = trimOrgStart(body, start, end, tokens);
        if (text.slice(start, suffixStart).length < 2) continue;
        if (ORG_GENERIC_NAMES.has(text.slice(start, end))) continue;
        if (bounds !== null && !bounds.has(start)) continue;
        out.push(new RecognizerResult(start, end, "ORGANIZATION", 0.80, "ChineseOrganizationRecognizer"));
      }
      return out;
    },
  };
}

// --------------------------------------------------------------------------- #
// 职务/职衔
// --------------------------------------------------------------------------- #
const JOB_RIGHT_OK = new Set("一的等了和与及兼、，。；：）】》\"'");
function makeJobTitleRecognizer(assets) {
  const titles = [...assets.titles].sort((a, b) => b.length - a.length);
  const pat = titles.length
    ? "(?:" + titles.map(escapeRegex).join("|") + ")"
    : "(?:经理|主任|处长|局长|科长|总监|董事长|教授|工程师|顾问|管理员)";
  return {
    name: "ChineseJobTitleRecognizer",
    supportedEntities: ["JOB_TITLE"],
    entities(text) {
      const out = [];
      const bounds = boundaries(text); // 恒 null
      const re = new RegExp(pat, "g");
      for (const m of text.matchAll(re)) {
        const start = m.index;
        const end = m.index + m[0].length;
        if (bounds !== null) { /* 无 jieba 时不会进入 */ }
        else if (end < text.length && isCjk(text[end]) && !JOB_RIGHT_OK.has(text[end])) continue;
        out.push(new RecognizerResult(start, end, "JOB_TITLE", 0.75, "ChineseJobTitleRecognizer"));
      }
      return out;
    },
  };
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// --------------------------------------------------------------------------- #
// 注册入口：返回 15 个识别器，顺序/类型对齐 Python get_chinese_recognizers()
// --------------------------------------------------------------------------- #
export function getChineseRecognizers(assets) {
  // 词表按 assets 引用缓存（WeakMap registrar）：同一 assets 只建一次集合，
  // 注入到模块级 SURNAMES/SURNAME_CHARS（对齐 Python 模块级注入语义）。
  let set = SURNAME_SETS.get(assets);
  if (!set) {
    const surnames = new Set(assets.surnames);
    set = { surnames, surnameChars: new Set([...surnames, ...T2S_KEYS]) };
    SURNAME_SETS.set(assets, set);
  }
  SURNAMES = set.surnames;
  SURNAME_CHARS = set.surnameChars;

  const phone = new LightRecognizer("PHONE_NUMBER", RE_MOBILE.source, 0.88, null, "MobileRecognizer");
  const landline = new LightRecognizer("PHONE_NUMBER", RE_LANDLINE.source, 0.85, null, "LandlineRecognizer");
  const email = new LightRecognizer("EMAIL_ADDRESS", RE_EMAIL.source, 0.85, null, "EmailRecognizer");
  const credit = new LightRecognizer("CREDIT_CODE", RE_CREDIT.source, 0.85, null, "CreditCodeRecognizer");

  const recognizers = [
    makeIdRecognizer(),                 // 1  ChineseIDRecognizer
    makeId15Recognizer(),               // 2  ChineseID15Recognizer
    phone,                              // 3  PHONE_NUMBER (mobile)
    landline,                           // 4  PHONE_NUMBER (landline)
    email,                              // 5  EMAIL_ADDRESS
    credit,                             // 6  CREDIT_CODE
    makeBankCardRecognizer(),           // 7  BankCardRecognizer
    makePassportRecognizer(),           // 8  PassportRecognizer
    makePlateRecognizer(),              // 9  PlateRecognizer
    makeIpMacRecognizer(),              // 10 IpMacRecognizer
    makePersonRecognizer(),             // 11 ChinesePersonRecognizer
    makeRosterPersonRecognizer(),       // 12 ChineseRosterPersonRecognizer
    makeLocationRecognizer(assets),     // 13 ChineseLocationRecognizer
    makeOrganizationRecognizer(),       // 14 ChineseOrganizationRecognizer
    makeJobTitleRecognizer(assets),     // 15 ChineseJobTitleRecognizer
  ];
  // 契约第 38 行：每个识别器都暴露 .analyze。LightRecognizer 原型上已有 analyze，
  // 且其 entities 箭头函数调用 this.analyze ——绝不能覆盖，否则无限递归。
  for (const rec of recognizers) {
    if (typeof rec.analyze !== "function") rec.analyze = rec.entities;
  }
  return recognizers;
}
