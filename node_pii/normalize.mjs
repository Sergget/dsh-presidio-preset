// node_pii/normalize.mjs
// 逐字对齐 presidio_pii/normalize.py（基准：Python「无 jieba fallback」模式）。
// 仅用 Node 标准库；索引口径为 JS UTF-16 code unit（中文均在 BMP，与 Python 字符下标等价）。

// 数字之间常见的分隔符：空白/换行、连字符系列、下划线。
// 不含点号 —— "192.168.1.100" 与 "user@example.com" 里的点是有意义的分隔，
// 吞掉会让 IP 与邮箱识别失败。全部用 \u 转义书写，避免源码混入不可见字符。
const SEP_SET = new Set([
  " ", "\u0009", "\u000d", "\u000a",              // 半角空格、Tab、CR、LF
  "\u00a0", "\u3000", "\u2009", "\u200a", "\u2007", "\u202f", "\ufeff",
  // 不换行/全角/窄空格、零宽（U+202F 窄不换行空格、U+FEFF BOM/零宽）
  "\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212", // 连字符与破折号系列
  "-",                                             // ASCII 连字符（最常被用到）
  "_",                                             // 下划线
]);

// 等价于 Python str.isdigit() 在我们实际会遇到的字符上的语义。
// 归一化后的 chars 都是 NFKC 单字符折叠结果，十进制数字已 ASCII 化；
// \p{Nd} 覆盖 Python isdigit 的数字判定（含异体十进制数字）。
function isDigit(s) {
  if (!s) return false;
  for (const c of s) {
    if (!/\p{Nd}/u.test(c)) return false;
  }
  return true;
}

// 单字符 NFKC 折叠：全角数字/字母 -> 半角。
// Python 用 len(folded) == 1（code point 计数），这里用 code point 展开计数对齐。
function nfkcChar(ch) {
  const folded = ch.normalize("NFKC");
  return [...folded].length === 1 ? folded : ch;
}

const RE_COMPLETE_MOBILE = /^1[3-9]\d{9}$/;

// 当前归一化串末尾的连续数字是否恰好是一个完整的 11 位手机号。
// 最多回看 12 位：第 12 位仍是数字说明不是「恰好 11 位」，交回原吞噬逻辑。
function trailingIsCompleteMobile(chars) {
  const end = chars.length;
  let start = end;
  const floor = Math.max(0, end - 12);
  while (start > floor && isDigit(chars[start - 1])) start--;
  const run = chars.slice(start, end).join("");
  return run.length === 11 && RE_COMPLETE_MOBILE.test(run);
}

/**
 * 归一化文本。
 * 返回 { normalized, origin, spans }：
 *   origin[i] = 归一化串第 i 个字符对应的原文下标
 *   spans[i]  = 归一化串第 i 个字符在原文的 [start,end)
 */
export function normalize(text) {
  if (!text) return { text: "", origin: [], spans: [] };

  const chars = [];
  const origin = [];
  const spans = [];
  const n = text.length;
  let i = 0;

  while (i < n) {
    const folded = nfkcChar(text[i]);

    if (folded === "") {
      // 零宽字符：丢弃，但并入前一个归一化字符的原文区间
      if (spans.length) {
        const s = spans[spans.length - 1][0];
        spans[spans.length - 1] = [s, i + 1];
      }
      i++;
      continue;
    }

    if (SEP_SET.has(folded)) {
      // 分隔符：夹在两个数字之间且**只有一个字符**时才吞噬。
      // 连续多个空白是表格列对齐，吞掉会把几列数字拼成伪卡号。
      const prevDigit = chars.length > 0 && isDigit(chars[chars.length - 1]);
      const j = i + 1;
      const nextIsSep = j < n && SEP_SET.has(nfkcChar(text[j]));
      const nextDigit = j < n && isDigit(nfkcChar(text[j]));
      // 左侧已是完整手机号时不得再吞，否则号码会与下一行数字粘成超长串。
      const completeMobile = prevDigit && trailingIsCompleteMobile(chars);
      if (prevDigit && nextDigit && !nextIsSep && !completeMobile) {
        if (spans.length) {
          const s = spans[spans.length - 1][0];
          spans[spans.length - 1] = [s, j];
        }
        i = j;
        continue;
      }
      // 不是可吞噬的数字间分隔符：保留为普通空格
      chars.push(" ");
      origin.push(i);
      spans.push([i, i + 1]);
      i++;
      continue;
    }

    chars.push(folded);
    origin.push(i);
    spans.push([i, i + 1]);
    i++;
  }

  // 属性名 text 对齐 Python normalize.py:146 / 契约第 16 行
  return { text: chars.join(""), origin, spans };
}

/**
 * 把归一化坐标 [start,end) 转回原文坐标（等价 Python to_original）。
 * 归一化串末尾字符的原文区间末端作为结束位置，以便把被吞噬的尾随分隔符纳入替换范围。
 */
export function toOriginal(start, end, origin, spans) {
  if (!origin || origin.length === 0 || start >= origin.length) return [start, end];
  const origStart = origin[start];
  const last = Math.min(end - 1, spans.length - 1);
  const origEnd = last >= 0 ? spans[last][1] : origin[start] + 1;
  return [origStart, Math.max(origEnd, origStart + 1)];
}

export class NormalizedText {
  constructor(text) {
    const { text: normalized, origin, spans } = normalize(text);
    this.text = normalized;          // 契约第 16 行：属性名是 text，不是 normalized
    this.origin = origin;
    this.spans = spans;
    this.changed = normalized !== text;
  }

  back(start, end) {
    return toOriginal(start, end, this.origin, this.spans);
  }
}
