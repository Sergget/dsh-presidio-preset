"""文本归一化: 把写法变体折叠成标准形, 以便识别器命中。

真实文档里 PII 常被写成非标准形态:
  - 全角数字/字母 : 手机号写成 "１３８００１３８０００"
  - 数字插值     : "138 0013 8000" / "110101-19900307-7890" / 换行截断
  - 姓名插值     : "张 伟"

识别在归一化后的文本上做, 再用偏移映射把结果转回原文坐标,
这样占位符替换的是原文片段, 还原不受影响。

设计要点:
  - 只有「归一化前后一一对应」的变换才允许 (长度可缩短, 但不能合并语义单元);
  - 每个归一化字符都记录它在原文中的实际区间, 回填时取并集;
  - 不做简繁转换、不做 OCR 容错 (语义改变, 无法安全回填)。
"""
from __future__ import annotations

import re
import unicodedata
from typing import List, Tuple

# 数字之间常见的分隔符: 空白/换行、连字符系列、下划线。
# 不含点号 —— "192.168.1.100" 与 "user@example.com" 里的点是有意义的分隔,
# 吞掉会让 IP 与邮箱识别失败。
# 全部用 \u 转义书写, 避免源码里混入不可见字符导致规则歧义。
_SEP_CHARS = set(
    " \u0009\u000d\u000a"                          # 半角空格、Tab、CR、LF
    " 　    ﻿"        # 不换行/全角/窄空格、零宽
    "‐‑‒–—−"              # 连字符与破折号系列
    "-"                                            # ASCII 连字符 (最常被用到)
    "_"                                            # 下划线
)


def _is_digit(ch: str) -> bool:
    return (ch.isdigit() and ch.isascii()) or ch in "０１２３４５６７８９"


def _nfkc_char(ch: str) -> str:
    """单字符 NFKC 折叠: 全角数字/字母 -> 半角。"""
    folded = unicodedata.normalize("NFKC", ch)
    return folded if len(folded) == 1 else ch


def normalize(text: str) -> Tuple[str, List[int], List[Tuple[int, int]]]:
    """归一化文本。

    返回 (归一化文本, norm_index -> 原文下标, norm_index -> 原文区间)。
    第二个数组用于把归一化坐标转回原文; 第三个用于取被折叠掉的原文片段
    (例如 "138 0013 8000" 里的空格, 替换时要一并吃掉)。
    """
    if not text:
        return "", [], []

    chars: List[str] = []
    origin: List[int] = []                # 归一化串下标 -> 原文下标
    spans: List[Tuple[int, int]] = []     # 归一化串下标 -> 原文区间 [start, end)

    i = 0
    n = len(text)
    while i < n:
        folded = _nfkc_char(text[i])

        if folded == "":
            # 零宽字符: 丢弃, 但并入前一个归一化字符的原文区间
            if spans:
                s, _e = spans[-1]
                spans[-1] = (s, i + 1)
            i += 1
            continue

        if folded in _SEP_CHARS:
            # 分隔符: 只有夹在两个数字之间时才吞噬 ("138 0013 8000")
            prev_digit = bool(chars) and chars[-1].isdigit()
            j = i
            while j < n and _nfkc_char(text[j]) in _SEP_CHARS:
                j += 1
            next_digit = j < n and _nfkc_char(text[j]).isdigit()
            if prev_digit and next_digit:
                if spans:
                    s, _e = spans[-1]
                    spans[-1] = (s, j)
                i = j
                continue
            # 不是数字之间的分隔符: 保留为普通空格
            chars.append(" ")
            origin.append(i)
            spans.append((i, i + 1))
            i += 1
            continue

        chars.append(folded)
        origin.append(i)
        spans.append((i, i + 1))
        i += 1

    return "".join(chars), origin, spans


def to_original(start: int, end: int, origin: List[int],
                spans: List[Tuple[int, int]]) -> Tuple[int, int]:
    """把归一化坐标 [start, end) 转回原文坐标。

    归一化串末尾字符的原文区间末端作为结束位置, 以便把被吞噬的
    尾随分隔符也纳入替换范围 ("138 0013 8000" -> 整体替换)。
    """
    if not origin or start >= len(origin):
        return start, end
    orig_start = origin[start]
    last = min(end - 1, len(spans) - 1)
    orig_end = spans[last][1] if last >= 0 else origin[start] + 1
    return orig_start, max(orig_end, orig_start + 1)


class NormalizedText:
    """归一化文本及其偏移映射, 供识别器使用。"""

    __slots__ = ("text", "origin", "spans", "changed")

    def __init__(self, text: str):
        self.text, self.origin, self.spans = normalize(text)
        self.changed = self.text != text

    def back(self, start: int, end: int) -> Tuple[int, int]:
        return to_original(start, end, self.origin, self.spans)
