"""可选的中文分词支持 (jieba), 用于校验实体的词边界与词性。

中文没有空格, 纯正则无法区分 "李明开会" 与 "成品软件" 这类字符级同形串。
装了 jieba 时, 识别器会要求候选实体与分词边界对齐、并利用词性 (nr 人名 / ns 地名),
精度显著提升; 没装时自动回退到启发式规则, 功能不受影响。

jieba 是纯 Python 词典分词器 (非 ML 模型), 通过可选依赖安装:
    pip install -e ".[segment]"
"""
from __future__ import annotations

from typing import List, Optional, Set, Tuple

try:  # pragma: no cover - 取决于运行环境
    import logging

    import jieba
    import jieba.posseg as pseg

    jieba.setLogLevel(logging.WARNING)
    _HAS_JIEBA = True
except Exception:  # pragma: no cover
    jieba = None  # type: ignore[assignment]
    pseg = None  # type: ignore[assignment]
    _HAS_JIEBA = False

Token = Tuple[str, int, int, str]  # (词, 起, 止, 词性)

_cache_text: Optional[str] = None
_cache_bounds: Set[int] = set()
_cache_tokens: Optional[List[Token]] = None
_initialized = False


def _ensure_init() -> None:
    """jieba 的词典是懒加载的; 首次使用前必须初始化, 否则 FREQ 为空。"""
    global _initialized
    if _HAS_JIEBA and not _initialized:
        jieba.initialize()
        _initialized = True


def available() -> bool:
    """当前环境是否可用的分词器。"""
    return _HAS_JIEBA


def _tokenize(text: str) -> None:
    """对文本做一次分词, 同时填充边界与词性缓存 (两者共用同一次分词结果)。"""
    global _cache_text, _cache_bounds, _cache_tokens
    _ensure_init()
    tokens: List[Token] = []
    offset = 0
    for pair in pseg.cut(text):
        word = pair.word
        tokens.append((word, offset, offset + len(word), pair.flag))
        offset += len(word)
    if offset != len(text):  # 个别文本分词后长度不一致, 退回纯分词 (无词性)
        tokens = [(w, s, e, "") for w, s, e in jieba.tokenize(text)]
    _cache_text = text
    _cache_tokens = tokens
    _cache_bounds = {t[1] for t in tokens} | {t[2] for t in tokens}


def boundaries(text: str) -> Optional[Set[int]]:
    """返回文本所有词边界位置 (字符下标集合); 无分词器时返回 None。

    只缓存最近一次文本: 引擎按文本单元逐段调用, 相邻识别器共享同一份结果。
    """
    if not _HAS_JIEBA:
        return None
    if _cache_text != text:
        _tokenize(text)
    return _cache_bounds


def pos_tokens(text: str) -> Optional[List[Token]]:
    """返回 [(词, 起, 止, 词性)]; 无分词器时返回 None。"""
    if not _HAS_JIEBA:
        return None
    if _cache_text != text:
        _tokenize(text)
    return _cache_tokens


def is_common_word(word: str) -> bool:
    """是否为词典里的常用词 (真名一般不在词典中)。"""
    if not _HAS_JIEBA:
        return False
    _ensure_init()
    return jieba.dt.FREQ.get(word, 0) > 0
