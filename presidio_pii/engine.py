"""轻量 Presidio 引擎封装 (零 spaCy 依赖)。

核心概念遵循 Microsoft Presidio:
  - Recognizer.analyze(text) -> List[RecognizerResult]
  - AnalyzerEngine : 聚合多 Recognizer 的结果
  - AnonymizerEngine : 替换实体为占位符
  - 还原 : 利用 SessionRegistry 的映射

占位符格式 : ⟦PII:<TYPE>:<SEQ>⟧  (Unicode 边界, 抗 LLM 篆改)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List

from .chinese_recognizers import RecognizerResult, get_chinese_recognizers
from .custom_rules import load_custom_rules
from .db import SessionRegistry
from .normalize import NormalizedText

PH_OPEN, PH_CLOSE = "⟦", "⟧"
_PH_RE = re.compile(r"⟦PII:[A-Z_]+:\d+⟧")


def count_placeholders(text: str) -> int:
    """统计文本中残留的占位符数量 (用于还原后校验)。"""
    return len(_PH_RE.findall(text))

# 实体优先级 (重叠冲突时使用: 数字越小优先级越高)
# 裁决顺序: 先取更长的实体 ("安徽省数据资源管理局" 不被其中的 "安徽省" 切碎),
# 等长时再按本优先级 — 证件号优先于银行卡 (15 位身份证不应被判成卡号),
# 人名高于机构名 (防止人名被机构名整体吞掉),
# 地名高于人名 (地名 "北京市朝阳区" 比误切的人名更精确)
_PRIO = {"ID_NUMBER": 0, "CREDIT_CODE": 1, "PASSPORT": 2, "PHONE_NUMBER": 3,
         "EMAIL_ADDRESS": 4, "LICENSE_PLATE": 5, "BANK_CARD": 6, "LOCATION": 7,
         "PERSON": 8, "JOB_TITLE": 9, "ORGANIZATION": 10,
         "IP_ADDRESS": 11, "MAC_ADDRESS": 12}


@dataclass
class RedactResult:
    text: str
    session_id: str
    doc_id: str
    n_replaced: int = 0
    restored: Dict[str, str] = field(default_factory=dict)
    unrestored: Dict[str, str] = field(default_factory=dict)
    entity_counts: Dict[str, int] = field(default_factory=dict)
    n_whitelisted: int = 0


class PresidioPIIEngine:
    """零 spaCy 依赖的轻量引擎, API 兼容 Microsoft Presidio 概念。

    whitelist: 受保护的关键词列表。命中白名单的区域不会被脱敏,
    与白名单区域重叠的实体一并跳过 (例如白名单含 "合肥市数据资源局" 时,
    其中的 "合肥市" 也不会被单独脱敏)。
    """

    def __init__(self, db_path=None, whitelist=None, custom_rules=None):
        self.recognizers = get_chinese_recognizers()
        self.custom_rules = custom_rules if custom_rules is not None else load_custom_rules()
        self.recognizers.extend(self.custom_rules)
        self.registry = SessionRegistry(db_path) if db_path else SessionRegistry()
        self.whitelist = [w for w in (whitelist or []) if w]

    def set_whitelist(self, terms) -> None:
        self.whitelist = [w for w in (terms or []) if w]

    # ---- 白名单 ----
    def _protected_spans(self, text: str) -> List[tuple]:
        """白名单词在文本中的所有出现位置 (start, end)。"""
        spans = []
        for term in self.whitelist:
            start = text.find(term)
            while start != -1:
                spans.append((start, start + len(term)))
                start = text.find(term, start + 1)
        return spans

    @staticmethod
    def _drop_protected(results: List[RecognizerResult], spans: List[tuple]):
        """丢弃与白名单区域重叠的实体, 返回 (保留的实体, 被跳过的数量)。"""
        if not spans:
            return results, 0
        kept = [r for r in results
                if not any(r.start < e and r.end > s for s, e in spans)]
        return kept, len(results) - len(kept)

    # ---- 分析 ----
    def analyze(self, text: str) -> List[RecognizerResult]:
        """识别文本中的 PII, 返回按文本顺序排列的结果。

        先在归一化文本上识别 (折叠全角字符与数字间插值), 再把坐标转回原文,
        因此 "１３８００１３８０００"、"138 0013 8000" 这类写法也能命中,
        且替换的是原文片段。
        """
        if not text:
            return []
        norm = NormalizedText(text)
        probe = norm.text if norm.changed else text
        results: List[RecognizerResult] = []
        for rec in self.recognizers:
            # 自定义规则 (wants_raw) 按约定在原文上匹配并返回原文坐标;
            # 内置识别器在归一化文本上识别, 命中后映射回原文坐标
            results.extend(rec.analyze(text if getattr(rec, "wants_raw", False) else probe))
        if norm.changed:
            mapped = []
            for r in results:
                start, end = norm.back(r.start, r.end)
                if start < 0 or end > len(text) or start >= end:
                    continue
                mapped.append(RecognizerResult(start, end, r.entity_type, r.score))
            results = mapped
        # 去重 & 冲突处理
        return self._resolve_overlaps(results)

    @staticmethod
    def _resolve_overlaps(results: List[RecognizerResult]) -> List[RecognizerResult]:
        if not results:
            return []
        # 长实体优先: "安徽省数据资源管理局" 应整体保留, 不被其中的 "安徽省" 切碎;
        # 等长时按优先级, 再按起点, 保证结果稳定
        results.sort(key=lambda r: (-(r.end - r.start),
                                    _PRIO.get(r.entity_type, 99), r.start))
        merged: List[RecognizerResult] = []
        for r in results:
            if not any(r.start < m.end and r.end > m.start for m in merged):
                merged.append(r)
        # 还原为文本顺序
        merged.sort(key=lambda r: r.start)
        return merged

    # ---- 脱敏 ----
    def redact(self, text: str, session_id: str, doc_id: str = "default",
               counters: Dict[str, int] | None = None,
               commit: bool = True) -> RedactResult:
        """脱敏单段文本。

        counters 可在同一文档的多次调用间复用 (跨单元共享序号),
        首次遇到某实体类型时才查询映射库, 避免逐单元重复 MAX(seq) 查询。
        commit=False 时把提交推迟到调用方, 批量写库时避免逐单元 fsync。
        """
        results = self.analyze(text)  # 已按文本顺序排序
        skipped = 0
        if self.whitelist:
            results, skipped = self._drop_protected(results, self._protected_spans(text))
        # 序号在会话内全局递增 (跨多次 redact 调用), 避免多轮对话占位符冲突
        if counters is None:
            counters = {res.entity_type: self.registry.get_max_seq(session_id, res.entity_type)
                        for res in results}
        else:
            for res in results:
                if res.entity_type not in counters:
                    counters[res.entity_type] = self.registry.get_max_seq(session_id, res.entity_type)
        restored: Dict[str, str] = {}
        entity_counts: Dict[str, int] = {}
        plan = []  # (result, placeholder, original)
        for res in results:
            ptype = res.entity_type
            counters[ptype] = counters.get(ptype, 0) + 1
            ph = f"{PH_OPEN}PII:{ptype}:{counters[ptype]:04d}{PH_CLOSE}"
            orig = text[res.start:res.end]
            plan.append((res, ph, orig))
            restored[ph] = orig
            entity_counts[ptype] = entity_counts.get(ptype, 0) + 1

        # 逆序替换以避免 offset 漂移
        out_text = text
        for res, ph, _orig in reversed(plan):
            out_text = out_text[:res.start] + ph + out_text[res.end:]

        # 映射入库 (idx 按文本顺序); 整批提交, 避免逐条 commit 的磁盘同步开销
        for idx, (res, ph, orig) in enumerate(plan):
            self.registry.add_mapping(session_id, doc_id, idx,
                                      res.entity_type, ph, orig, commit=False)
        if plan and commit:
            self.registry.commit()

        return RedactResult(text=out_text, session_id=session_id, doc_id=doc_id,
                            n_replaced=len(plan), restored=restored,
                            entity_counts=entity_counts, n_whitelisted=skipped)

    # ---- 还原 ----
    def restore(self, text: str, session_id: str, doc_id: str = "default",
                mapping: List[Dict] | Dict[str, str] | None = None,
                collect_unrestored: bool = True) -> RedactResult:
        """还原文本中的占位符。

        mapping 可传入已取好的映射 (列表或 占位符->原文 字典), 批量还原时只构建一次。
        collect_unrestored=False 时跳过"未命中"统计 (批量还原按整篇统计时用)。
        只扫描文本中实际出现的占位符, 成本与占位符数量成正比, 与映射表大小无关。
        """
        if mapping is None:
            mapping = self.registry.get_restore_map(session_id, doc_id)
        by_ph = mapping if isinstance(mapping, dict) else \
            {m["placeholder"]: m["original"] for m in mapping}

        out = text
        restored: Dict[str, str] = {}
        for ph in _PH_RE.findall(text):
            if ph in restored:
                continue
            orig = by_ph.get(ph)
            if orig is None:
                continue
            out = out.replace(ph, orig)
            restored[ph] = orig

        unrestored = ({ph: orig for ph, orig in by_ph.items() if ph not in restored}
                      if collect_unrestored else {})
        return RedactResult(text=out, session_id=session_id, doc_id=doc_id,
                            restored=restored, unrestored=unrestored)
