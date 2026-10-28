"""轻量 Presidio 引擎封装 (零 spaCy 依赖)。

核心概念遵循 Microsoft Presidio:
  - Recognizer.analyze(text) -> List[RecognizerResult]
  - AnalyzerEngine : 聚合多 Recognizer 的结果
  - AnonymizerEngine : 替换实体为占位符
  - 还原 : 利用 SessionRegistry 的映射

占位符格式 : ⟦PII:<TYPE>:<SEQ>⟧  (Unicode 边界, 抗 LLM 篆改)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .chinese_recognizers import RecognizerResult, get_chinese_recognizers
from .db import SessionRegistry

PH_OPEN, PH_CLOSE = "⟦", "⟧"

# 实体优先级 (用于重叠冲突处理: 高优先级胜)
_PRIO = {"ID_NUMBER": 0, "PERSON": 1, "LOCATION": 2,
         "JOB_TITLE": 3, "ORGANIZATION": 4}


@dataclass
class RedactResult:
    text: str
    session_id: str
    doc_id: str
    n_replaced: int = 0
    restored: Dict[str, str] = field(default_factory=dict)
    unrestored: Dict[str, str] = field(default_factory=dict)


class PresidioPIIEngine:
    """零 spaCy 依赖的轻量引擎, API 兼容 Microsoft Presidio 概念。"""

    def __init__(self, db_path=None):
        self.recognizers = get_chinese_recognizers()
        self.registry = SessionRegistry(db_path) if db_path else SessionRegistry()

    # ---- 分析 ----
    def analyze(self, text: str) -> List[RecognizerResult]:
        results = []
        for rec in self.recognizers:
            results.extend(rec.analyze(text))
        # 去重 & 冲突处理
        results = self._resolve_overlaps(results)
        return results

    @staticmethod
    def _resolve_overlaps(results: List[RecognizerResult]) -> List[RecognizerResult]:
        if not results:
            return []
        # 按起点, 然后优先级排序 (高优先级在前)
        results.sort(key=lambda r: (r.start, _PRIO.get(r.entity_type, 99),
                                    -(r.end - r.start)))
        merged: List[RecognizerResult] = []
        for r in results:
            # 与已接受实体冲突?
            overlap = False
            for m in merged:
                if r.start < m.end and r.end > m.start:
                    # 冲突: 若当前优先级更低, 跳过; 若更高, 截断
                    if _PRIO.get(r.entity_type, 99) > _PRIO.get(m.entity_type, 99):
                        overlap = True
                        break
                    # 当前优先级更低, 跳过
                    overlap = True
                    break
            if not overlap:
                merged.append(r)
        # 再次按起点排序
        merged.sort(key=lambda r: r.start)
        return merged

    # ---- 脱敏 ----
    def redact(self, text: str, session_id: str, doc_id: str = "default") -> RedactResult:
        results = self.analyze(text)
        # 逆序替换以避免 offset 漂移
        results = sorted(results, key=lambda x: x.start, reverse=True)

        counters: Dict[str, int] = {}
        restored: Dict[str, str] = {}
        out_text = text
        n = 0
        for res in results:
            ptype = res.entity_type
            counters[ptype] = counters.get(ptype, 0) + 1
            seq = counters[ptype]
            ph = f"{PH_OPEN}PII:{ptype}:{seq:04d}{PH_CLOSE}"
            orig = text[res.start:res.end]
            out_text = out_text[:res.start] + ph + out_text[res.end:]
            restored[ph] = orig
            self.registry.add_mapping(session_id, doc_id, n, ptype, ph, orig)
            n += 1

        return RedactResult(text=out_text, session_id=session_id, doc_id=doc_id,
                            n_replaced=n, restored=restored)

    # ---- 还原 ----
    def restore(self, text: str, session_id: str, doc_id: str = "default") -> RedactResult:
        mapping = self.registry.get_restore_map(session_id, doc_id)
        out = text
        restored, unrestored = {}, {}
        for m in mapping:
            ph, orig = m["placeholder"], m["original"]
            if ph in out:
                out = out.replace(ph, orig)
                restored[ph] = orig
            else:
                unrestored[ph] = orig
        return RedactResult(text=out, session_id=session_id, doc_id=doc_id,
                            restored=restored, unrestored=unrestored)
