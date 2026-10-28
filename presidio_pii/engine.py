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

# 实体优先级 (用于重叠冲突处理: 数字越小优先级越高)
# 设计原则: 召回优先 — PERSON 必须高于 ORGANIZATION (防止人名被机构名整体吞掉),
# LOCATION 高于 PERSON (地名 "北京市朝阳区" 比误切的人名更精确),
# BANK_CARD 正则最宽松, 在数字类实体中优先级最低
_PRIO = {"ID_NUMBER": 0, "CREDIT_CODE": 1, "PHONE_NUMBER": 2, "EMAIL_ADDRESS": 3,
         "BANK_CARD": 4, "LOCATION": 5, "PERSON": 6, "JOB_TITLE": 7,
         "ORGANIZATION": 8}


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
        # 按 (优先级, 长度, 起点) 排序: 高优先级胜, 同级时长实体胜
        results.sort(key=lambda r: (_PRIO.get(r.entity_type, 99),
                                    -(r.end - r.start), r.start))
        merged: List[RecognizerResult] = []
        for r in results:
            if not any(r.start < m.end and r.end > m.start for m in merged):
                merged.append(r)
        # 还原为文本顺序
        merged.sort(key=lambda r: r.start)
        return merged

    # ---- 脱敏 ----
    def redact(self, text: str, session_id: str, doc_id: str = "default") -> RedactResult:
        results = self.analyze(text)  # 已按文本顺序排序
        # 序号在会话内全局递增 (跨多次 redact 调用), 避免多轮对话占位符冲突
        counters: Dict[str, int] = {
            ptype: self.registry.get_max_seq(session_id, ptype)
            for ptype in {res.entity_type for res in results}
        }
        restored: Dict[str, str] = {}
        plan = []  # (result, placeholder, original)
        for res in results:
            ptype = res.entity_type
            counters[ptype] = counters.get(ptype, 0) + 1
            ph = f"{PH_OPEN}PII:{ptype}:{counters[ptype]:04d}{PH_CLOSE}"
            orig = text[res.start:res.end]
            plan.append((res, ph, orig))
            restored[ph] = orig

        # 逆序替换以避免 offset 漂移
        out_text = text
        for res, ph, _orig in reversed(plan):
            out_text = out_text[:res.start] + ph + out_text[res.end:]

        # 映射入库 (idx 按文本顺序)
        for idx, (res, ph, orig) in enumerate(plan):
            self.registry.add_mapping(session_id, doc_id, idx,
                                      res.entity_type, ph, orig)

        return RedactResult(text=out_text, session_id=session_id, doc_id=doc_id,
                            n_replaced=len(plan), restored=restored)

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
