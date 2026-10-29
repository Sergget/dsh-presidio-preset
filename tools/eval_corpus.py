"""对合成测试语料做召回/误报评估。

兼容两版语料:
  - v1: manifest["parts"], 全部 docx
  - v2: manifest["docs"], docx/xlsx/pptx/md 混合

统计:
  - 召回: 真值实体中被识别出的比例 (按实体类型、按文档类型)
  - 简称类: 标记 hard 的真值 (公司/单位简称) 单独统计
  - 额外命中: 识别出但不在真值里的文本, 需人工判断 (基础文档自带的地名/机构不算错)

用法:
  python tools/eval_corpus.py --dir testdata/
  python tools/eval_corpus.py --dir testdata_v2/ --whitelist testdata_v2/whitelist.txt
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.documents import read_units  # noqa: E402
from presidio_pii.engine import PresidioPIIEngine  # noqa: E402


def load_whitelist(path: Path | None) -> list:
    if not path or not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8-sig").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def _load_docs(corpus: Path, manifest: dict):
    """统一两种 manifest: 产出 (path, doc_type, entities)。"""
    if "docs" in manifest:
        for doc in manifest["docs"]:
            yield corpus / doc["file"], doc.get("type", "?"), doc["entities"]
    else:
        for part in manifest.get("parts", []):
            yield corpus / part["file"], "part", part["entities"]


def _coverage(spans: list, start: int, end: int) -> float:
    """真值片段被识别区间覆盖的比例 (允许边界略有出入)。"""
    covered = 0
    for ds, de in spans:
        lo, hi = max(start, ds), min(end, de)
        if lo < hi:
            covered += hi - lo
    return covered / max(1, end - start)


def evaluate(corpus: Path, whitelist_path: Path | None = None) -> dict:
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    engine = PresidioPIIEngine(db_path=":memory:", whitelist=load_whitelist(whitelist_path))

    per_type = defaultdict(lambda: [0, 0])          # 实体类型 -> [hit, total]
    per_doc = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # 文档类型 -> 实体类型 -> [...]
    missed = []
    hard_total = hard_hit = 0
    extra = Counter()
    n_truth = 0
    n_docs = 0

    for path, doc_type, entities in _load_docs(corpus, manifest):
        if not path.exists():
            continue
        n_docs += 1
        units = [text for _key, text in read_units(path)]
        spans = [[(r.start, r.end, r.entity_type) for r in engine.analyze(t)] for t in units]

        truth_spans = []   # (unit_idx, start, end)
        for ent in entities:
            text, etype = ent["text"], ent["type"]
            hard = ent.get("hard", False)
            n_truth += 1
            if hard:
                hard_total += 1
            hit = False
            for ui, utext in enumerate(units):
                pos = utext.find(text)
                while pos != -1:
                    truth_spans.append((ui, pos, pos + len(text)))
                    if _coverage([(s, e) for s, e, _ in spans[ui]], pos, pos + len(text)) >= 0.8:
                        hit = True
                    pos = utext.find(text, pos + 1)
            per_type[etype][1] += 1
            per_doc[doc_type][etype][1] += 1
            if hit:
                per_type[etype][0] += 1
                per_doc[doc_type][etype][0] += 1
                if hard:
                    hard_hit += 1
            elif not hard:
                missed.append((doc_type, text, etype))

        for ui, utext in enumerate(units):
            for s, e, _etype in spans[ui]:
                if not any(ui == ti and s < te and e > ts for ti, ts, te in truth_spans):
                    extra[utext[s:e]] += 1

    return {
        "per_type": dict(per_type),
        "per_doc": {k: dict(v) for k, v in per_doc.items()},
        "missed": missed,
        "hard_total": hard_total,
        "hard_hit": hard_hit,
        "extra": extra,
        "n_truth": n_truth,
        "n_docs": n_docs,
    }


def _rate(hit: int, total: int) -> str:
    return f"{hit / total * 100:5.1f}%" if total else "  0.0%"


def report(result: dict) -> None:
    print(f"=== 召回 (按实体类型) | 文档 {result['n_docs']} 份 / 真值 {result['n_truth']} 条 ===")
    for etype, (hit, total) in sorted(result["per_type"].items()):
        print(f"  {etype:14} {hit:4}/{total:<4} {_rate(hit, total)}")
    if result["hard_total"]:
        print(f"  {'简称(hard)':14} {result['hard_hit']:4}/{result['hard_total']:<4} "
              f"{_rate(result['hard_hit'], result['hard_total'])}")

    print("\n=== 召回 (按文档类型 × 实体类型) ===")
    for doc_type, stats in sorted(result["per_doc"].items()):
        parts = [f"{etype}={_rate(h, t).strip()}" for etype, (h, t) in sorted(stats.items())]
        print(f"  {doc_type:12} " + "  ".join(parts))

    if result["missed"]:
        print(f"\n=== 未识别 ({len(result['missed'])}) ===")
        for doc_type, text, etype in result["missed"][:40]:
            print(f"  [{doc_type}] {etype:14} {text}")

    print(f"\n=== 额外命中 ({len(result['extra'])}) ===")
    print("  (可能是基础文档自带的地名/机构, 需人工判断)")
    for text, n in result["extra"].most_common(40):
        print(f"  {text}  x{n}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("合成语料召回/误报评估")
    ap.add_argument("--dir", default="testdata", help="语料目录 (含 manifest.json)")
    ap.add_argument("--whitelist", help="白名单文件")
    ap.add_argument("--json", help="把结果写入 JSON 报告")
    args = ap.parse_args(argv)

    corpus = Path(args.dir)
    if not (corpus / "manifest.json").exists():
        print(f"[error] 找不到 {corpus / 'manifest.json'}, 先运行 tools/gen_corpus_v2.py",
              file=sys.stderr)
        return 1
    result = evaluate(corpus, Path(args.whitelist) if args.whitelist else None)
    report(result)
    if args.json:
        payload = {
            "n_docs": result["n_docs"],
            "n_truth": result["n_truth"],
            "per_type": result["per_type"],
            "per_doc": result["per_doc"],
            "hard": [result["hard_hit"], result["hard_total"]],
            "missed": result["missed"],
            "extra": result["extra"].most_common(),
        }
        Path(args.json).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print(f"\n[json] {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
