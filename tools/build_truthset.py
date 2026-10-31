"""人工真值集标注脚手架 (P2)。

合成语料能证明「能识别」, 不能证明「在真实分布上够用」。本工具生成标注模板:
从语料中抽取句子供人工标注, 并提供一致性 (Cohen's κ) 与置信区间计算。

数据本身留空, 由人工填写后作为最终验收口径。

用法:
  # 1) 生成标注模板 (含 200-500 句抽样)
  python tools/build_truthset.py sample --dir testdata_v2 --out truthset/ --per-type 40

  # 2) 人工填写 truthset/annotations.jsonl (每行一条, 见文件内说明)

  # 3) 计算标注一致性
  python tools/build_truthset.py kappa --a truthset/ann_a.jsonl --b truthset/ann_b.jsonl

  # 4) 用真值集评估引擎
  python tools/build_truthset.py eval --dir truthset/
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.documents import read_units  # noqa: E402

ANNOTATION_GUIDE = """# 人工标注说明

在 `annotations.jsonl` 中每行一条 JSON:

{"id": "resume/resume-01.docx#para:3", "text": "负责人：王建国", "entities": [["王建国", "PERSON"]]}

规则:
1. `id` 为样本文档单元标识, 不要改动
2. `text` 为该单元的原文, 不要改动
3. `entities` 列出该单元中**所有**应被脱敏的实体, 每项 [文本, 类型]
4. 类型从以下选取: PERSON / LOCATION / ORGANIZATION / JOB_TITLE /
   ID_NUMBER / PHONE_NUMBER / EMAIL_ADDRESS / CREDIT_CODE / BANK_CARD /
   PASSPORT / LICENSE_PLATE / IP_ADDRESS / MAC_ADDRESS
5. 存疑的条目标 `["文本", "UNSURE"]`, 不计入召回计算, 单独统计
6. 通用部门名 (研发部/法务部) 不标; 国家名/泛称 (全省/全市) 不标
7. 简称 (智数科技/市数据局) 要标, 会在评估中单列

双人独立标注后运行:
  python tools/build_truthset.py kappa --a ann_a.jsonl --b ann_b.jsonl
"""


def _load_manifest(corpus: Path) -> dict:
    return json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))


def _iter_doc_units(corpus: Path, manifest: dict):
    """产出 (doc_id, unit_key, text)。"""
    docs = manifest.get("docs") or [
        {"file": p["file"], "type": "part", "entities": p["entities"]}
        for p in manifest.get("parts", [])
    ]
    for doc in docs:
        path = corpus / doc["file"]
        if not path.exists():
            continue
        for key, text in read_units(path):
            if text.strip():
                yield doc["file"], key, text


def cmd_sample(args) -> int:
    """从语料中分层抽样, 生成标注模板。"""
    corpus = Path(args.dir)
    manifest = _load_manifest(corpus)
    rng = random.Random(args.seed)

    by_type: dict = defaultdict(list)
    for doc_file, key, text in _iter_doc_units(corpus, manifest):
        dtype = doc_file.split("/")[0] if "/" in doc_file else "?"
        by_type[dtype].append((doc_file, key, text))

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    picked = []
    for dtype, units in sorted(by_type.items()):
        # 优先抽含 PII 概率高的单元 (较长、含数字或标点分隔)
        candidates = [u for u in units if len(u[2]) >= args.min_len]
        if not candidates:
            candidates = units
        rng.shuffle(candidates)
        for doc_file, key, text in candidates[:args.per_type]:
            picked.append({
                "id": f"{doc_file}#{key}",
                "text": text[:args.max_len],
                "entities": [],
            })

    total = len(picked)
    with (out_dir / "annotations.jsonl").open("w", encoding="utf-8") as f:
        for item in picked:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    (out_dir / "GUIDE.md").write_text(ANNOTATION_GUIDE, encoding="utf-8")
    (out_dir / "meta.json").write_text(json.dumps(
        {"source": str(corpus), "seed": args.seed, "n_samples": total,
         "per_type": args.per_type, "types": {k: len(v) for k, v in by_type.items()}},
        ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[sample] 生成 {total} 条待标注样本 -> {out_dir / 'annotations.jsonl'}")
    print(f"[sample] 标注说明 -> {out_dir / 'GUIDE.md'}")
    if total < args.min_samples:
        print(f"[warn] 样本数 {total} < 建议下限 {args.min_samples}; "
              f"可提高 --per-type 或从更多语料抽样")
    return 0


def _load_annotations(path: Path) -> dict:
    """读取标注文件 -> {id: {(start, end, type)}}。"""
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        spans = set()
        for ent in item.get("entities", []):
            if len(ent) < 2:
                continue
            text, etype = ent[0], ent[1]
            pos = item["text"].find(text)
            if pos >= 0:
                spans.add((pos, pos + len(text), etype))
        result[item["id"]] = spans
    return result


def cohens_kappa(a: dict, b: dict) -> float:
    """Cohen's κ: 两份标注在「字符是否被标为实体」上的一致性。

    以字符为单位比较 (每个字符取「无实体」或「某类型」), 这样能同时反映
    边界分歧与类型分歧。
    """
    pairs = []
    for key in set(a) & set(b):
        text_len = max((max((s for s, _e, _t in a[key]), default=0),
                        max((s for s, _e, _t in b[key]), default=0))) + 1
        la = ["O"] * text_len
        lb = ["O"] * text_len
        for s, e, t in a[key]:
            for i in range(s, min(e, text_len)):
                la[i] = t
        for s, e, t in b[key]:
            for i in range(s, min(e, text_len)):
                lb[i] = t
        pairs.extend(zip(la, lb))
    if not pairs:
        return 0.0
    n = len(pairs)
    agree = sum(1 for x, y in pairs if x == y)
    po = agree / n
    ca, cb = Counter(x for x, _ in pairs), Counter(y for _, y in pairs)
    pe = sum((ca[k] / n) * (cb[k] / n) for k in set(ca) | set(cb))
    if pe >= 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def wilson_interval(hit: int, total: int, z: float = 1.96):
    """Wilson 置信区间 (用于召回率的区间估计)。"""
    if total == 0:
        return (0.0, 0.0)
    p = hit / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def cmd_kappa(args) -> int:
    a = _load_annotations(Path(args.a))
    b = _load_annotations(Path(args.b))
    k = cohens_kappa(a, b)
    common = len(set(a) & set(b))
    print(f"[kappa] 共同标注 {common} 条")
    print(f"[kappa] Cohen's κ = {k:.3f}")
    verdict = ("一致性良好" if k >= 0.8 else
               "一致性可接受, 建议复核分歧" if k >= 0.6 else
               "一致性不足, 需重新对齐标注标准")
    print(f"[kappa] 判定: {verdict}")
    return 0


def cmd_eval(args) -> int:
    """用人工真值集评估引擎, 输出召回 + Wilson 区间。"""
    from presidio_pii.engine import PresidioPIIEngine

    truth_path = Path(args.dir) / "annotations.jsonl"
    if not truth_path.exists():
        print(f"[error] 找不到 {truth_path}", file=sys.stderr)
        return 1

    engine = PresidioPIIEngine(db_path=":memory:")
    per_type = defaultdict(lambda: [0, 0])
    unsure = 0
    false_positives = Counter()

    for line in truth_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        text = item["text"]
        truth = set()
        for ent in item.get("entities", []):
            if len(ent) < 2:
                continue
            pos = text.find(ent[0])
            if pos < 0:
                continue
            if ent[1] == "UNSURE":
                unsure += 1
                continue
            truth.add((pos, pos + len(ent[0]), ent[1]))
        detected = {(r.start, r.end, r.entity_type) for r in engine.analyze(text)}

        for s, e, t in truth:
            per_type[t][1] += 1
            if any(ds <= s and de >= e and dt == t for ds, de, dt in detected):
                per_type[t][0] += 1
        for ds, de, dt in detected:
            if not any(ds < te and de > ts for ts, te, _ in truth):
                false_positives[text[ds:de]] += 1

    print("=== 人工真值集召回 ===")
    for etype, (hit, total) in sorted(per_type.items()):
        lo, hi = wilson_interval(hit, total)
        print(f"  {etype:14} {hit:3}/{total:<3} {hit / total * 100:5.1f}% "
              f"[95% CI {lo * 100:.1f}%–{hi * 100:.1f}%]")
    print(f"\n存疑条目 (UNSURE): {unsure}")
    print(f"额外命中: {len(false_positives)}")
    for text, n in false_positives.most_common(20):
        print(f"  {text}  x{n}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("人工真值集标注脚手架")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sample", help="生成标注模板")
    p.add_argument("--dir", default="testdata_v2", help="语料目录")
    p.add_argument("--out", default="truthset", help="输出目录")
    p.add_argument("--per-type", type=int, default=40, help="每类抽样条数")
    p.add_argument("--min-len", type=int, default=20, help="候选单元最短长度")
    p.add_argument("--max-len", type=int, default=400, help="样本文本最长截断")
    p.add_argument("--min-samples", type=int, default=200, help="建议样本下限")
    p.add_argument("--seed", type=int, default=42)

    p = sub.add_parser("kappa", help="计算双人标注一致性")
    p.add_argument("--a", required=True)
    p.add_argument("--b", required=True)

    p = sub.add_parser("eval", help="用真值集评估引擎")
    p.add_argument("--dir", default="truthset")

    args = ap.parse_args(argv)
    return {"sample": cmd_sample, "kappa": cmd_kappa, "eval": cmd_eval}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
