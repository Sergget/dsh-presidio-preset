"""无 DSH 环境的真实文档检测工具。

对任意真实文档执行完整流程:
  抽取文本单元 -> redact -> 模拟 LLM (原样保留占位符) -> restore -> 逐单元与原文比对

并做三项校验:
  1. 泄漏检查: 已识别的 PII 明文不得出现在脱敏产物中
  2. 还原无损: 还原后每个文本单元与原文完全一致
  3. 占位符清零: 还原产物中不得残留 ⟦PII:...⟧

用法:
  python tools/standalone_check.py <file> [file...] [--report REPORT.json] [--keep]
支持格式: txt / md / docx / xlsx / pptx
退出码: 全部通过=0, 任一失败=1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from presidio_pii.documents import read_units, write_units
from presidio_pii.engine import PresidioPIIEngine

_PH = re.compile(r"⟦PII:[A-Z_]+:\d{4}⟧")


def check_file(engine: PresidioPIIEngine, src: Path, workdir: Path,
               keep: bool = False) -> dict:
    sid = engine.registry.create_session()
    doc_id = src.name

    # 1) 抽取 + 脱敏
    orig_units = read_units(src)
    redacted_units = []
    entity_counts: Counter = Counter()
    pii_values: set = set()
    total_replaced = 0
    for key, text in orig_units:
        rd = engine.redact(text, sid, doc_id)
        total_replaced += rd.n_replaced
        for ph, orig in rd.restored.items():
            entity_counts[ph.strip("⟦⟧").split(":")[1]] += 1
            pii_values.add(orig)
        redacted_units.append((key, rd.text))

    # 2) 写出脱敏文档
    redacted_path = workdir / f"{src.stem}.redacted{src.suffix}"
    write_units(src, redacted_path, redacted_units)

    # 3) 模拟 LLM: 原样返回 (占位符保留) —— 真实 LLM 由 dsh_sim.py 单独验证
    on_disk = dict(read_units(redacted_path))
    llm_units = [(k, on_disk.get(k, t)) for k, t in redacted_units]

    # 4) 还原 + 写出
    restored_units = []
    n_restored = 0
    for key, text in llm_units:
        rs = engine.restore(text, sid, doc_id)
        n_restored += len(rs.restored)
        restored_units.append((key, rs.text))
    restored_path = workdir / f"{src.stem}.restored{src.suffix}"
    write_units(src, restored_path, restored_units)
    restored_back = dict(read_units(restored_path))

    # ---- 校验 ----
    # 泄漏: 脱敏产物中不得含任何已识别 PII 明文
    leaks = sorted({pii for pii in pii_values
                    if any(pii in t for _, t in on_disk.items())})
    # 还原无损 + 占位符清零
    unit_results = []
    for key, orig_text in orig_units:
        got = restored_back.get(key)
        unit_results.append({
            "unit": key,
            "roundtrip_equal": got == orig_text,
            "no_placeholder_left": not _PH.search(got or ""),
        })
    all_ok = (not leaks
              and all(r["roundtrip_equal"] and r["no_placeholder_left"]
                      for r in unit_results))

    report = {
        "file": str(src),
        "status": "PASS" if all_ok else "FAIL",
        "n_units": len(orig_units),
        "n_replaced": total_replaced,
        "n_restored": n_restored,
        "entity_counts": dict(entity_counts),
        "leaked_pii": leaks,
        "unit_results": unit_results,
        "artifacts": {
            "redacted": str(redacted_path),
            "restored": str(restored_path),
        },
    }
    if not keep:
        # 报告中记录产物路径, 但默认清理临时产物
        for p in (redacted_path, restored_path):
            p.unlink(missing_ok=True)
        report["artifacts"] = {}
    engine.registry.delete_session(sid)
    return report


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser("standalone_check: 无 DSH 真实文档检测")
    ap.add_argument("files", nargs="+", help="待检测文档 (txt/md/docx/xlsx/pptx)")
    ap.add_argument("--report", help="JSON 报告输出路径 (默认仅打印)")
    ap.add_argument("--keep", action="store_true",
                    help="保留 redacted/restored 产物 (默认写入临时目录并清理)")
    args = ap.parse_args(argv)

    engine = PresidioPIIEngine(db_path=_REPO_ROOT / ".pii_presidio_store" / "check.db")
    workdir = Path(tempfile.mkdtemp(prefix="pii_check_"))

    reports = []
    for f in args.files:
        path = Path(f)
        if not path.exists():
            reports.append({"file": f, "status": "FAIL", "error": "文件不存在"})
            continue
        try:
            reports.append(check_file(engine, path, workdir, keep=args.keep))
        except Exception as exc:  # 格式损坏等
            reports.append({"file": str(path), "status": "FAIL", "error": repr(exc)})

    # 控制台摘要
    print(f"{'状态':<6} {'单元':>4} {'替换':>4} {'还原':>4}  文件")
    for r in reports:
        if "error" in r:
            print(f"{'FAIL':<6} {'-':>4} {'-':>4} {'-':>4}  {r['file']}  ({r['error']})")
            continue
        print(f"{r['status']:<6} {r['n_units']:>4} {r['n_replaced']:>4} "
              f"{r['n_restored']:>4}  {r['file']}"
              + (f"  泄漏:{r['leaked_pii']}" if r["leaked_pii"] else ""))
        print(f"       实体分布: {r['entity_counts']}")
    ok = all(r.get("status") == "PASS" for r in reports)
    if args.report:
        Path(args.report).write_text(
            json.dumps({"all_pass": ok, "results": reports},
                       ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[report] {args.report}")
    print("[result] ALL PASS" if ok else "[result] 存在失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
