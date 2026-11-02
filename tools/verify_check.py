"""核对工具（沙箱友好版）：对测试集文件执行 redact→restore→三项校验。

与 tools/standalone_check.py 的差异：
  - 不用 tempfile.mkdtemp()（沙箱内 python 子进程自建目录后写 docx 会被拒）；
  - 产物目录由 pwsh 预创建（--workdir 指定），python 只写文件；
  - 三项校验不变：泄漏检查 / 还原无损 / 占位符清零。

用法（在 pwsh 里先建目录再跑）：
  pwsh:  New-Item -ItemType Directory -Force .pii_presidio_store\verify-artifacts
  python tools/verify_check.py --file testdata_v2/resume/resume-01.docx --workdir .pii_presidio_store/verify-artifacts
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from presidio_pii.documents import read_units, write_units
from presidio_pii.engine import PresidioPIIEngine

_PH = re.compile(r"⟦PII:[A-Z_]+:\d{4}⟧")


def check_file(engine, src: Path, workdir: Path) -> dict:
    sid = engine.registry.create_session()
    doc_id = src.name

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

    redacted_path = workdir / f"{src.stem}.redacted{src.suffix}"
    write_units(src, redacted_path, redacted_units)

    on_disk = dict(read_units(redacted_path))
    llm_units = [(k, on_disk.get(k, t)) for k, t in redacted_units]

    restored_units = []
    n_restored = 0
    for key, text in llm_units:
        rs = engine.restore(text, sid, doc_id)
        n_restored += len(rs.restored)
        restored_units.append((key, rs.text))
    restored_path = workdir / f"{src.stem}.restored{src.suffix}"
    write_units(src, restored_path, restored_units)
    restored_back = dict(read_units(restored_path))

    leaks = sorted({pii for pii in pii_values
                    if any(pii in t for _, t in on_disk.items())})
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
        "artifacts": {"redacted": str(redacted_path), "restored": str(restored_path)},
    }
    engine.registry.delete_session(sid)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("verify_check: 沙箱友好的三项核对")
    ap.add_argument("--files", nargs="+", required=True,
                    help="待核对文件（可多个；一次进程复用引擎，显著提速）")
    ap.add_argument("--workdir", required=True,
                    help="产物目录（必须先由 pwsh 创建）")
    ap.add_argument("--report", help="JSON 报告输出路径")
    ap.add_argument("--keep", action="store_true",
                    help="保留 redacted/restored 产物（默认清理 restored，防明文残留）")
    args = ap.parse_args(argv)

    workdir = Path(args.workdir)
    engine = PresidioPIIEngine(
        db_path=_REPO_ROOT / ".pii_presidio_store" / "verify_check.db")

    reports = []
    for f in args.files:
        src = Path(f)
        try:
            report = check_file(engine, src, workdir)
        except Exception as exc:
            report = {"file": str(src), "status": "FAIL", "error": repr(exc)}
        reports.append(report)

        print(f"状态  {report.get('status')}")
        if "error" in report:
            print(f"  error: {report['error']}")
            continue
        print(f"  文件   : {report['file']}")
        print(f"  单元/替换/还原: {report['n_units']}/{report['n_replaced']}/{report['n_restored']}")
        print(f"  实体分布: {report['entity_counts']}")
        if report["leaked_pii"]:
            print(f"  泄漏: {report['leaked_pii']}")
        failed_units = [r for r in report["unit_results"]
                        if not (r["roundtrip_equal"] and r["no_placeholder_left"])]
        if failed_units:
            print(f"  失败单元: {[r['unit'] for r in failed_units]}")

    # 默认清理 restored 产物（明文还原文件），防残留泄漏；redacted 保留供查看
    if not args.keep:
        for r in reports:
            arts = r.get("artifacts") or {}
            rp = arts.get("restored")
            if rp:
                try:
                    Path(rp).unlink(missing_ok=True)
                    r["artifacts"] = {k: v for k, v in arts.items() if k != "restored"}
                except OSError:
                    pass

    if args.report:
        Path(args.report).write_text(
            json.dumps({"all_pass": all(r.get("status") == "PASS" for r in reports),
                        "results": reports},
                       ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  [report] {args.report}")

    ok = all(r.get("status") == "PASS" for r in reports)
    print("[result] ALL PASS" if ok else "[result] 存在失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
