"""外部语料回归：从网络下载公开样例文件，注入合成 PII，跑 redact→restore。

约束（用户要求）：测试文件只能来自网络下载，不得使用本地语料或自造文件。
本脚本只把文件放到系统临时目录，不入库；报告里不打印任何文档正文。

用法:
  python tools/external_corpus_check.py [--dir <缓存目录>] [--refresh] [--json <报告>]

退出码: 0 全部通过 / 1 有失败 / 3 离线（无法下载）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from presidio_pii.documents import read_units  # noqa: E402
from presidio_pii.engine import PresidioPIIEngine  # noqa: E402

# 公开样例（均不含真实个人信息；PII 由本脚本注入的合成数据）
SOURCES = {
    "docx": "https://filesamples.com/samples/document/docx/sample1.docx",
    "xlsx": "https://filesamples.com/samples/document/xlsx/sample1.xlsx",
    "pptx": "https://raw.githubusercontent.com/apache/poi/trunk/test-data/slideshow/SampleShow.pptx",
    "csv": "https://filesamples.com/samples/document/csv/sample1.csv",
    "txt": "https://filesamples.com/samples/document/txt/sample3.txt",
}
OFFICE = {"docx", "xlsx", "pptx"}

# 合成 PII（全部为虚构值，用于验证召回与无损）
_PERSON = "张伟"
_PHONE = "13800138000"
_ID = "110101199003077890"
_EMAIL = "zhang.wei@example.com"
_INJECT = f"客户 {_PERSON}，电话 {_PHONE}，身份证 {_ID}，邮箱 {_EMAIL}\n"
_PII_VALUES = (_PERSON, _PHONE, _ID, _EMAIL)

_PH_RE = re.compile(r"⟦PII:[A-Z_]+:\d{4}⟧")


def _online() -> bool:
    import socket
    try:
        socket.create_connection(("pypi.org", 443), timeout=5).close()
        return True
    except OSError:
        return False


def _download(name: str, url: str, path: Path, refresh: bool) -> None:
    if path.exists() and path.stat().st_size > 0 and not refresh:
        return
    req = urllib.request.Request(url, headers={"User-Agent": "pii-guard-release-gate"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(path, "wb") as fh:
        fh.write(resp.read())


def _check_office(kind: str, src: Path, engine: PresidioPIIEngine) -> dict:
    sid = engine.registry.create_session()
    units = read_units(src)
    if not units:
        return {"kind": kind, "status": "FAIL", "reason": "无可读文本单元"}
    injected = [(k, _INJECT + t) for k, t in units]
    redacted = []
    n_replaced = 0
    for key, text in injected:
        rd = engine.redact(text, sid, src.name)
        n_replaced += rd.n_replaced
        redacted.append((key, rd.text))
    restored = []
    for key, text in redacted:
        rs = engine.restore(text, sid, src.name)
        restored.append((key, rs.text))
    engine.registry.delete_session(sid)

    redacted_text = "".join(t for _, t in redacted)
    leaks = [v for v in _PII_VALUES if v in redacted_text]
    equal = all(a == b for (_, a), (_, b) in zip(restored, injected))
    left = len(_PH_RE.findall("".join(t for _, t in restored)))
    status = "PASS" if (n_replaced > 0 and equal and not leaks and left == 0) else "FAIL"
    return {"kind": kind, "status": status, "units": len(units),
            "replaced": n_replaced, "roundtrip_equal": equal,
            "placeholders_left": left, "leaks": len(leaks)}


def _check_text(kind: str, src: Path, engine: PresidioPIIEngine) -> dict:
    sid = engine.registry.create_session()
    raw = src.read_text(encoding="utf-8-sig", errors="replace")
    injected = _INJECT + raw
    rd = engine.redact(injected, sid, src.name)
    rs = engine.restore(rd.text, sid, src.name)
    engine.registry.delete_session(sid)
    leaks = [v for v in _PII_VALUES if v in rd.text]
    left = len(_PH_RE.findall(rs.text))
    status = "PASS" if (rd.n_replaced > 0 and rs.text == injected
                        and not leaks and left == 0) else "FAIL"
    return {"kind": kind, "status": status, "units": 1,
            "replaced": rd.n_replaced, "roundtrip_equal": rs.text == injected,
            "placeholders_left": left, "leaks": len(leaks)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("external_corpus_check")
    ap.add_argument("--dir", default=str(Path(tempfile.gettempdir()) / "pii_ext_corpus"),
                    help="下载缓存目录（默认系统临时目录）")
    ap.add_argument("--refresh", action="store_true", help="强制重新下载")
    ap.add_argument("--json", help="报告输出路径")
    args = ap.parse_args(argv)

    if not _online():
        print("[SKIP] 离线，无法下载外部语料（不允许用本地语料替代）")
        return 3

    workdir = Path(args.dir)
    workdir.mkdir(parents=True, exist_ok=True)
    db = workdir / "corpus_check.db"
    if db.exists():
        db.unlink()
    engine = PresidioPIIEngine(db_path=db)

    results = []
    for kind, url in SOURCES.items():
        path = workdir / f"sample.{kind}"
        try:
            _download(kind, url, path, args.refresh)
        except (urllib.error.URLError, OSError) as exc:
            results.append({"kind": kind, "status": "FAIL", "reason": f"下载失败: {exc}"})
            continue
        try:
            fn = _check_office if kind in OFFICE else _check_text
            result = fn(kind, path, engine)
            result["bytes"] = path.stat().st_size
            result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            result["source"] = url
            results.append(result)
        except Exception as exc:  # 依赖缺失/格式不支持都要如实失败
            results.append({"kind": kind, "status": "FAIL", "reason": repr(exc)})

    for r in results:
        if r["status"] == "PASS":
            print(f"PASS {r['kind']:<5} bytes={r['bytes']} units={r['units']} "
                  f"replaced={r['replaced']} equal={r['roundtrip_equal']} "
                  f"left={r['placeholders_left']} leaks={r['leaks']}")
        else:
            print(f"FAIL {r['kind']:<5} {r.get('reason', '')}")

    all_pass = all(r["status"] == "PASS" for r in results)
    print(f"[result] {sum(r['status'] == 'PASS' for r in results)}/{len(results)} PASS")
    if args.json:
        Path(args.json).write_text(
            json.dumps({"all_pass": all_pass, "results": results},
                       ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
