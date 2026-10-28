"""命令行与 Demo 接口。

Usage:
  python -m presidio_pii.cli --demo
  python -m presidio_pii.cli redact <file> [-o OUT] [--session SID] [--doc-id ID]
  python -m presidio_pii.cli restore <file> [-o OUT] [--session SID] [--doc-id ID]

redact 会在输出文件旁生成 <out>.session.json (记录 session_id / doc_id),
restore 未显式指定 --session 时自动读取, 无需手工抄录。
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from .documents import SUPPORTED_EXTS, read_units, write_units
from .engine import PresidioPIIEngine


def _demo() -> None:
    text = """
    张伟是中国银行北京市朝阳区支行行长, 身份证 110101199003077890,
    手机号 13800138000, 邮箱 a.b@bank.com, 统信社 91110000123456787H。
    李明在重庆市渝北区经纪有限公司担任总经理, 电话留给李飞。
    """
    engine = PresidioPIIEngine()
    sid = engine.registry.create_session("demo")

    print("---- ORIGINAL ----")
    print(text.strip())

    rd = engine.redact(text, sid, "demo")
    print("---- REDACTED ----")
    print(rd.text.strip())
    print("[mappings]")
    for ph, orig in rd.restored.items():
        print(f"  {ph}  <-  {orig}")

    restored = engine.restore(rd.text, sid, "demo")
    print("---- RESTORED ----")
    print(restored.text.strip())

    ok = (restored.restored.keys() == rd.restored.keys() and not restored.unrestored)
    print(f"[ok] placeholders restored: {ok}")
    engine.registry.delete_session(sid)


def _cmd_redact(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.exists():
        print(f"[error] 文件不存在: {src}", file=sys.stderr)
        return 1
    out = Path(args.output) if args.output else src.with_suffix(src.suffix + ".redacted" + src.suffix)

    engine = PresidioPIIEngine()
    doc_id = args.doc_id or src.name
    if args.session:
        sid = args.session
    else:
        sid = engine.registry.create_session(doc_id)

    total = 0
    units = []
    for key, text in read_units(src):
        rd = engine.redact(text, sid, doc_id)
        total += rd.n_replaced
        units.append((key, rd.text))
    write_units(src, out, units)

    # 生成会话凭据 sidecar, 供 restore 使用
    meta = {"session_id": sid, "doc_id": doc_id, "source": str(src), "output": str(out)}
    meta_path = out.with_suffix(out.suffix + ".session.json")
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[redact] {src} -> {out}")
    print(f"[redact] 替换 {total} 处 PII | session_id={sid} doc_id={doc_id}")
    print(f"[redact] 会话凭据: {meta_path}")
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.exists():
        print(f"[error] 文件不存在: {src}", file=sys.stderr)
        return 1

    sid, doc_id = args.session, args.doc_id
    if not sid:
        meta_path = src.with_suffix(src.suffix + ".session.json")
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            sid, doc_id = meta["session_id"], meta.get("doc_id")
            print(f"[restore] 使用会话凭据 {meta_path} (session_id={sid})")
        else:
            print(f"[error] 未指定 --session 且找不到凭据文件 {meta_path}", file=sys.stderr)
            return 1

    # "t.txt.redacted.txt" -> "t.txt.restored.txt"; 其余情况追加 .restored
    out = (Path(args.output) if args.output else
           src.with_suffix("").with_suffix(".restored" + src.suffix))

    engine = PresidioPIIEngine()
    total = 0
    units = []
    for key, text in read_units(src):
        rs = engine.restore(text, sid, doc_id)
        total += len(rs.restored)
        units.append((key, rs.text))
    write_units(src, out, units)

    print(f"[restore] {src} -> {out}")
    print(f"[restore] 还原 {total} 处占位符")
    return 0


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser("Presidio PII DSH Plugin")
    sub = ap.add_subparsers(dest="command")

    sub.add_parser("--demo", help="run built-in demo")

    p_red = sub.add_parser("redact", help="脱敏文档 (txt/md/docx/xlsx/pptx)")
    p_red.add_argument("file")
    p_red.add_argument("-o", "--output", help="输出路径 (默认 <file>.redacted.<ext>)")
    p_red.add_argument("--session", help="复用已有 session_id (默认新建)")
    p_red.add_argument("--doc-id", help="文档标识 (默认文件名)")

    p_res = sub.add_parser("restore", help="还原脱敏文档")
    p_res.add_argument("file")
    p_res.add_argument("-o", "--output", help="输出路径 (默认 <file>.restored.<ext>)")
    p_res.add_argument("--session", help="session_id (默认读取 <file>.session.json)")
    p_res.add_argument("--doc-id", help="文档标识")

    args = ap.parse_args(argv)
    if args.command is None or args.command == "--demo":
        _demo()
        return 0
    if args.command == "redact":
        return _cmd_redact(args)
    if args.command == "restore":
        return _cmd_restore(args)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    sys.exit(main())
