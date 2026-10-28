"""命令行与 Demo 接口。

Usage:
  python -m presidio_pii.cli --demo
  python -m presidio_pii.cli redact <file>
  python -m presidio_pii.cli restore <file.redacted>
"""
from __future__ import annotations

import argparse
import sys
import io
from pathlib import Path

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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser("Presidio PII DSH Plugin")
    ap.add_argument("--demo", action="store_true", help="run built-in demo")
    args = ap.parse_args(argv)
    if args.demo:
        _demo()
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    sys.exit(main())
