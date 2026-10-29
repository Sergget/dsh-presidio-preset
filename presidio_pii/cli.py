"""命令行与 Demo 接口。

Usage:
  python -m presidio_pii.cli --demo
  python -m presidio_pii.cli <file>                # 等价于 redact <file>
  python -m presidio_pii.cli redact <file> [-o OUT | -d DIR] [--session SID] [--doc-id ID] [-v]
  python -m presidio_pii.cli restore <file> [-o OUT | -d DIR] [--session SID] [--doc-id ID] [-v]

redact 默认输出到 <源文件目录>/<文件名>-redacted/ 下, 与原文件同名, 并生成两个 CSV:
  <文件名>.mapping.csv  占位符 <-> 原文 的对应关系 (裸脚本的映射存储载体)
  <文件名>.session.csv  会话凭据 (session_id / doc_id / 路径)
restore 优先读 mapping.csv, 因此脱敏目录整体拷走也能还原; 也支持 --session 走映射库。
裸脚本的凭据用 CSV; DSH preset 的落盘格式由 preset 自身决定, 不受此约束。
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import time
from pathlib import Path

from .documents import SUPPORTED_EXTS, read_units, write_units
from .engine import PresidioPIIEngine, count_placeholders


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


def _make_engine(persistent: bool = False, whitelist=None) -> PresidioPIIEngine:
    """创建引擎。

    默认用内存映射库: 裸脚本的对应关系落在 CSV, 不需要逐条写盘 (实测快约 25 倍)。
    仅当需要跨文件复用同一会话 (--session) 或回退到映射库时才走持久化 SQLite,
    路径可用环境变量 PII_DSH_DB_PATH 覆盖 (与 preset 共用同一开关)。
    """
    if not persistent:
        return PresidioPIIEngine(db_path=":memory:", whitelist=whitelist)
    db_path = os.environ.get("PII_DSH_DB_PATH")
    return (PresidioPIIEngine(db_path=db_path, whitelist=whitelist) if db_path
            else PresidioPIIEngine(whitelist=whitelist))


def _load_whitelist(path: str | None, keep: list | None) -> list:
    """合并白名单来源: --keep 参数 + 白名单文件 (每行一个词, # 开头为注释)。"""
    terms = list(keep or [])
    if path:
        fp = Path(path)
        if not fp.exists():
            raise FileNotFoundError(f"白名单文件不存在: {fp}")
        for line in fp.read_text(encoding="utf-8-sig").splitlines():
            term = line.strip()
            if term and not term.startswith("#"):
                terms.append(term)
    # 去重保序
    return list(dict.fromkeys(t for t in terms if t))


def _ensure_utf8_stdio() -> None:
    """非 UTF-8 终端 (如 Windows 管道下的 cp936) 时改用 UTF-8 并逐行刷新。

    只在编码确实不是 UTF-8 时替换, 避免打断 pytest 的 capsys 捕获;
    替换时开启 line_buffering, 保证 -v 的过程输出实时可见。
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if getattr(stream, "buffer", None) is None:
            continue
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") == "utf8":
            continue
        setattr(sys, name, io.TextIOWrapper(stream.buffer, encoding="utf-8",
                                            line_buffering=True, write_through=True))


def _vlog(enabled: bool, msg: str) -> None:
    """-v 模式下输出过程信息 (缩进两格, 与结果摘要区分)。逐行刷新, 便于实时观察。"""
    if enabled:
        print(f"  {msg}", flush=True)


def _fmt_counts(counts: dict) -> str:
    """实体分布 -> `PERSON=2, PHONE_NUMBER=1` (按数量降序, 同数按名称)。"""
    if not counts:
        return ""
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"{k}={v}" for k, v in items)


def _elapsed(t0: float) -> str:
    return f"{time.perf_counter() - t0:.2f}s"


def _write_session_meta(path: Path, meta: dict) -> None:
    """写会话凭据 sidecar。

    裸脚本场景用 CSV (`key,value` 两列, utf-8-sig 便于 Excel 直接打开);
    DSH preset 不走这条路径, 其格式由 preset 自身决定。
    """
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["key", "value"])
        for key, value in meta.items():
            writer.writerow([key, value])


def _read_session_meta(path: Path) -> dict:
    """读会话凭据 sidecar, 支持 CSV 与历史遗留的 JSON。"""
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    meta: dict = {}
    for row in csv.DictReader(io.StringIO(text)):
        if row.get("key"):
            meta[row["key"]] = row.get("value")
    return meta


def _find_session_meta(src: Path) -> Path | None:
    """定位脱敏产物的会话凭据: 优先 .session.csv, 回退历史 .session.json。"""
    for suffix in (".session.csv", ".session.json"):
        candidate = src.with_suffix(src.suffix + suffix)
        if candidate.exists():
            return candidate
    return None


_MAPPING_FIELDS = ("idx", "ptype", "placeholder", "original")


def _write_mapping_csv(path: Path, rows: list[dict]) -> None:
    """导出 占位符 <-> 原文 对应关系。

    裸脚本以此 CSV 作为脱敏映射的落盘载体 (可直接用 Excel 查改);
    DSH preset 仍走 SQLite, 不读这里。
    """
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_MAPPING_FIELDS)
        writer.writeheader()
        for i, row in enumerate(rows):
            writer.writerow({"idx": i, "ptype": row["ptype"],
                             "placeholder": row["placeholder"], "original": row["original"]})


def _read_mapping_csv(path: Path) -> list[dict]:
    """读映射 CSV; 空行/缺 placeholder 的行跳过。"""
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [row for row in csv.DictReader(f) if row.get("placeholder")]


def _resolve_out(src: Path, args: argparse.Namespace) -> Path:
    """确定 redact 输出文件路径。

    优先级: -o 显式文件 > -d 目录 > 默认 <src.parent>/<文件名>-redacted/ 下与原文件同名。
    """
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        return out
    out_dir = Path(args.out_dir) if args.out_dir else src.parent / f"{src.stem}-redacted"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / src.name


def _resolve_restore_out(src: Path, args: argparse.Namespace) -> Path:
    """确定 restore 输出文件路径。

    兼容两种来源命名:
      - 旧: `a.txt.redacted.txt` -> `a-restored/a.txt`
      - 新: `a-redacted/a.txt`    -> `a-restored/a.txt`
    指定 -o 时直接用该路径, 指定 -d 时仅替换目录。
    """
    stem = src.stem
    if stem.lower().endswith(".redacted" + src.suffix.lower()):
        base = stem[: -len(".redacted" + src.suffix)]
        name = base + src.suffix
    elif stem.lower().endswith(".redacted"):
        base = stem[: -len(".redacted")]
        name = base + src.suffix
    else:
        base, name = stem, f"{stem}{src.suffix}"

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        return out
    parent = src.parent
    # 源文件位于 <名>-redacted/ 时, 还原产物落到同级 <名>-restored/, 不嵌套在脱敏目录里
    if parent.name == f"{base}-redacted":
        parent = parent.parent
    out_dir = Path(args.out_dir) if args.out_dir else parent / f"{base}-restored"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / name


def _cmd_redact(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.exists():
        print(f"[error] 文件不存在: {src}", file=sys.stderr)
        return 1
    if src.suffix.lower() not in SUPPORTED_EXTS:
        print(f"[error] 不支持的格式: {src.suffix} (支持: {', '.join(SUPPORTED_EXTS)})", file=sys.stderr)
        return 1

    verbose = args.verbose
    t0 = time.perf_counter()
    out = _resolve_out(src, args)

    if verbose:
        print(f"[verbose] 源文件: {src} ({src.suffix.lower().lstrip('.')}, {src.stat().st_size / 1024:.1f} KB)",
              flush=True)
        print(f"[verbose] 输出  : {out}", flush=True)

    units = read_units(src)
    _vlog(verbose, f"[1/4] 读取完成: {len(units)} 个文本单元 ({_elapsed(t0)})")

    try:
        whitelist = _load_whitelist(args.whitelist, args.keep)
    except FileNotFoundError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    engine = _make_engine(persistent=bool(args.session), whitelist=whitelist)
    doc_id = args.doc_id or src.name
    sid = args.session or engine.registry.create_session(doc_id)
    _vlog(verbose, f"[2/4] 开始识别与脱敏 (session_id={sid}, "
                   f"{'映射库' if args.session else '内存映射库 + CSV'}"
                   f"{f', 白名单 {len(whitelist)} 词' if whitelist else ''})")

    total = 0
    counts: dict = {}
    skipped = 0
    out_units = []
    counters: dict = {}          # 跨单元复用, 避免逐单元查询最大序号
    for i, (key, text) in enumerate(units, 1):
        rd = engine.redact(text, sid, doc_id, counters=counters, commit=False)
        total += rd.n_replaced
        skipped += rd.n_whitelisted
        for k, v in rd.entity_counts.items():
            counts[k] = counts.get(k, 0) + v
        out_units.append((key, rd.text))
        if verbose and rd.n_replaced:
            print(f"        [{i}/{len(units)}] {key}: {rd.n_replaced} 处 ({_fmt_counts(rd.entity_counts)})",
                  flush=True)

    engine.registry.commit()     # 整篇文档一次提交
    write_units(src, out, out_units)
    _vlog(verbose, f"[3/4] 已回写: {out}")

    # 导出映射 CSV (裸脚本的对应关系落盘载体, 与映射库并存)
    mapping_path = out.with_suffix(out.suffix + ".mapping.csv")
    mapping_rows = engine.registry.get_restore_map(sid, doc_id)
    _write_mapping_csv(mapping_path, mapping_rows)
    _vlog(verbose, f"[4/4] 映射 CSV: {mapping_path} ({len(mapping_rows)} 条)")

    # 生成会话凭据 sidecar (CSV, 便于裸脚本/表格工具查看), 供 restore 使用
    meta = {"session_id": sid, "doc_id": doc_id, "source": str(src), "output": str(out)}
    meta_path = out.with_suffix(out.suffix + ".session.csv")
    _write_session_meta(meta_path, meta)

    print(f"[redact] {src} -> {out}")
    print(f"[redact] 替换 {total} 处 PII | session_id={sid} doc_id={doc_id}")
    if counts:
        print(f"[redact] 实体分布: {_fmt_counts(counts)}")
    if skipped:
        print(f"[redact] 白名单跳过 {skipped} 处")
    print(f"[redact] 映射 CSV: {mapping_path}")
    print(f"[redact] 会话凭据: {meta_path}")
    if verbose:
        print(f"[verbose] 完成: {len(units)} 个单元 / 替换 {total} 处 / 耗时 {_elapsed(t0)}", flush=True)
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.exists():
        print(f"[error] 文件不存在: {src}", file=sys.stderr)
        return 1
    if src.suffix.lower() not in SUPPORTED_EXTS:
        print(f"[error] 不支持的格式: {src.suffix} (支持: {', '.join(SUPPORTED_EXTS)})", file=sys.stderr)
        return 1

    verbose = args.verbose
    t0 = time.perf_counter()

    # 映射来源优先级: --session 显式指定 (映射库) > 同目录映射 CSV (自包含, 不依赖映射库)
    #                 > 会话凭据指向的映射库会话
    sid, doc_id = args.session, args.doc_id
    mapping_path = src.with_suffix(src.suffix + ".mapping.csv")
    engine: PresidioPIIEngine
    if not sid and mapping_path.exists():
        rows = _read_mapping_csv(mapping_path)
        engine = PresidioPIIEngine(db_path=":memory:")
        for i, row in enumerate(rows):
            engine.registry.add_mapping("csv", None, i, row["ptype"],
                                        row["placeholder"], row["original"], commit=False)
        engine.registry.commit()
        sid, doc_id = "csv", None
        print(f"[restore] 使用映射 CSV {mapping_path} ({len(rows)} 条)")
    else:
        if not sid:
            meta_path = _find_session_meta(src)
            if meta_path:
                meta = _read_session_meta(meta_path)
                sid, doc_id = meta["session_id"], meta.get("doc_id")
                print(f"[restore] 使用会话凭据 {meta_path} (session_id={sid})")
            else:
                print(f"[error] 未指定 --session, 且找不到映射 CSV "
                      f"{mapping_path} 或会话凭据", file=sys.stderr)
                return 1
        engine = _make_engine(persistent=True)   # 回退到映射库

    out = _resolve_restore_out(src, args)

    units = read_units(src)
    _vlog(verbose, f"[1/4] 读取完成: {len(units)} 个文本单元 ({_elapsed(t0)})")

    _vlog(verbose, f"[2/4] 开始还原 (session_id={sid})")

    # 映射只取一次并转成字典, 逐单元复用; 未命中按整篇文档统计, 避免逐单元累加误报
    mapping = engine.registry.get_restore_map(sid, doc_id)
    by_ph = {m["placeholder"]: m["original"] for m in mapping}
    total = 0
    restored_keys: set = set()
    out_units = []
    for i, (key, text) in enumerate(units, 1):
        rs = engine.restore(text, sid, doc_id, mapping=by_ph, collect_unrestored=False)
        total += len(rs.restored)
        restored_keys.update(rs.restored)
        out_units.append((key, rs.text))
        if verbose and rs.restored:
            print(f"        [{i}/{len(units)}] {key}: 还原 {len(rs.restored)} 处", flush=True)

    write_units(src, out, out_units)
    _vlog(verbose, f"[3/4] 已回写: {out}")

    unrestored_total = sum(1 for m in mapping if m["placeholder"] not in restored_keys)
    leftover = sum(count_placeholders(t) for _, t in out_units)

    print(f"[restore] {src} -> {out}")
    print(f"[restore] 还原 {total} 处占位符")
    if unrestored_total:
        print(f"[restore] 警告: {unrestored_total} 处映射未在文档中出现 (可能已被修改或属于其他单元)")
    if leftover:
        print(f"[restore] 警告: 还原后仍残留 {leftover} 个占位符 (映射中无对应条目)")
    if verbose:
        print(f"[verbose] [4/4] 完成: {len(units)} 个单元 / 还原 {total} 处 / 耗时 {_elapsed(t0)}", flush=True)
    return 0


def main(argv: list | None = None) -> int:
    _ensure_utf8_stdio()
    ap = argparse.ArgumentParser("Presidio PII DSH Plugin")
    ap.add_argument("--demo", action="store_true", help="run built-in demo")
    sub = ap.add_subparsers(dest="command")

    p_red = sub.add_parser("redact", help="脱敏文档 (txt/md/docx/xlsx/pptx)")
    p_red.add_argument("file")
    g_red = p_red.add_mutually_exclusive_group()
    g_red.add_argument("-o", "--output", help="输出文件路径 (与 -d 互斥)")
    g_red.add_argument("-d", "--out-dir", help="输出目录 (默认 <源文件目录>/<文件名>-redacted/)")
    p_red.add_argument("--session", help="复用已有 session_id (默认新建)")
    p_red.add_argument("--doc-id", help="文档标识 (默认文件名)")
    p_red.add_argument("--whitelist", metavar="FILE",
                       help="白名单文件: 每行一个关键词, 命中的区域不脱敏 (# 开头为注释)")
    p_red.add_argument("--keep", action="append", metavar="TERM",
                       help="白名单关键词, 可重复 (与 --whitelist 合并)")
    p_red.add_argument("-v", "--verbose", action="store_true", help="显示处理过程与进度")

    p_res = sub.add_parser("restore", help="还原脱敏文档")
    p_res.add_argument("file")
    g_res = p_res.add_mutually_exclusive_group()
    g_res.add_argument("-o", "--output", help="输出文件路径 (与 -d 互斥)")
    g_res.add_argument("-d", "--out-dir", help="输出目录 (默认 <file>.restored.<ext>)")
    p_res.add_argument("--session", help="session_id (默认读取 <file>.mapping.csv, 其次 .session.csv)")
    p_res.add_argument("--doc-id", help="文档标识")
    p_res.add_argument("-v", "--verbose", action="store_true", help="显示处理过程与进度")

    argv = list(sys.argv[1:] if argv is None else argv)
    # 省略子命令时, 裸文件路径默认视为 redact: `cli 报告.docx` / `cli -v 报告.docx`
    if argv and not any(a in ("redact", "restore") for a in argv) \
            and any(not a.startswith("-") for a in argv):
        argv.insert(0, "redact")

    args = ap.parse_args(argv)
    if args.command == "redact":
        return _cmd_redact(args)
    if args.command == "restore":
        return _cmd_restore(args)
    _demo()
    return 0


if __name__ == "__main__":
    sys.exit(main())
