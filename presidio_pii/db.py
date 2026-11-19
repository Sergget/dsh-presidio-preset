"""SQLite 临时登记与还原映射存储。"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

DEFAULT_DB = Path("./.pii_presidio_store/sessions.db")


def _granted_principals() -> list[str]:
    """Windows ACL 里保留的主体: 当前用户 + SYSTEM + 本机管理员组。

    只授予这三者, 去掉 Users/Authenticated Users 这类继承项, 使同一台机器上
    的其他账号读不到映射库（库里有原文）。
    """
    names: list[str] = []
    user = os.environ.get("USERNAME")
    domain = os.environ.get("USERDOMAIN")
    if user:
        names.append(f"{domain}\\{user}" if domain else user)
    names.append("SYSTEM")
    names.append("BUILTIN\\Administrators")
    return names


def _icacls(path: Path, extra: list[str]) -> bool:
    try:
        proc = subprocess.run(
            ["icacls", str(path), *extra],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _harden(path: Path, directory: bool) -> None:
    """把映射库/目录权限收紧到「仅本人可读写」。

    映射库存的是明文原文, 默认继承的 Users 组权限会让同机其他账号可读。
    POSIX 用 chmod, Windows 用 icacls 去掉继承并只授予当前用户 + SYSTEM +
    管理员组。任何失败都只告警不阻断——脱敏功能比权限收紧更重要;
    但收紧后会立刻验证自己仍能访问, 失败则回滚继承, 绝不让库变成谁都打不开。
    """
    if not path.exists():
        return
    try:
        if os.name == "nt":
            inherit_flag = ":(OI)(CI)F" if directory else ":F"
            grants = [f"{name}{inherit_flag}" for name in _granted_principals()]
            args = ["/inheritance:r", "/grant:r", *grants]
            if not _icacls(path, args):
                print(f"[pii] 无法收紧权限 (icacls 失败): {path}", file=sys.stderr)
                return
            # 回读验证: 自己仍可访问, 否则回滚继承
            if not os.access(path, os.R_OK | os.W_OK):
                _icacls(path, ["/inheritance:e"])
                print(f"[pii] 权限收紧后自查失败, 已回滚: {path}", file=sys.stderr)
        else:
            os.chmod(path, 0o700 if directory else 0o600)
    except OSError as exc:
        print(f"[pii] 无法收紧权限 ({path}): {exc}", file=sys.stderr)


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS session (
        session_id TEXT PRIMARY KEY, created_at REAL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS mapping (
        session_id  TEXT,
        doc_id      TEXT,
        idx         INTEGER,
        ptype       TEXT,
        placeholder TEXT,
        original    TEXT,
        created_at  REAL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_map_sess ON mapping(session_id)")
    # get_max_seq 按 (session_id, ptype) 取 MAX, 无此索引时随库增长退化为全表扫描
    conn.execute("CREATE INDEX IF NOT EXISTS ix_map_sess_ptype ON mapping(session_id, ptype)")


class SessionRegistry:
    def __init__(self, db_path: Path | str = DEFAULT_DB):
        db_path = Path(db_path) if db_path != ":memory:" else db_path
        if db_path != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)
            _harden(db_path.parent, directory=True)
        self.conn = sqlite3.connect(str(db_path))
        # WAL + NORMAL: 批量写入时显著减少 fsync; :memory: 会忽略这两个设置
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        _init_schema(self.conn)
        if db_path != ":memory:":
            # 建库/建 WAL 之后再收紧一次: WAL 与 shm 是后生成的, 也要跟着收紧
            for suffix in ("", "-wal", "-shm"):
                _harden(Path(str(db_path) + suffix), directory=False)

    def create_session(self, doc_id: str = "default") -> str:
        sid = uuid.uuid4().hex[:12]
        now = time.time()
        self.conn.execute("INSERT INTO session(session_id, created_at) VALUES (?,?)", (sid, now))
        self.conn.commit()
        return sid

    def add_mapping(self, sid: str, doc_id: str, idx: int,
                    ptype: str, placeholder: str, original: str,
                    commit: bool = True) -> None:
        """登记一条映射; commit=False 时由调用方批量提交 (大幅减少磁盘同步)。"""
        self.conn.execute(
            "INSERT INTO mapping(session_id, doc_id, idx, ptype, placeholder, original, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, doc_id, idx, ptype, placeholder, original, time.time()))
        if commit:
            self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def get_restore_map(self, sid: str, doc_id: str | None = None) -> list[dict]:
        where = "session_id=?"
        args: list = [sid]
        if doc_id:
            where += " AND doc_id=?"
            args.append(doc_id)
        rows = self.conn.execute(
            f"SELECT ptype, placeholder, original FROM mapping WHERE {where} ORDER BY idx", args).fetchall()
        return [{"ptype": r[0], "placeholder": r[1], "original": r[2]} for r in rows]

    def get_max_seq(self, sid: str, ptype: str) -> int:
        """返回该会话内指定实体类型当前最大序号 (跨多次 redact 调用全局递增,
        避免同会话不同轮次的占位符冲突)。

        占位符形如 ``⟦PII:<TYPE>:<SEQ>⟧``，序号不保证定宽（引擎用 ``:04d``
        只是补零到 4 位，超过 9999 就是 5 位以上）。因此不能按固定偏移
        ``SUBSTR(placeholder, -5, 4)`` 取值：那会在第 10000 条时截出 ``1000``，
        反而小于已有最大值，导致占位符重复、还原串味。这里按类型名长度算出
        数字段的起点，长度取到闭合符之前，任意位数都正确。
        """
        # 1-based 起点: ⟦PII: 共 5 字符, 加上类型名与分隔冒号, 再加 1 落到首位数字。
        # 尾部 ⟧ 不必单独裁掉: CAST('12345⟧' AS INTEGER) 在首个非数字处停止。
        digit_start = 5 + len(ptype) + 1 + 1
        row = self.conn.execute(
            "SELECT MAX(CAST(SUBSTR(placeholder, ?) AS INTEGER)) "
            "FROM mapping WHERE session_id=? AND ptype=?",
            (digit_start, sid, ptype)).fetchone()
        return row[0] or 0

    def delete_session(self, sid: str) -> None:
        self.conn.execute("DELETE FROM mapping WHERE session_id=?", (sid,))
        self.conn.execute("DELETE FROM session WHERE session_id=?", (sid,))
        self.conn.commit()

    def close(self) -> None:
        """关闭底层连接。Windows 上不关连接会让库文件持续被占用，
        导致临时目录/迁移目录无法删除，因此显式提供关闭入口。"""
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "SessionRegistry":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
