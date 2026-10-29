"""SQLite 临时登记与还原映射存储。"""
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path

DEFAULT_DB = Path("./.pii_presidio_store/sessions.db")


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
        self.conn = sqlite3.connect(str(db_path))
        # WAL + NORMAL: 批量写入时显著减少 fsync; :memory: 会忽略这两个设置
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        _init_schema(self.conn)

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
        避免同会话不同轮次的占位符冲突)。"""
        row = self.conn.execute(
            "SELECT MAX(CAST(SUBSTR(placeholder, -5, 4) AS INTEGER)) FROM mapping "
            "WHERE session_id=? AND ptype=?", (sid, ptype)).fetchone()
        return row[0] or 0

    def delete_session(self, sid: str) -> None:
        self.conn.execute("DELETE FROM mapping WHERE session_id=?", (sid,))
        self.conn.execute("DELETE FROM session WHERE session_id=?", (sid,))
        self.conn.commit()
