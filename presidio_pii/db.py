"""SQLite 临时登记与还原映射存储。"""
from __future__ import annotations

import sqlite3
import time
import uuid
from pathlib import Path

DEFAULT_DB = Path("./.pii_presidio_store/sessions.db")


def _init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
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
    return conn


class SessionRegistry:
    def __init__(self, db_path: Path = DEFAULT_DB):
        self.conn = _init_db(db_path)

    def create_session(self, doc_id: str = "default") -> str:
        sid = uuid.uuid4().hex[:12]
        now = time.time()
        self.conn.execute("INSERT INTO session(session_id, created_at) VALUES (?,?)", (sid, now))
        self.conn.commit()
        return sid

    def add_mapping(self, sid: str, doc_id: str, idx: int,
                    ptype: str, placeholder: str, original: str) -> None:
        self.conn.execute(
            "INSERT INTO mapping(session_id, doc_id, idx, ptype, placeholder, original, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, doc_id, idx, ptype, placeholder, original, time.time()))
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

    def delete_session(self, sid: str) -> None:
        self.conn.execute("DELETE FROM mapping WHERE session_id=?", (sid,))
        self.conn.execute("DELETE FROM session WHERE session_id=?", (sid,))
        self.conn.commit()
