// SQLite 临时登记与还原映射存储（node:sqlite 版，零 npm 依赖）。
// 逐字对齐 presidio_pii/db.py：schema / WAL+NORMAL / getMaxSeq 口径。
//
// 关键差异（RCA）：Python sqlite3 默认开启隐式事务，DML 需显式 commit()；
// node:sqlite 默认 autocommit，裸 COMMIT 会报 "no transaction is active"。
// 为忠实复刻 addMapping(commit=false) + commit() 的批量提交语义，这里显式
// 维护 BEGIN/COMMIT 事务边界。
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const IS_WIN = process.platform === 'win32';

/** Windows ACL 里保留的主体: 当前用户 + SYSTEM + 本机管理员组（对齐 db.py:_granted_principals）。 */
function grantedPrincipals() {
  const names = [];
  const user = process.env.USERNAME;
  const domain = process.env.USERDOMAIN;
  if (user) names.push(domain ? `${domain}\\${user}` : user);
  names.push('SYSTEM');
  names.push('BUILTIN\\Administrators');
  return names;
}

function icacls(target, extra) {
  try {
    const r = spawnSync('icacls', [target, ...extra], { timeout: 15000, windowsHide: true });
    return r.status === 0;
  } catch {
    return false;
  }
}

/** 权限收紧：POSIX chmod（目录 0700 / 文件 0600）；Windows icacls 去继承并只授予
 * 当前用户 + SYSTEM + 管理员组（映射库存明文原文，默认继承的 Users 组同机可读）。
 * 任何失败只告警不阻断；收紧后自查仍可访问，失败则回滚继承，绝不让库打不开。
 * 逐字对齐 db.py:_harden。 */
function harden(target, directory) {
  try {
    if (!fs.existsSync(target)) return;
    if (IS_WIN) {
      const flag = directory ? ':(OI)(CI)F' : ':F';
      const grants = grantedPrincipals().map((n) => `${n}${flag}`);
      if (!icacls(target, ['/inheritance:r', '/grant:r', ...grants])) {
        console.warn(`[pii] 无法收紧权限 (icacls 失败): ${target}`);
        return;
      }
      // 回读验证: 自己仍可访问, 否则回滚继承
      try {
        fs.accessSync(target, fs.constants.R_OK | fs.constants.W_OK);
      } catch {
        icacls(target, ['/inheritance:e']);
        console.warn(`[pii] 权限收紧后自查失败, 已回滚: ${target}`);
      }
    } else {
      fs.chmodSync(target, directory ? 0o700 : 0o600);
    }
  } catch (exc) {
    // 权限收紧失败不阻断脱敏功能。
    console.warn(`[pii] 无法收紧权限 (${target}): ${exc}`);
  }
}

function initSchema(conn) {
  conn.exec(`CREATE TABLE IF NOT EXISTS session (
        session_id TEXT PRIMARY KEY, created_at REAL)`);
  conn.exec(`CREATE TABLE IF NOT EXISTS mapping (
        session_id  TEXT,
        doc_id      TEXT,
        idx         INTEGER,
        ptype       TEXT,
        placeholder TEXT,
        original    TEXT,
        created_at  REAL)`);
  conn.exec('CREATE INDEX IF NOT EXISTS ix_map_sess ON mapping(session_id)');
  // getMaxSeq 按 (session_id, ptype) 取 MAX，无此索引会退化为全表扫描。
  conn.exec('CREATE INDEX IF NOT EXISTS ix_map_sess_ptype ON mapping(session_id, ptype)');
}

export class SessionRegistry {
  constructor(dbPath) {
    const memory = dbPath === ':memory:';
    if (!memory) {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
      harden(path.dirname(dbPath), true);
    }
    this.conn = new DatabaseSync(String(dbPath));
    this._txOpen = false;
    // WAL + NORMAL：批量写入减少 fsync；:memory: 会忽略这两个 PRAGMA。
    this.conn.exec('PRAGMA journal_mode=WAL');
    this.conn.exec('PRAGMA synchronous=NORMAL');
    initSchema(this.conn);
    if (!memory) {
      // 建库/建 WAL 之后再收紧一次：WAL 与 shm 是后生成的。
      for (const suffix of ['', '-wal', '-shm']) harden(String(dbPath) + suffix, false);
    }
  }

  _begin() {
    if (!this._txOpen) {
      this.conn.exec('BEGIN');
      this._txOpen = true;
    }
  }

  createSession() {
    const sid = randomBytes(16).toString('hex').slice(0, 12);
    this._begin();
    this.conn.prepare('INSERT INTO session(session_id, created_at) VALUES (?,?)')
      .run(sid, Date.now() / 1000);
    this.commit();
    return sid;
  }

  addMapping(sid, docId, idx, ptype, placeholder, original, commit = true) {
    this._begin();
    this.conn.prepare(
      'INSERT INTO mapping(session_id, doc_id, idx, ptype, placeholder, original, created_at) '
      + 'VALUES (?,?,?,?,?,?,?)'
    ).run(sid, docId, idx, ptype, placeholder, original, Date.now() / 1000);
    if (commit) this.commit();
  }

  commit() {
    if (this._txOpen) {
      this.conn.exec('COMMIT');
      this._txOpen = false;
    }
  }

  getRestoreMap(sid, docId) {
    let sql = 'SELECT ptype, placeholder, original FROM mapping WHERE session_id=?';
    const args = [sid];
    if (docId) {
      sql += ' AND doc_id=?';
      args.push(docId);
    }
    sql += ' ORDER BY idx';
    // 参数必须逐个展开传入：传数组会被 node:sqlite 当成命名参数对象而报错。
    const rows = this.conn.prepare(sql).all(...args);
    return rows.map((r) => ({ ptype: r.ptype, placeholder: r.placeholder, original: r.original }));
  }

  getMaxSeq(sid, ptype) {
    // 1-based 起点：⟦PII: 共 5 字符，加类型名与分隔冒号，再进 1 落到首位数字。
    // 尾部 ⟧ 不必裁：CAST('12345⟧' AS INTEGER) 在首个非数字处停止。
    const digitStart = 5 + ptype.length + 2;
    const row = this.conn.prepare(
      'SELECT MAX(CAST(SUBSTR(placeholder, ?) AS INTEGER)) AS mx '
      + 'FROM mapping WHERE session_id=? AND ptype=?'
    ).get(digitStart, sid, ptype);
    return row?.mx || 0;
  }

  deleteSession(sid) {
    this._begin();
    this.conn.prepare('DELETE FROM mapping WHERE session_id=?').run(sid);
    this.conn.prepare('DELETE FROM session WHERE session_id=?').run(sid);
    this.commit();
  }

  close() {
    try {
      // 有未提交事务时回滚，对齐 Python close() 对活动事务的处理。
      if (this._txOpen) {
        this.conn.exec('ROLLBACK');
        this._txOpen = false;
      }
      this.conn.close();
    } catch {
      // 关闭异常不阻断退出。
    }
  }
}

export default SessionRegistry;
