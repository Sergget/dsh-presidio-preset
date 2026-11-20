// PII 脱敏常驻服务（stdio JSON 行协议）——逐字对齐 presidio_pii/server.py。
// 供 dsh-pii-guard Node 插件作为子进程 spawn；启动一次，词表加载一次。
import readline from 'node:readline';
import { getEngine, beforeLlm, sessionId, maskValue } from './hooks.mjs';

const PH_RE = /⟦PII:([A-Z_]+):(\d+)⟧/g;

function phType(ph) { return ph.replace(/^⟦/, '').replace(/⟧$/, '').split(':')[1]; }

function restoreDisplay(text, sid, mode) {
  const engine = getEngine();
  const key = sessionId(sid);
  const mapping = engine.registry.getRestoreMap(key, 'svc');
  const byPh = Object.fromEntries(mapping.map((m) => [m.placeholder, m.original]));
  if (mode === 'mask') {
    // 必须对「原始 text 的占位符」打码，不能在 rs.text 上做——
    // engine.restore 已把占位符还原成原文，在 rs.text 上 replace 找不到占位符，
    // 会原样输出完整 PII（显示侧泄露）。原文不过显示侧。
    const display = text.replace(PH_RE, (whole, etype) => {
      const orig = byPh[whole];
      return orig ? maskValue(orig, etype) : whole;
    });
    const seen = new Set();
    let n = 0;
    for (const m of text.matchAll(PH_RE)) {
      if (byPh[m[0]] !== undefined && !seen.has(m[0])) { seen.add(m[0]); n++; }
    }
    return { display, n };
  }
  const rs = engine.restore(text, key, 'svc', mapping);
  return { display: rs.text, n: Object.keys(rs.restored).length };
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (rawLine) => {
  const line = rawLine.trim();
  if (!line) return;
  let rid = null;
  try {
    const req = JSON.parse(line);
    rid = req.id;
    const op = req.op || 'redact';
    const text = req.text ?? '';
    const sid = req.sid ?? 'svc';
    if (op === 'restore') {
      const mode = req.mode || 'full';
      if (mode !== 'full' && mode !== 'mask') throw new Error(`bad mode: ${JSON.stringify(mode)}`);
      const { display, n } = restoreDisplay(text, sid, mode);
      emit({ id: rid, restored: display, n });
    } else {
      const engine = getEngine();
      const skey = sessionId(sid);
      const before = engine.registry.getRestoreMap(skey, 'svc');
      const beforeKeys = new Set(before.map((m) => m.placeholder));
      const redacted = beforeLlm(text, sid, 'svc');
      const after = engine.registry.getRestoreMap(skey, 'svc');
      const byPh = Object.fromEntries(after.map((m) => [m.placeholder, m.original]));
      const mode = String(req.mode || 'full').toLowerCase();
      const phMap = {};
      for (const [ph, orig] of Object.entries(byPh)) {
        if (beforeKeys.has(ph)) continue; // 只增量下发新映射
        phMap[ph] = mode === 'mask' ? maskValue(orig, phType(ph)) : orig;
      }
      emit({ id: rid, redacted, n: redacted.split('⟦PII:').length - 1, map: phMap });
    }
  } catch (ex) {
    emit({ id: rid, error: String(ex && ex.stack ? ex.stack : ex) });
  }
});
