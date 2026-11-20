// 轻量 PII 引擎核心流水线（Node 版）——逐字对齐 presidio_pii/engine.py
// 语义基准：Python「无 jieba fallback」模式；占位符 ⟦PII:<TYPE>:<SEQ:04d>⟧
import { NormalizedText } from './normalize.mjs';
import { getChineseRecognizers, loadAssets } from './recognizers.mjs';
import { CustomRuleSet } from './custom_rules.mjs';
import { SessionRegistry } from './db.mjs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const PH_OPEN = '⟦';
export const PH_CLOSE = '⟧';
const PH_SRC = '⟦PII:[A-Z_]+:\\d+⟧';
const UUID_SRC = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';

export function countPlaceholders(text) {
  return (text.match(new RegExp(PH_SRC, 'g')) || []).length;
}

// 实体优先级（重叠冲突时：数字越小优先级越高），对齐 engine.py:39-42
export const PRIO = Object.freeze({
  ID_NUMBER: 0, CREDIT_CODE: 1, PASSPORT: 2, PHONE_NUMBER: 3,
  EMAIL_ADDRESS: 4, LICENSE_PLATE: 5, BANK_CARD: 6, LOCATION: 7,
  PERSON: 8, JOB_TITLE: 9, ORGANIZATION: 10,
  IP_ADDRESS: 11, MAC_ADDRESS: 12,
});

// 内部结果用 plain object，避免依赖识别器模块的具体 class 实现（鸭子类型兼容）
function rr(start, end, entity_type, score) {
  return { start, end, entity_type, score };
}

const ENGINE_DIR = path.dirname(fileURLToPath(import.meta.url));

function defaultRepoDir() {
  return process.env.PII_GUARD_REPO || path.resolve(ENGINE_DIR, '..');
}

export class Engine {
  constructor(cfg = {}) {
    const repoDir = cfg.repoDir || defaultRepoDir();
    this._assets = loadAssets(repoDir);
    this._builtinRecognizers = getChineseRecognizers(this._assets);

    if (cfg.customRules instanceof CustomRuleSet) {
      this._ruleSet = cfg.customRules;
    } else if (typeof cfg.customRules === 'string') {
      this._ruleSet = new CustomRuleSet({ sources: cfg.customRules, checkInterval: cfg.rulesCheckInterval ?? 1.0, repoDir });
    } else if (Array.isArray(cfg.customRules)) {
      this._ruleSet = CustomRuleSet.fromRules(cfg.customRules);
    } else {
      this._ruleSet = new CustomRuleSet({ checkInterval: cfg.rulesCheckInterval ?? 1.0, repoDir });
    }

    this.registry = cfg.registry || new SessionRegistry(cfg.dbPath);
    this.whitelist = (cfg.whitelist || []).filter(Boolean);
    this.entityTypes = this._sanitizeEntityTypes(cfg.entityTypes);
    this._syncRecognizers();
  }

  _knownEntityTypes() {
    const known = new Set();
    for (const rec of this._builtinRecognizers) {
      if (rec.entity_type) known.add(rec.entity_type);
      for (const t of (rec.supportedEntities || [])) if (t) known.add(t);
    }
    // 内置识别器的类型也直接从模块级声明补齐（部分实现只在 result 上带类型）
    for (const t of Object.keys(PRIO)) known.add(t);
    for (const r of (this._ruleSet.rules || [])) if (r.entity_type) known.add(r.entity_type);
    return known;
  }

  _sanitizeEntityTypes(types) {
    const raw = new Set((types || []).filter(Boolean));
    if (!raw.size) return new Set();
    const known = this._knownEntityTypes();
    const valid = new Set([...raw].filter((t) => known.has(t)));
    const unknown = [...raw].filter((t) => !known.has(t));
    if (unknown.length) {
      console.error(`[pii] 忽略未知实体类型 ${JSON.stringify(unknown.sort())}；合法类型: ${JSON.stringify([...known].sort())}`);
    }
    return valid; // 全无效 → 空集合 → 视为全开（fail toward 多脱敏）
  }

  _syncRecognizers() {
    this.recognizers = [...this._builtinRecognizers, ...(this._ruleSet.rules || [])];
    const customPrio = typeof this._ruleSet.entityPriorities === 'function'
      ? this._ruleSet.entityPriorities() : {};
    this._prio = { ...PRIO, ...customPrio };
  }

  reloadCustomRules(force = true) {
    if (this._ruleSet.refresh(force)) this._syncRecognizers();
    return (this._ruleSet.rules || []).length;
  }

  setWhitelist(terms) {
    this.whitelist = (terms || []).filter(Boolean);
  }

  setEntityTypes(types) {
    this.entityTypes = this._sanitizeEntityTypes(types);
  }

  // ---- 白名单 ----
  _protectedSpans(text) {
    const spans = [];
    for (const term of this.whitelist) {
      let start = text.indexOf(term);
      while (start !== -1) {
        spans.push([start, start + term.length]);
        start = text.indexOf(term, start + 1);
      }
    }
    return spans;
  }

  _dropProtected(results, spans) {
    if (!spans.length) return [results, 0];
    const kept = results.filter((r) => !spans.some(([s, e]) => r.start < e && r.end > s));
    return [kept, results.length - kept.length];
  }

  // ---- 分析 ----
  analyze(text) {
    if (!text) return [];
    if (this._ruleSet.refresh()) this._syncRecognizers();
    const norm = new NormalizedText(text);
    const probe = norm.changed ? (norm.text ?? norm.normalized) : text;

    let rawHits = [];
    let probeHits = [];
    for (const rec of this.recognizers) {
      const wantsRaw = rec.wants_raw === true || rec.wantsRaw === true;
      const target = wantsRaw ? text : probe;
      let hits = [];
      if (typeof rec.analyze === 'function') hits = rec.analyze(target);
      else if (typeof rec.entities === 'function') hits = rec.entities(target);
      const bucket = wantsRaw ? rawHits : probeHits;
      for (const r of (hits || [])) bucket.push(r);
    }

    // 只有跑在归一化文本上的结果需要映射回原文坐标。wants_raw 的识别器（内置
    // 自定义规则）本来就返回原文坐标，再走一次 back() 会把跨度整体平移——实测
    // 把"男"挪成"民"、把"1990-03-07"吞掉后两个字符、把账号前两位留在明文里。
    // 双端 golden 完全一致却都错，就是因为两边犯了同一个错。
    let results = rawHits;
    if (norm.changed) {
      const mapped = [];
      for (const r of probeHits) {
        const [start, end] = norm.back(r.start, r.end);
        if (start < 0 || end > text.length || start >= end) continue;
        mapped.push(rr(start, end, r.entity_type, r.score));
      }
      results = rawHits.concat(mapped);
    } else {
      results = rawHits.concat(probeHits);
    }

    results = this._trimSpans(text, results);
    results = this._dropUuidSpans(text, results);
    results = this._filterEntityTypes(results);
    return this._resolveOverlaps(results, this._prio);
  }

  _filterEntityTypes(results) {
    if (!this.entityTypes.size) return results;
    const custom = new Set((this._ruleSet.rules || []).map((r) => r.entity_type).filter(Boolean));
    const allowed = new Set([...this.entityTypes, ...custom]);
    return results.filter((r) => allowed.has(r.entity_type));
  }

  _trimSpans(text, results) {
    const out = [];
    for (const r of results) {
      let start = r.start, end = r.end;
      while (start < end && /\s/u.test(text[start])) start++;
      while (end > start && /\s/u.test(text[end - 1])) end--;
      if (end <= start) continue;
      out.push((start === r.start && end === r.end) ? r : rr(start, end, r.entity_type, r.score));
    }
    return out;
  }

  _dropUuidSpans(text, results) {
    const spans = [];
    const re = new RegExp(UUID_SRC, 'g');
    let m;
    while ((m = re.exec(text)) !== null) spans.push([m.index, m.index + m[0].length]);
    if (!spans.length) return results;
    return results.filter((r) => !spans.some(([s, e]) => r.start < e && r.end > s));
  }

  _resolveOverlaps(results, prio) {
    if (!results.length) return [];
    const priority = prio || PRIO;
    const sorted = [...results].sort((a, b) => {
      const la = a.end - a.start, lb = b.end - b.start;
      if (la !== lb) return lb - la; // 长实体优先
      const pa = priority[a.entity_type] ?? 99, pb = priority[b.entity_type] ?? 99;
      if (pa !== pb) return pa - pb; // 等长按优先级
      return a.start - b.start;      // 再按起点
    });
    const merged = [];
    for (const r of sorted) {
      if (!merged.some((m) => r.start < m.end && r.end > m.start)) merged.push(r);
    }
    merged.sort((a, b) => a.start - b.start);
    return merged;
  }

  // ---- 脱敏 ----
  redact(text, sid, docId = 'default', counters = null, commit = true) {
    let results = this.analyze(text);
    let skipped = 0;
    if (this.whitelist.length) {
      const [kept, n] = this._dropProtected(results, this._protectedSpans(text));
      results = kept;
      skipped = n;
    }
    if (!counters) counters = {};
    for (const res of results) {
      if (!(res.entity_type in counters)) {
        counters[res.entity_type] = this.registry.getMaxSeq(sid, res.entity_type);
      }
    }

    const restored = {}, entityCounts = {}, plan = [];
    for (const res of results) {
      const ptype = res.entity_type;
      counters[ptype] = (counters[ptype] || 0) + 1;
      const ph = `${PH_OPEN}PII:${ptype}:${String(counters[ptype]).padStart(4, '0')}${PH_CLOSE}`;
      const orig = text.slice(res.start, res.end);
      plan.push({ res, ph, orig });
      restored[ph] = orig;
      entityCounts[ptype] = (entityCounts[ptype] || 0) + 1;
    }

    // 逆序替换以避免 offset 漂移
    let outText = text;
    for (const { res, ph } of [...plan].reverse()) {
      outText = outText.slice(0, res.start) + ph + outText.slice(res.end);
    }

    plan.forEach(({ res, ph, orig }, idx) => {
      this.registry.addMapping(sid, docId, idx, res.entity_type, ph, orig, false);
    });
    if (plan.length && commit) this.registry.commit();

    return {
      text: outText, session_id: sid, doc_id: docId,
      n_replaced: plan.length, restored, entity_counts: entityCounts,
      n_whitelisted: skipped,
      // camelCase 别名，方便 JS 调用方
      sessionId: sid, docId, nReplaced: plan.length,
    };
  }

  // ---- 还原 ----
  restore(text, sid, docId = 'default', mapping = null, collectUnrestored = true) {
    if (mapping == null) mapping = this.registry.getRestoreMap(sid, docId);
    const byPh = (mapping && !Array.isArray(mapping))
      ? mapping
      : Object.fromEntries((mapping || []).map((m) => [m.placeholder, m.original]));

    let out = text;
    const restored = {};
    const found = text.match(new RegExp(PH_SRC, 'g')) || [];
    for (const ph of found) {
      if (ph in restored) continue;
      const orig = byPh[ph];
      if (orig === undefined || orig === null) continue;
      out = out.split(ph).join(orig);
      restored[ph] = orig;
    }
    const unrestored = collectUnrestored
      ? Object.fromEntries(Object.entries(byPh).filter(([ph]) => !(ph in restored)))
      : {};
    return { text: out, restored, unrestored, session_id: sid, doc_id: docId };
  }

  reset() {
    this.registry.close();
  }
}

export default Engine;
