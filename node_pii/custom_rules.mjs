// 用户自定义规则（Node 版）——逐字对齐 presidio_pii/custom_rules.py 的 JSON 正则规则部分
// 差异：.py 代码规则（importlib 执行任意 Python analyze()）Node 无法等价执行，忽略并告警。
import fs from 'node:fs';

const CUSTOM_ENV = 'PII_DSH_CUSTOM_RULES';
const CONTEXT_WINDOW = 20;
const DEFAULT_PRIORITY = 99;

function warn(msg) {
  console.error(`[custom_rules] ${msg}`);
}

function rr(start, end, entity_type, score) {
  return { start, end, entity_type, score };
}

function parsePriority(value) {
  if (value == null) return DEFAULT_PRIORITY;
  if (typeof value === 'boolean' || typeof value !== 'number' || !Number.isInteger(value)) {
    throw new Error(`priority 需为 0-99 的整数: ${JSON.stringify(value)}`);
  }
  if (value < 0 || value > 99) throw new Error(`priority 超出 0-99: ${value}`);
  return value;
}

function specHintsReject(spec, text, start) {
  const ctx = text.slice(Math.max(0, start - CONTEXT_WINDOW), start);
  if (spec.negative_hint?.length && spec.negative_hint.some((h) => ctx.includes(h))) return true;
  if (spec.context_hint?.length && !spec.context_hint.some((h) => ctx.includes(h))) return true;
  return false;
}

// JSON 规则生成的正则识别器（鸭子类型，对齐 RegexRuleRecognizer）
class RegexRuleRecognizer {
  constructor(spec, regexStr) {
    this.name = spec.name;
    this.entity_type = spec.entity_type;
    this.score = spec.score;
    this.priority = spec.priority;
    this.spec = spec;
    this.wants_raw = true; // 原文匹配，坐标即原文坐标（对齐 Python:117）
    this.regex = new RegExp(regexStr, 'g');
  }

  analyze(text) {
    const out = [];
    this.regex.lastIndex = 0;
    let m;
    while ((m = this.regex.exec(text)) !== null) {
      let s, e;
      if (m.length > 1 && m[1] !== undefined) {
        const g1 = m[1];
        // 计算 group1 在全文中的偏移：group1 起点 = match 起点 + group0 中 group1 的相对位置
        const rel = m[0].indexOf(g1);
        s = m.index + (rel >= 0 ? rel : 0);
        e = s + g1.length;
      } else {
        s = m.index;
        e = s + m[0].length;
      }
      if (specHintsReject(this.spec, text, s)) {
        if (m[0].length === 0) this.regex.lastIndex++;
        continue;
      }
      out.push(rr(s, e, this.entity_type, this.score));
      if (m[0].length === 0) this.regex.lastIndex++;
    }
    return out;
  }
}

function resolveValidator() {
  // Python 的 "模块:函数" 校验器依赖 importlib 执行，Node 无法等价——忽略并告警
  warn('检测到 validator 引用（Python 代码规则），Node 版不支持，已忽略该校验器');
  return null;
}

function loadJsonRules(path, strict = false) {
  const rules = [];
  const errors = [];
  let data;
  try {
    data = JSON.parse(fs.readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
  } catch (ex) {
    if (strict) throw new Error(`${path}: ${ex.message}`);
    warn(`规则文件读取失败 ${path}: ${ex.message}`);
    return [];
  }
  if (!Array.isArray(data)) {
    if (strict) throw new Error(`${path}: 规则文件顶层应为数组`);
    warn(`${path}: 规则文件顶层应为数组`);
    return [];
  }
  for (const item of data) {
    try {
      if (!item || typeof item !== 'object') throw new Error('规则项不是对象');
      if (!item.name || !item.entity_type || !item.pattern) {
        throw new Error('缺少 name/entity_type/pattern');
      }
      const spec = {
        name: item.name,
        entity_type: item.entity_type,
        score: Number(item.score ?? 0.80),
        context_hint: item.context_hint || [],
        negative_hint: item.negative_hint || [],
        priority: parsePriority(item.priority),
      };
      if (item.validator) resolveValidator();
      // 验证正则可编译
      new RegExp(item.pattern, 'g');
      rules.push(new RegexRuleRecognizer(spec, item.pattern));
    } catch (ex) {
      const msg = `跳过非法规则 ${item?.name ?? '?'}: ${ex.message}`;
      if (strict) errors.push(msg);
      else warn(msg);
    }
  }
  if (strict && errors.length) throw new Error(errors.join('; '));
  return rules;
}

function loadCustomRules(value, strict = false) {
  const raw = value ?? process.env[CUSTOM_ENV];
  if (!raw) return [];
  const rules = [];
  const errors = [];
  for (const part of String(raw).split(/[;,]/)) {
    const p = part.trim();
    if (!p) continue;
    if (!fs.existsSync(p)) {
      const msg = `规则文件不存在: ${p}`;
      if (strict) errors.push(msg); else warn(msg);
      continue;
    }
    const lower = p.toLowerCase();
    try {
      if (lower.endsWith('.json')) rules.push(...loadJsonRules(p, strict));
      else if (lower.endsWith('.py')) {
        const msg = `Python 代码规则 Node 版不支持，已忽略: ${p}`;
        if (strict) errors.push(msg); else warn(msg);
      } else throw new Error(`不支持的规则文件类型: ${p}`);
    } catch (ex) {
      if (strict) errors.push(ex.message); else warn(ex.message);
    }
  }
  if (strict && errors.length) throw new Error(errors.join('; '));
  return rules;
}

export class CustomRuleSet {
  constructor(opts = {}) {
    this.opts = opts;
    this._static = Array.isArray(opts.rules);
    this.sources = opts.sources ?? (this._static ? null : (process.env[CUSTOM_ENV] || null));
    this.strict = opts.strict ?? false;
    this.checkInterval = Math.max(0, Number(opts.checkInterval ?? 1.0));
    this._lastCheck = 0;
    this._signature = '';
    if (this._static) {
      this.rules = [...opts.rules];
    } else {
      this._signature = this._sourceSignature();
      this.rules = loadCustomRules(this.sources, this.strict);
    }
  }

  static fromRules(rules) {
    return new CustomRuleSet({ rules });
  }

  _sourcePaths() {
    if (!this.sources) return [];
    return String(this.sources).split(/[;,]/).map((p) => p.trim()).filter(Boolean);
  }

  _sourceSignature() {
    const sig = [];
    for (const p of this._sourcePaths()) {
      try {
        const st = fs.statSync(p);
        sig.push(`${p}|${st.mtimeMs}|${st.size}`);
      } catch {
        sig.push(`${p}|none|none`);
      }
    }
    return sig.join(';');
  }

  refresh(force = false) {
    if (this._static || !this.sources) return false;
    const now = Date.now();
    if (!force) {
      if (this.checkInterval <= 0) return false;
      if (now - this._lastCheck < this.checkInterval * 1000) return false;
    }
    this._lastCheck = now;
    const sig = this._sourceSignature();
    if (sig === this._signature) return false;
    let rules;
    try {
      rules = loadCustomRules(this.sources, false);
    } catch (ex) {
      warn(`规则热更新失败，继续使用上一份规则: ${ex.message}`);
      this._signature = sig;
      return false;
    }
    if (!rules.length && this.rules.length) {
      warn('规则热更新未产出任何规则（文件缺失或全部非法），继续使用上一份规则');
      this._signature = sig;
      return false;
    }
    this.rules = rules;
    this._signature = sig;
    return true;
  }

  entityPriorities() {
    const prio = {};
    for (const r of this.rules) {
      const p = r.priority;
      const t = r.entity_type;
      if (p == null || !t) continue;
      if (!(t in prio) || p < prio[t]) prio[t] = p;
    }
    return prio;
  }

  get entityTypes() {
    return [...new Set(this.rules.map((r) => r.entity_type).filter(Boolean))];
  }

  [Symbol.iterator]() { return this.rules[Symbol.iterator](); }
  get length() { return this.rules.length; }
}

export default CustomRuleSet;
