/**
 * Shared regex safety helpers for dsh-presidio-pii.
 *
 * `hasNestedQuantifier` detects the classic catastrophic-backtracking shape
 * (a quantified group whose body can itself repeat, or whose alternation
 * branches share a prefix — e.g. `(a+)+`, `(a|a)*`, `(\d+|\d+)+`).
 *
 * It is intentionally a heuristic, not a full regex analyser: the goal is to
 * reject the user-supplied shell allowlist patterns that can freeze the agent
 * loop, without rejecting ordinary command patterns.
 */

/**
 * @param {string} source regular expression source (no surrounding slashes)
 * @returns {boolean} true when the pattern looks vulnerable to ReDoS
 */
export function hasNestedQuantifier(source) {
  const n = String(source ?? '').length;
  let i = 0;

  function readQuant() {
    if (i >= n) return null;
    const ch = source[i];
    if (ch === '*' || ch === '+' || ch === '?') {
      i += 1;
      if (source[i] === '?' || source[i] === '+') i += 1;
      return ch === '?' ? 1 : Infinity;
    }
    if (ch === '{') {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(source.slice(i));
      if (!m) return null;
      i += m[0].length;
      const min = parseInt(m[1], 10);
      let max;
      if (m[2] === undefined) max = min;
      else if (m[3] === '') max = Infinity;
      else max = parseInt(m[3], 10);
      if (source[i] === '?' || source[i] === '+') i += 1;
      return Math.max(min, max);
    }
    return null;
  }

  function parseBody(inGroup) {
    let fatal = false;
    let repeatIn = false;
    const branchTexts = [''];
    let active = 0;

    while (i < n) {
      const ch = source[i];
      if (ch === '\\') { i += 2; branchTexts[active] += '\\'; continue; }
      if (ch === '[') {
        i += 1;
        if (source[i] === '^') i += 1;
        if (source[i] === ']') i += 1;
        while (i < n && source[i] !== ']') { if (source[i] === '\\') i += 1; i += 1; }
        if (source[i] === ']') i += 1;
        const q = readQuant();
        if (q !== null && q > 1) repeatIn = true;
        branchTexts[active] += '©';
        continue;
      }
      if (ch === '(') {
        i += 1;
        if (source[i] === '?') {
          if (['?:', '?=', '?!'].includes(source.slice(i, i + 2))) i += 2;
          else if (['?<=', '?<!'].includes(source.slice(i, i + 3))) i += 3;
          else if (source[i + 1] === '<') {
            const gt = source.indexOf('>', i);
            if (gt !== -1 && gt - i < 64) i = gt + 1;
            else i += 1;
          } else i += 1;
        }
        const child = parseBody(true);
        if (source[i] === ')') i += 1;
        const q = readQuant();
        if (q !== null && q > 1) {
          if (child.repeatIn) fatal = true;
          if (child.branchTexts.length > 1 && overlap(child.branchTexts)) fatal = true;
          repeatIn = true;
        }
        if (child.repeatIn) repeatIn = true;
        if (child.fatal) fatal = true;
        continue;
      }
      if (ch === ')') {
        if (inGroup) { i += 1; return { fatal, repeatIn, branchTexts }; }
        i += 1;
        continue;
      }
      if (ch === '|') { branchTexts.push(''); active = branchTexts.length - 1; i += 1; continue; }
      i += 1;
      const q = readQuant();
      if (q !== null && q > 1) repeatIn = true;
      branchTexts[active] += ch;
    }
    return { fatal, repeatIn, branchTexts };
  }

  function overlap(texts) {
    const keys = texts.filter((s) => s.length > 0 && !s.includes('\\'));
    for (let a = 0; a < keys.length; a += 1) {
      for (let b = a + 1; b < keys.length; b += 1) {
        if (keys[a] === keys[b] || keys[a].startsWith(keys[b]) || keys[b].startsWith(keys[a])) return true;
      }
    }
    return false;
  }

  return parseBody(false).fatal;
}
