// JSONL 审计日志（零 npm 依赖），逐字对齐 presidio_pii/journal.py。
import fs from 'node:fs';
import path from 'node:path';

/** 本地时间、秒精度 ISO（等价 Python datetime.now().isoformat(timespec='seconds')）。 */
function localIsoSeconds(now = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}`
    + `T${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
}

export class JsonlJournal {
  /** maxBytes<=0 表示不限大小（契约默认 0）；>0 时超限轮转为 <path>.1。 */
  constructor(filePath, maxBytes = 0) {
    this.path = String(filePath);
    this.maxBytes = Number(maxBytes) || 0;
    fs.mkdirSync(path.dirname(this.path), { recursive: true });
  }

  /**
   * 超限则把当前文件轮转为 .1（先删旧 .1 再 rename），失败不阻塞写入。
   * 契约：备份文件只有一份；轮转按字节数判断。
   */
  _rotateIfNeeded(incomingBytes) {
    if (this.maxBytes <= 0) return;
    let size = 0;
    try {
      size = fs.statSync(this.path).size;
    } catch (exc) {
      // 文件还不存在：没有可轮转的内容，直接返回（否则首条超长记录会对
      // 不存在的文件做 rename，产生无意义的 ENOENT 告警）。
      if (exc?.code === 'ENOENT') return;
      throw exc;
    }
    if (size + incomingBytes <= this.maxBytes) return;
    const backup = `${this.path}.1`;
    try {
      try {
        fs.unlinkSync(backup);
      } catch (exc) {
        if (exc?.code !== 'ENOENT') throw exc;
      }
      fs.renameSync(this.path, backup);
    } catch (exc) {
      // 轮转失败不阻断写：日志照常追加。
      console.warn(`[pii] journal 轮转失败 (${backup}): ${exc}`);
    }
  }

  record(event, fields = {}) {
    const now = new Date();
    const rec = {
      ts: Math.round((now.getTime() / 1000) * 1000) / 1000,
      iso: localIsoSeconds(now),
      event,
      ...fields,
    };
    const line = JSON.stringify(rec) + '\n';
    this._rotateIfNeeded(Buffer.byteLength(line, 'utf8'));
    fs.appendFileSync(this.path, line, { encoding: 'utf8' });
  }

  /** 读取当前文件（不含 .1 备份），逐行解析，跳过空行与坏行。 */
  readAll() {
    let data;
    try {
      data = fs.readFileSync(this.path, 'utf8');
    } catch (exc) {
      if (exc?.code === 'ENOENT') return [];
      throw exc;
    }
    const out = [];
    for (const line of data.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        out.push(JSON.parse(trimmed));
      } catch {
        // 跳过半行/坏行，保持读取鲁棒。
      }
    }
    return out;
  }
}

export default JsonlJournal;
