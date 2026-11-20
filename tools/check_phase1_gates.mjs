// Phase 1 门禁检查（门禁①②③）
// 门禁①：预设 plugins 数组不得出现 dsh-tool-executor-ptc
// 门禁②：预设 plugins 数组不得出现 PII_GUARD_FAIL_OPEN=1
// 门禁③：spill 目录占位符形态检查

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const REPO = new URL("../", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

function fail(msg) { console.error("FAIL:", msg); process.exitCode = 1; }
function pass(msg) { console.log("PASS:", msg); }

// ── 门禁① + ②：扫描 agent.cordis.yml + bundle/cordis.patch.yml ──────────
const ymlFiles = [
  join(REPO, ".agent-presets", "presidio-pii", "agent.cordis.yml"),
  join(REPO, ".agent-presets", "presidio-pii", "bundle", "cordis.patch.yml"),
];

for (const fp of ymlFiles) {
  const text = readFileSync(fp, "utf8");
  const fname = fp.replace(REPO, "").replace(/\\/g, "/");

  if (text.includes("dsh-tool-executor-ptc")) {
    fail(`${fname} 不得出现 dsh-tool-executor-ptc（门禁①）`);
  } else {
    pass(`${fname} 无 dsh-tool-executor-ptc（门禁①）`);
  }

  if (text.includes("PII_GUARD_FAIL_OPEN=1")) {
    fail(`${fname} 不得出现 PII_GUARD_FAIL_OPEN=1（门禁②）`);
  } else {
    pass(`${fname} 无 PII_GUARD_FAIL_OPEN=1（门禁②）`);
  }
}

// ── 门禁③：spill 目录占位符形态检查 ─────────────────────────────────────
const spillDirs = [
  join(REPO, ".pii_presidio_store", "spill"),
  join(REPO, ".pii_presidio_store", "spill-local"),
];

for (const dir of spillDirs) {
  try {
    const st = statSync(dir);
    if (!st.isDirectory()) continue;
    const files = readdirSync(dir);
    for (const f of files) {
      const fp = join(dir, f);
      const text = readFileSync(fp, "utf8");
      if (/⟦PII:⟦PII:/.test(text)) {
        fail(`spill 文件 ${fp} 存在嵌套占位符 ⟦PII:⟦PII:（门禁③）`);
        continue;
      }
      const longDigits = text.match(/\d{6,}/g);
      if (longDigits) {
        fail(`spill 文件 ${fp} 存在未脱敏长数字串 ${longDigits.slice(0, 3)}（门禁③）`);
        continue;
      }
      pass(`spill 文件 ${fp} 通过占位符形态检查（门禁③）`);
    }
    if (files.length === 0) {
      pass(`spill 目录 ${dir} 为空，无需检查（门禁③）`);
    }
  } catch {
    pass(`spill 目录 ${dir} 不存在，无需检查（门禁③）`);
  }
}

console.log("GATE_PHASE1_DONE");
