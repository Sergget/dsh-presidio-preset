// 验证 presidio-pii agent preset 声明里的每条子插件在**当前 dsh 版本**可解析。
//
// 背景：dsh 0.2.1-rc.5 -> 0.2.2-rc.1 时，
//   @deepseek-ai/dsh-tool-subagent-control/list-agents 子路径导出被删除
//   （功能并入主入口 @deepseek-ai/dsh-tool-subagent-control）。
// preset 的 plugins 清单若残留该子行，registry 激活时 auditRows 导入失败，
// record.broken 被置位，GUI 显示「加载失败」。
//
// 用法：
//   node tools/verify_preset_plugins.mjs [patch.yml ...]
// 缺省检查：
//   $DSH_HOME/cordis.patch.yml
//   $DSH_HOME/profiles/desktop/cordis.patch.yml
//   <repo>/.agent-presets/presidio-pii/bundle/cordis.patch.yml
//
// 退出码：0=全部可解析（且无重复 preset id），1=发现问题，2=参数/读取错误。
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ─── DSH 依赖定位（FIX-3） ───────────────────────────────────────────────
// 病根：旧版只认 `npm root -g`。app.asar 形态 DSH 的全局 npm root 下没有
// @deepseek-ai/dsh，createRequire 直接抛错且无任何指引。
// 定位策略：
//   - 显式 env DSH_NODE_MODULES = 硬覆盖（必须有效，无效立即报错退出，绝不静默回退）。
//   - 未设置时按 fallback 梯度探测，直到找到含 @deepseek-ai/dsh/package.json 的目录：
//       1. $DSH_HOME/node_modules
//       2. $DSH_INSTALL_DIR/resources/app.asar.unpacked/dsh/node_modules
//       3. $DSH_HOME/profiles/*/node_modules（逐个扫描）
//       4. npm root -g（最后兜底，npm i -g 形态）
const DSH_PKG_REL = "@deepseek-ai/dsh/package.json";

function norm(p) {
  return String(p).replace(/\\/g, "/");
}

// 探测某个 node_modules 根目录下是否真有 dsh 包（用 existsSync，不用 async——
// createRequire 需要同步确定基准；existsSync 已足够可靠）。
function hasDsh(nodeModulesDir) {
  return existsSync(resolve(nodeModulesDir, DSH_PKG_REL));
}

// 收集 npm root -g，失败不致命（兼容无 npm / 受限环境）。
function npmGlobalRoot() {
  try {
    return execSync("npm root -g", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

// 未显式指定 DSH_NODE_MODULES 时，按以下顺序自动探测 fallback 候选。
function buildFallbackCandidates() {
  const candidates = [];
  const note = (source, dir) => candidates.push({ source, dir: norm(dir) });
  const home = process.env.DSH_HOME;

  // $DSH_HOME/node_modules
  if (home) note("$DSH_HOME/node_modules", resolve(home, "node_modules"));

  // $DSH_INSTALL_DIR/resources/app.asar.unpacked/dsh/node_modules
  if (process.env.DSH_INSTALL_DIR) {
    note("$DSH_INSTALL_DIR/resources/app.asar.unpacked/dsh/node_modules",
      resolve(process.env.DSH_INSTALL_DIR, "resources/app.asar.unpacked/dsh/node_modules"));
  }

  // $DSH_HOME/profiles/*/node_modules（只扫描存在的 profile 目录）
  if (home) {
    const profilesDir = resolve(home, "profiles");
    try {
      if (existsSync(profilesDir)) {
        for (const entry of readdirSync(profilesDir, { withFileTypes: true })) {
          if (entry.isDirectory()) {
            note(`$DSH_HOME/profiles/${entry.name}/node_modules`,
              resolve(profilesDir, entry.name, "node_modules"));
          }
        }
      }
    } catch {
      // profiles 目录不可读时跳过该候选源，不致命。
    }
  }

  // npm root -g —— 最后兜底（npm i -g 形态）。
  const globalRoot = npmGlobalRoot();
  if (globalRoot) note("npm root -g", globalRoot);

  return candidates;
}

function printGuidanceAndExit(tried, header) {
  console.error(header);
  for (const c of tried) {
    console.error(`  - [${c.source}] ${c.dir}  (缺少 ${DSH_PKG_REL})`);
  }
  if (tried.length === 0) {
    console.error("  - （无任何候选：请设置 DSH_HOME 或 DSH_INSTALL_DIR，或确认 npm 可用）");
  }
  console.error("");
  console.error("修复指引：");
  console.error("  1) 显式指定含 @deepseek-ai/dsh 的 node_modules 根目录后重试：");
  console.error("       PowerShell:  $env:DSH_NODE_MODULES='<含 @deepseek-ai/dsh 的 node_modules 目录>'; node tools/verify_preset_plugins.mjs");
  console.error("       cmd:         set DSH_NODE_MODULES=<含 @deepseek-ai/dsh 的 node_modules 目录> && node tools/verify_preset_plugins.mjs");
  console.error("  2) 或设置 DSH_HOME / DSH_INSTALL_DIR 指向实际安装位置，脚本会自动探测：");
  console.error("       $env:DSH_HOME='<dsh 主目录>'; node tools/verify_preset_plugins.mjs");
  console.error("       $env:DSH_INSTALL_DIR='<dsh 安装目录，含 resources/app.asar.unpacked>'; node tools/verify_preset_plugins.mjs");
  console.error("  3) 若 dsh 以 npm 全局方式安装，确认 `npm root -g` 下存在 @deepseek-ai/dsh。");
  process.exit(2);
}

const explicit = process.env.DSH_NODE_MODULES;
let DSH_NODE_MODULES = null;

if (explicit) {
  // 显式 env 是硬覆盖：用户既然指定了位置，就不会静默回退到别处——否则
  // 用户会以为用的是他指定的路径，实际不是，这违反"不静默失败"原则。
  const dir = norm(explicit);
  if (hasDsh(dir)) {
    DSH_NODE_MODULES = dir;
  } else {
    // 列出"若省略此变量本会尝试的候选"，帮用户判断该把它改成什么。
    printGuidanceAndExit(
      [{ source: "env DSH_NODE_MODULES（显式指定）", dir }].concat(buildFallbackCandidates()),
      `ERROR: 显式指定的 DSH_NODE_MODULES 不含 ${DSH_PKG_REL}：${dir}\n      显式指定是硬覆盖，不会静默回退到其他路径；若省略它，本脚本会尝试：`
    );
  }
} else {
  // 未显式指定：按 DSH_HOME → DSH_INSTALL_DIR → profiles → npm root -g 梯度探测。
  const tried = [];
  for (const cand of buildFallbackCandidates()) {
    tried.push(cand);
    if (hasDsh(cand.dir)) {
      DSH_NODE_MODULES = cand.dir;
      break;
    }
  }
  if (!DSH_NODE_MODULES) {
    printGuidanceAndExit(tried, "ERROR: 无法定位 @deepseek-ai/dsh —— 已尝试以下 DSH_NODE_MODULES 候选（按优先级）：");
  }
}

// 从 @deepseek-ai/dsh 的 package.json 解析：npm 会把部分传递依赖（如 yaml）
// 嵌在它自己的 node_modules 下，而不是平铺到根目录。
const dshRequire = createRequire(resolve(DSH_NODE_MODULES, DSH_PKG_REL));

let YAML;
try {
  YAML = dshRequire("yaml");
} catch (err) {
  console.error(`ERROR: 已找到 @deepseek-ai/dsh（基准 ${DSH_NODE_MODULES}），但其依赖 yaml 无法解析：${err.code ?? err.name}: ${(err.message || "").split("\n")[0]}`);
  console.error("      该 dsh 安装可能不完整。请修复安装或改用 DSH_NODE_MODULES 指向完整安装。");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const home = process.env.DSH_HOME || "";
if (!home) {
  console.error("WARN: 未设置 DSH_HOME，bundle 模板路径检查可能不完整；请用 -DshHome 或 export DSH_HOME 指定。");
}

const defaults = [
  resolve(home, "cordis.patch.yml"),
  resolve(home, "profiles/desktop/cordis.patch.yml"),
  resolve(repo, ".agent-presets/presidio-pii/bundle/cordis.patch.yml"),
];

const files = process.argv.slice(2).length ? process.argv.slice(2) : defaults;

function collectRows(node, out = []) {
  if (Array.isArray(node)) {
    for (const item of node) collectRows(item, out);
  } else if (node && typeof node === "object") {
    if (typeof node.name === "string" && node.name.length) out.push(node);
    if (Array.isArray(node.insert)) collectRows(node.insert, out);
    if (Array.isArray(node.config)) collectRows(node.config, out);
  }
  return out;
}

function findPreset(rows, id) {
  return rows.filter((r) => r.id === id);
}

let problems = 0;
for (const file of files) {
  const label = file.replace(/\\/g, "/");
  if (!existsSync(file)) {
    console.log(`SKIP  ${label} (file missing)`);
    continue;
  }
  let doc;
  try {
    doc = YAML.parse(readFileSync(file, "utf8"));
  } catch (err) {
    console.log(`ERROR ${label}: YAML parse failed: ${err.message}`);
    problems++;
    continue;
  }
  const rows = collectRows(doc);
  const presets = findPreset(rows, "preset-presidio-pii");
  if (presets.length === 0) {
    console.log(`INFO  ${label}: no preset-presidio-pii declaration`);
    continue;
  }
  if (presets.length > 1) {
    console.log(`FAIL  ${label}: ${presets.length} duplicate preset-presidio-pii declarations`);
    problems++;
  }
  for (const preset of presets) {
    const plugins = Array.isArray(preset.config?.plugins) ? preset.config.plugins : [];
    console.log(`CHECK ${label}: ${plugins.length} plugins`);
    for (const p of collectRows(plugins)) {
      const name = p.name;
      // cordis:group / file:/// 不走 node require 解析
      if (name === "cordis:group" || name.startsWith("file:")) continue;
      try {
        dshRequire.resolve(name);
      } catch (err) {
        console.log(`FAIL  ${label}: plugin id=${p.id ?? "-"} name=${name} => ${err.code ?? err.name}: ${(err.message || "").split("\n")[0]}`);
        problems++;
      }
    }
    // 旧键检测（不必然致命，但说明清单漂移）
    for (const p of collectRows(plugins)) {
      if (p.config && typeof p.config === "object" && Object.hasOwn(p.config, "modelSelectionSettings")) {
        console.log(`WARN  ${label}: plugin id=${p.id} uses legacy key modelSelectionSettings (0.2.2-rc.1 uses modelSelection/modelDiscovery)`);
      }
    }
  }
}

console.log(problems === 0 ? "RESULT: PASS (all preset plugins resolvable)" : `RESULT: FAIL (${problems} problem(s))`);
process.exit(problems === 0 ? 0 : 1);
