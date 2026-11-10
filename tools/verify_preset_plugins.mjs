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
import { readFileSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
// 让 require.resolve 以 dsh-cli 的 node_modules 为基准（本机实现 checkout）
const DSH_CLI_NODE_MODULES = "E:/Code/dsh-cli/node_modules";
const dshRequire = createRequire(resolve(DSH_CLI_NODE_MODULES, "probe.cjs"));

const YAML = require(resolve(DSH_CLI_NODE_MODULES, "yaml"));

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const home = process.env.DSH_HOME || "E:/Code/dsh_home";

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
