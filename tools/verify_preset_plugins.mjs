// 验证 dsh-presidio-pii preset 声明里的每条子插件在当前 DSH 版本可解析，且无重复 id。
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DSH_PKG_REL = "@deepseek-ai/dsh/package.json";

function norm(p) {
  return String(p).replace(/\\/g, "/");
}

function hasDsh(nodeModulesDir) {
  return existsSync(resolve(nodeModulesDir, DSH_PKG_REL));
}

function npmGlobalRoot() {
  try {
    return execSync("npm root -g", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");

function buildFallbackCandidates() {
  const candidates = [];
  const note = (source, dir) => candidates.push({ source, dir: norm(dir) });
  const home = process.env.DSH_HOME;
  const inst = process.env.DSH_INSTALL_DIR;

  // 1. 本仓库/项目环境中的 node_modules 查找
  note("repo node_modules", resolve(repo, "node_modules"));

  if (home) note("$DSH_HOME/node_modules", resolve(home, "node_modules"));

  if (inst) {
    note("$DSH_INSTALL_DIR/..", resolve(inst, "../.."));
    note("$DSH_INSTALL_DIR/resources/app.asar/dsh/node_modules",
      resolve(inst, "resources/app.asar/dsh/node_modules"));
    note("$DSH_INSTALL_DIR/resources/app.asar.unpacked/dsh/node_modules",
      resolve(inst, "resources/app.asar.unpacked/dsh/node_modules"));
  }

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
      // ignore
    }
  }

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
    console.error("  - （无任何候选：请设置 DSH_HOME 或 DSH_INSTALL_DIR）");
  }
  process.exit(2);
}

const explicit = process.env.DSH_NODE_MODULES;
let DSH_NODE_MODULES = null;

if (explicit) {
  const dir = norm(explicit);
  if (hasDsh(dir)) {
    DSH_NODE_MODULES = dir;
  } else {
    printGuidanceAndExit(
      [{ source: "env DSH_NODE_MODULES（显式指定）", dir }].concat(buildFallbackCandidates()),
      `ERROR: 显式指定的 DSH_NODE_MODULES 不含 ${DSH_PKG_REL}：${dir}`
    );
  }
} else {
  const tried = [];
  for (const cand of buildFallbackCandidates()) {
    tried.push(cand);
    if (hasDsh(cand.dir)) {
      DSH_NODE_MODULES = cand.dir;
      break;
    }
  }
  if (!DSH_NODE_MODULES) {
    printGuidanceAndExit(tried, "ERROR: 无法定位 @deepseek-ai/dsh —— 已尝试以下候选：");
  }
}

const dshRequire = createRequire(resolve(DSH_NODE_MODULES, DSH_PKG_REL));

let jsYaml;
try {
  jsYaml = dshRequire("js-yaml");
} catch (err) {
  console.error(`ERROR: 无法加载 js-yaml：${err.message}`);
  process.exit(2);
}

const JsExprType = new jsYaml.Type("tag:yaml.org,2002:js", {
  kind: "scalar",
  resolve: (data) => typeof data === "string",
  construct: (data) => ({ __jsExpr: data }),
});
const PATCH_SCHEMA = jsYaml.DEFAULT_SCHEMA.extend([JsExprType]);

const bundleDir = resolve(repo, "plugins/dsh-presidio-pii");
const home = process.env.DSH_HOME || "";

// profile 名不写死：枚举 $DSH_HOME/profiles/* 下所有带 cordis.patch.yml 的目录，
// 并遵守 DSH_PROFILE 显式指定（若该 profile 存在则只校验它）。
function profilePatchFiles(homeDir) {
  const explicitProfile = (process.env.DSH_PROFILE || "").trim();
  const profilesDir = resolve(homeDir, "profiles");
  if (!existsSync(profilesDir)) return [];
  let entries;
  try {
    entries = readdirSync(profilesDir, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isDirectory())
    .filter((e) => !explicitProfile || e.name === explicitProfile)
    .map((e) => resolve(profilesDir, e.name, "cordis.patch.yml"))
    .filter((f) => existsSync(f));
}

const defaults = [
  resolve(bundleDir, "cordis.patch.yml"),
  ...(home ? [resolve(home, "cordis.patch.yml"), ...profilePatchFiles(home)] : []),
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

const bundleRequire = createRequire(resolve(bundleDir, "package.json"));

let problems = 0;
for (const file of files) {
  const label = norm(file);
  if (!existsSync(file)) {
    console.log(`SKIP  ${label} (file missing)`);
    continue;
  }
  let doc;
  try {
    doc = jsYaml.load(readFileSync(file, "utf8"), { schema: PATCH_SCHEMA });
  } catch (err) {
    console.log(`ERROR ${label}: YAML parse failed: ${err.message}`);
    problems++;
    continue;
  }
  const topRows = collectRows(doc);
  const presets = findPreset(topRows, "preset-presidio-pii");
  if (presets.length > 1) {
    console.log(`FAIL  ${label}: ${presets.length} duplicate preset-presidio-pii rows`);
    problems++;
  }
  for (const p of presets) {
    const plugins = p.config?.plugins ?? [];
    const subRows = collectRows(plugins);
    let broken = 0;
    for (const row of subRows) {
      if (row.name.startsWith("cordis:") || row.name.startsWith("file://")) continue;
      try {
        if (row.name === "dsh-presidio-pii" || row.name.startsWith("dsh-presidio-pii/")) {
          bundleRequire.resolve(row.name);
        } else {
          dshRequire.resolve(row.name);
        }
      } catch (err) {
        broken++;
        problems++;
        console.log(`FAIL  ${label} [${row.id}]: ${row.name} -> ${err.code ?? err.message}`);
      }
    }
    if (broken === 0) {
      console.log(`OK    ${label}: preset-presidio-pii (${subRows.length} plugin rows all resolve)`);
    }
  }
  if (presets.length === 0) {
    console.log(`OK    ${label}: no preset-presidio-pii override`);
  }
}

process.exit(problems ? 1 : 0);
