# install.ps1 — dsh-presidio-pii 统一单插件安装/校验辅助脚本
#
# 用法：
#   pwsh -NoProfile -File tools/install.ps1 [-Repo <仓库根>] [-DshHome <DSH_HOME 目录>] [-DryRun]
#
# 说明：
#   所有能力已合并为单一自包含 DSH Bundle：`plugins/dsh-presidio-pii/`。
#   不再需要替换 __REPO__/__DSH_HOME__ 占位符，也不再向 $DSH_HOME/plugins/ 手动复制散装文件。
#   本脚本负责：
#     1. 校验 Node ≥22.5 与统一插件包完整性（node_pii/、assets/、rule_libraries/、defaults/、skills/）。
#     2. 检测并提示（可选清理）$DSH_HOME 中遗留的散装目录（plugins/dsh-pii-guard*）或重复内联 preset-presidio-pii。
#     3. 输出（或引导）通过 DSH 官方 bundle 机制（plugin_manager install_bundle）安装该单插件。
#
# 本脚本不含任何硬编码绝对路径。

param(
    [string]$Repo,
    [string]$DshHome = $env:DSH_HOME,
    [switch]$DryRun,
    [switch]$CleanLegacy
)

$ErrorActionPreference = 'Stop'

function Normalize-Path([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    return ($p -replace '\\', '/').TrimEnd('/')
}

function Log([string]$msg) { Write-Host "[install] $msg" }
function Warn([string]$msg) { Write-Host "[install][WARN] $msg" -ForegroundColor Yellow }
function Fail([string]$msg) { Write-Host "[install][FAIL] $msg" -ForegroundColor Red; exit 1 }

# --- 1. 解析并规范化参数 ---------------------------------------------------
if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path $Repo)) { Fail "仓库根不存在: $Repo" }
$Repo = Normalize-Path (Resolve-Path $Repo).Path

if ([string]::IsNullOrWhiteSpace($DshHome)) {
    Fail '未提供 -DshHome 且 $env:DSH_HOME 为空。请显式指定 DSH 主目录。'
}
if (-not (Test-Path $DshHome)) { Fail "DSH_HOME 目录不存在: $DshHome" }
$DshHome = Normalize-Path (Resolve-Path $DshHome).Path

$BundleDir = Normalize-Path (Join-Path $Repo 'plugins/dsh-presidio-pii')
Log "Repo      = $Repo"
Log "BundleDir = $BundleDir"
Log "DshHome   = $DshHome"
Log "DryRun    = $($DryRun.IsPresent)"

# --- 2. Node 运行时与统一包完整性校验 ---------------------------------------
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) { Fail 'PATH 中未找到 node（需要 Node ≥22.5）。' }
$verText = "$( & node --version 2>&1 )"
$verMatch = [regex]::Match($verText, 'v?(\d+)\.(\d+)')
if (-not $verMatch.Success) { Fail "无法解析 Node 版本: '$verText'。" }
$nodeMajor = [int]$verMatch.Groups[1].Value
$nodeMinor = [int]$verMatch.Groups[2].Value
if ($nodeMajor -lt 22 -or ($nodeMajor -eq 22 -and $nodeMinor -lt 5)) {
    Fail "Node 版本 $nodeMajor.$nodeMinor 过低（需 ≥22.5 以使用 node:sqlite）。"
}
Log "Node 版本 $nodeMajor.$nodeMinor —— PASS"

$required = @(
    'package.json',
    'cordis.patch.yml',
    'client.js',
    'lib/paths.mjs',
    'lib/terms.js',
    'lib/guard.js',
    'lib/fs.mjs',
    'node_pii/server.mjs',
    'node_pii/hooks.mjs',
    'defaults/preset.json',
    'rule_libraries/extended-fields.json',
    'assets/surnames.txt',
    'skills/presidio-pii/SKILL.md'
)
foreach ($rel in $required) {
    $full = Join-Path $BundleDir $rel
    if (-not (Test-Path $full)) { Fail "统一插件包缺少必需文件: $full" }
}
Log "统一插件包 dsh-presidio-pii 完整性校验 —— PASS"

# --- 3. 遗留散装插件与内联配置排查 -----------------------------------------
$legacyDirs = @(
    (Join-Path $DshHome 'plugins/dsh-pii-guard'),
    (Join-Path $DshHome 'plugins/dsh-pii-guard-fs'),
    (Join-Path $DshHome 'plugins/dsh-pii-guard-terms')
)
foreach ($legacy in $legacyDirs) {
    if (Test-Path $legacy) {
        if ($CleanLegacy.IsPresent) {
            if ($DryRun.IsPresent) {
                Log "[DRY] 将删除遗留散装目录: $legacy"
            } else {
                Remove-Item -Path $legacy -Recurse -Force
                Log "已清理遗留散装目录: $legacy"
            }
        } else {
            Warn "发现遗留散装目录: $legacy（统一包不再需要它，可加 -CleanLegacy 清理）"
        }
    }
}

$homePatch = Join-Path $DshHome 'cordis.patch.yml'
if (Test-Path $homePatch) {
    $patchRaw = Get-Content $homePatch -Raw -Encoding UTF8
    if ($patchRaw -match 'id:\s*preset-presidio-pii\b') {
        Warn "$homePatch 中存在内联 preset-presidio-pii 声明；安装 dsh-presidio-pii bundle 前请先移除该内联块，以免触发 Duplicate agent preset。"
    }
}

# --- 3b. 旧版 bundle（dsh-pii-guard-terms）残留排查 ---------------------------
# 统一包之前的 web/desktop profile 可能还挂着 link 到旧目录的 dependency。
$profilesRoot = Join-Path $DshHome 'profiles'
if (Test-Path $profilesRoot) {
    foreach ($prof in Get-ChildItem -Path $profilesRoot -Directory -ErrorAction SilentlyContinue) {
        $pkgJson = Join-Path $prof.FullName 'package.json'
        if (-not (Test-Path $pkgJson)) { continue }
        $raw = Get-Content $pkgJson -Raw -Encoding UTF8
        if ($raw -match 'dsh-pii-guard') {
            Warn "$pkgJson 仍引用旧 bundle 名 dsh-pii-guard*；请在 DSH 中禁用它，或从 dependencies/bundles 移除。"
        }
    }
}

# --- 4. 安装指引 -----------------------------------------------------------
Log "统一插件包就绪：$BundleDir"
Log "在 DSH 会话中使用 plugin_manager 安装："
Log "  plugin_manager({ action: 'install_bundle', target: '$BundleDir' })"
Log "或对非 desktop profile 使用 CLI："
Log "  dsh plugin --profile web add $BundleDir"
