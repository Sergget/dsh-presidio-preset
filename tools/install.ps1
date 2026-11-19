# install.ps1 — presidio-pii 预设参数化安装脚本（FIX-1 / FIX-6 配置源部分）
#
# 用法（在仓库根或任意目录）：
#   powershell -ExecutionPolicy Bypass -File <repo>\tools\install.ps1 `
#       -Repo <仓库根> -DshHome <DSH_HOME 目录> [-DryRun]
#
# 参数默认值：
#   -Repo     默认本脚本所在仓库根（tools 的父目录）
#   -DshHome  默认 $env:DSH_HOME；为空则报错退出（不会猜作者路径）
#   -DryRun   可选开关：只打印每一步将要做什么与替换预览，不写任何文件
#
# 自洽方案（为什么不改模板本身）：
#   bundle/cordis.patch.yml 是【可安装模板】，内含 __REPO__/__DSH_HOME__ 占位符，
#   必须保持原样以支持「同一模板重复安装到不同机器」。本脚本只读取模板，把占位符
#   替换为真实路径后生成【同目录】的 cordis.patch.yml.installed（生成物，不入模板）。
#   plugin_manager install_bundle 安装 bundle 时配置源仍指向 ./cordis.patch.yml
#   （模板）；如需按本机路径生效，去掉 -DryRun 生成 installed 后手动核对，
#   或由上层安装流程把 installed 内容作为该机 patch 源。模板自身永不被覆盖。
#
# 版本校验（FIX-9）：仅接受 Python 3.9~3.13，超出或无法解析即报错退出。
#
# 本脚本不含任何硬编码绝对路径。

param(
    [string]$Repo,
    [string]$DshHome = $env:DSH_HOME,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Normalize-Path([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return '' }
    return ($p -replace '\\', '/').TrimEnd('/')
}

function Log([string]$msg) { Write-Host "[install] $msg" }
function Fail([string]$msg) { Write-Host "[install][FAIL] $msg" -ForegroundColor Red; exit 1 }

# --- 1. 解析并规范化参数 ---------------------------------------------------
if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path $Repo)) { Fail "仓库根不存在: $Repo" }
$Repo = Normalize-Path (Resolve-Path $Repo).Path

if ([string]::IsNullOrWhiteSpace($DshHome)) {
    Fail '未提供 -DshHome 且 $env:DSH_HOME 为空。请显式指定 DSH 主目录（脚本不会猜测作者路径）。'
}
if (-not (Test-Path $DshHome)) { Fail "DSH_HOME 目录不存在: $DshHome" }
$DshHome = Normalize-Path (Resolve-Path $DshHome).Path

Log "Repo    = $Repo"
Log "DshHome = $DshHome"
Log "DryRun  = $($DryRun.IsPresent)"

# --- 1b. Python 版本校验（FIX-9）------------------------------------------
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCmd) { Fail 'PATH 中未找到 python。请安装 Python 3.9~3.13 并确保 python 在 PATH 中。' }
$verText = "$( & python --version 2>&1 )"
$verMatch = [regex]::Match($verText, '(\d+)\.(\d+)')
if (-not $verMatch.Success) { Fail "无法解析 Python 版本: '$verText'。请使用官方 CPython 3.9~3.13。" }
$pyMajor = [int]$verMatch.Groups[1].Value
$pyMinor = [int]$verMatch.Groups[2].Value
if (-not ($pyMajor -eq 3 -and $pyMinor -ge 9 -and $pyMinor -le 13)) {
    Fail "Python 版本 $pyMajor.$pyMinor 不在支持范围（3.9~3.13）。请切换受支持版本后重试。"
}
Log "Python 版本 $pyMajor.$pyMinor —— PASS（支持范围 3.9~3.13）"

# --- 2. 读模板，替换占位符，生成 installed patch ---------------------------
$template = Join-Path $Repo '.agent-presets/presidio-pii/bundle/cordis.patch.yml'
$installed = Join-Path $Repo '.agent-presets/presidio-pii/bundle/cordis.patch.yml.installed'
if (-not (Test-Path $template)) { Fail "找不到 patch 模板: $template" }

$content = Get-Content $template -Raw -Encoding UTF8
$rendered = $content.Replace('__REPO__', $Repo).Replace('__DSH_HOME__', $DshHome)

if ($DryRun.IsPresent) {
    Log "[DRY] 将生成: $installed"
    Log '[DRY] 关键替换预览（含实际路径的行）:'
    ($rendered -split "`n") | Where-Object { $_ -match [regex]::Escape($Repo) -or $_ -match [regex]::Escape($DshHome) } |
        ForEach-Object { Write-Host "        $($_.TrimEnd())" }
    Log '[DRY] 未写入任何文件。'
} else {
    Set-Content -Path $installed -Value $rendered -Encoding UTF8 -NoNewline
    Log "已生成: $installed"
    if ($rendered -match '__REPO__|__DSH_HOME__') { Fail '渲染后仍残留占位符，请检查模板。' }
}

# --- 3. 复制 guard 插件到 DSH_HOME 安装位 ---------------------------------
$src = Join-Path $Repo 'plugins/dsh-pii-guard/lib/index.js'
$dst = Join-Path $DshHome 'plugins/dsh-pii-guard/lib/index.js'
if (-not (Test-Path $src)) { Fail "找不到 guard 插件源码: $src" }
if ($DryRun.IsPresent) {
    Log "[DRY] 将复制: $src -> $dst （New-Item 建目录，-Force 覆盖）"
} else {
    $dstDir = Split-Path -Parent $dst
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    Copy-Item -Path $src -Destination $dst -Force
    Log "已安装 guard 插件: $dst"
}

# --- 4. 收尾提示 ------------------------------------------------------------
Log '完成。接下来请用 plugin_manager install_bundle 安装 preset bundle 与 UI bundle，然后重启 DSH 使配置生效。'
if ($DryRun.IsPresent) {
    Log '[DRY] 本次为演练，未落盘；去掉 -DryRun 重跑即可实际安装。'
}
