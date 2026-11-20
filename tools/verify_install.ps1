<#
.SYNOPSIS
  DSH Presidio PII 安装后一键自检（FIX-4）。

.DESCRIPTION
  一条命令输出 5 项 PASS/FAIL/SKIP 及失败原因：
    1. Node 引擎语法：node --check node_pii/server.mjs（去 Python 化后引擎为 Node 原生）
    2. Node 引擎协议 smoke：node tests/node/protocol-smoke.mjs（redact→restore full/mask 全链路）
    3. bundle enabled：优先 plugin_manager CLI；当前 shell 无该命令则 SKIP + 明确指引
       （bundle patch 通过 link 注入，不写进 profile patch 文件，grep 会误判"没生效"）
    4. guard 插件加载：<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js 存在且与仓库版 sha256 一致
    5. 路径一致性：调用 tools/check_paths.ps1；文件不存在则 SKIP + 提示

  退出码：0=无 FAIL（可能含 SKIP）；1=存在 FAIL。

.PARAMETER Repo
  仓库根目录，默认是当前工作目录。

.PARAMETER DshHome
  DSH 主目录，默认取 $env:DSH_HOME。

.EXAMPLE
  pwsh -NoProfile -File tools/verify_install.ps1 -Repo <仓库根> -DshHome <DSH_HOME>
#>
[CmdletBinding()]
param(
  [string]$Repo = (Get-Location).Path,
  [string]$DshHome = $env:DSH_HOME
)

$ErrorActionPreference = "Continue"

# ── 结果收集 ─────────────────────────────────────────────────────────────
$results = @()

function Add-Result {
  param(
    [string]$Name,
    [ValidateSet("PASS", "FAIL", "SKIP")][string]$Status,
    [string]$Detail
  )
  $script:results += [pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }
}

# ── 头部 ─────────────────────────────────────────────────────────────────
Write-Output "============================================================"
Write-Output " DSH Presidio PII 安装后一键自检 (verify_install)"
Write-Output "============================================================"
Write-Output " Repo    : $Repo"
Write-Output " DshHome : $DshHome"
Write-Output ""

# Node 引擎检查需在仓库根目录执行（node_pii 是仓库内模块，server.mjs 依赖相对路径词表）
Push-Location $Repo
try {
  # ── 1. Node 引擎语法 ──────────────────────────────────────────────────
  try {
    $checkOut = & node --check node_pii/server.mjs 2>&1
    $checkExit = $LASTEXITCODE
    if ($checkExit -eq 0) {
      Add-Result -Name "Node 引擎语法" -Status PASS -Detail "node --check node_pii/server.mjs exit 0"
    } else {
      Add-Result -Name "Node 引擎语法" -Status FAIL -Detail "exit=$checkExit; 输出: $checkOut"
    }
  } catch {
    Add-Result -Name "Node 引擎语法" -Status FAIL -Detail "异常: $($_.Exception.Message)"
  }

  # ── 2. Node 引擎协议 smoke（redact → restore full/mask）───────────────
  try {
    $smokeOut = & node tests/node/protocol-smoke.mjs 2>&1
    $smokeExit = $LASTEXITCODE
    if ($smokeExit -eq 0) {
      Add-Result -Name "Node 引擎协议 smoke" -Status PASS -Detail "PROTOCOL_SMOKE 3/3（mask 不泄露原文）"
    } else {
      Add-Result -Name "Node 引擎协议 smoke" -Status FAIL -Detail "exit=$smokeExit; 输出: $(($smokeOut | Select-Object -Last 4) -join ' | ')"
    }
  } catch {
    Add-Result -Name "Node 引擎协议 smoke" -Status FAIL -Detail "异常: $($_.Exception.Message)"
  }
} finally {
  Pop-Location
}

# ── 3. bundle enabled ───────────────────────────────────────────────────
$pmCmd = Get-Command plugin_manager -ErrorAction SilentlyContinue
if ($pmCmd) {
  # 当前 shell 有 plugin_manager CLI —— 实际调用并过滤两个 bundle。
  try {
    $bundles = & plugin_manager list_bundles 2>&1
    $bExit = $LASTEXITCODE
    $bundlesText = "$bundles"
    $hasPreset = $bundlesText -match "dsh-presidio-pii-preset"
    $hasGuard = $bundlesText -match "dsh-pii-guard-terms"
    if ($bExit -eq 0 -and $hasPreset -and $hasGuard) {
      Add-Result -Name "bundle enabled" -Status PASS -Detail "list_bundles 命中 @local/dsh-presidio-pii-preset 与 dsh-pii-guard-terms"
    } else {
      Add-Result -Name "bundle enabled" -Status FAIL -Detail "list_bundles exit=$bExit; 命中 preset=$hasPreset / guard-terms=$hasGuard；输出: $(($bundles | Select-Object -First 3) -join ' | ')"
    }
  } catch {
    Add-Result -Name "bundle enabled" -Status FAIL -Detail "plugin_manager 调用异常: $($_.Exception.Message)"
  }
} else {
  # 无 shell CLI（plugin_manager 是 DSH 会话内工具）—— SKIP，不误报 FAIL。
  Add-Result -Name "bundle enabled" -Status SKIP -Detail "当前 shell 无 plugin_manager 命令。请在 DSH 会话内执行 plugin_manager list_bundles，过滤 @local/dsh-presidio-pii-preset 与 dsh-pii-guard-terms 确认已启用（link 注入不写 profile patch 文件，grep 会误判未生效）"
}

# ── 4. guard 插件加载 ───────────────────────────────────────────────────
if (-not $DshHome) {
  Add-Result -Name "guard 插件加载" -Status SKIP -Detail "DSH_HOME 未设置，无法定位 guard 插件；请用 -DshHome 指定或设置 `$env:DSH_HOME"
} else {
  $repoGuard = Join-Path $Repo "plugins\dsh-pii-guard\lib\index.js"
  $dshGuard = Join-Path $DshHome "plugins\dsh-pii-guard\lib\index.js"
  if (-not (Test-Path $repoGuard)) {
    Add-Result -Name "guard 插件加载" -Status FAIL -Detail "仓库版不存在: $repoGuard"
  } elseif (-not (Test-Path $dshGuard)) {
    Add-Result -Name "guard 插件加载" -Status FAIL -Detail "DSH_HOME 未安装 guard: $dshGuard；请运行 tools/install.ps1"
  } else {
    $repoHash = (Get-FileHash $repoGuard -Algorithm SHA256).Hash
    $dshHash = (Get-FileHash $dshGuard -Algorithm SHA256).Hash
    if ($repoHash -eq $dshHash) {
      Add-Result -Name "guard 插件加载" -Status PASS -Detail "已安装且 sha256 一致 ($($repoHash.Substring(0, [Math]::Min(12, $repoHash.Length)))...)"
    } else {
      Add-Result -Name "guard 插件加载" -Status FAIL -Detail "sha256 不一致：repo=$repoHash / dsh=$dshHash；请运行 tools/install.ps1 重新同步 guard 插件"
    }
  }
}

# ── 5. 路径一致性 ───────────────────────────────────────────────────────
$checkPaths = Join-Path $Repo "tools\check_paths.ps1"
if (-not (Test-Path $checkPaths)) {
  Add-Result -Name "路径一致性" -Status SKIP -Detail "tools/check_paths.ps1 不存在（另一代理可能尚未落盘），跳过；落地后本项自动启用"
} else {
  try {
    $cpOut = & pwsh -NoProfile -File $checkPaths 2>&1
    $cpExit = $LASTEXITCODE
    if ($cpExit -eq 0) {
      Add-Result -Name "路径一致性" -Status PASS -Detail "check_paths.ps1 exit 0"
    } else {
      Add-Result -Name "路径一致性" -Status FAIL -Detail "check_paths.ps1 exit=$cpExit; 输出: $(($cpOut | Select-Object -Last 3) -join ' | ')"
    }
  } catch {
    Add-Result -Name "路径一致性" -Status FAIL -Detail "check_paths.ps1 调用异常: $($_.Exception.Message)"
  }
}

# ── 汇总输出 ─────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "------------------------------------------------------------"
Write-Output " 检查结果："
Write-Output "------------------------------------------------------------"
$i = 0
foreach ($r in $results) {
  $i++
  Write-Output ("[{0}/5] {1} [{2}]" -f $i, $r.Name, $r.Status)
  if ($r.Detail) { Write-Output ("       " + $r.Detail) }
}
Write-Output "------------------------------------------------------------"

$failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
$skipCount = @($results | Where-Object { $_.Status -eq "SKIP" }).Count
$passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count

Write-Output " 汇总: PASS=$passCount  FAIL=$failCount  SKIP=$skipCount"
if ($failCount -gt 0) {
  Write-Output " 总体结论：未通过 —— 存在 $failCount 项失败，安装未完全就绪，请按上述 FAIL 项提示修复后重跑。"
  exit 1
} elseif ($skipCount -gt 0) {
  Write-Output " 总体结论：部分跳过 —— 无 FAIL；SKIP 项请在对应环境补齐确认（见各项指引）。"
  exit 0
} else {
  Write-Output " 总体结论：全部通过 —— 安装就绪。"
  exit 0
}
