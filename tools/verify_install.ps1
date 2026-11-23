<#
.SYNOPSIS
  DSH Presidio PII 统一单插件安装后自检（verify_install）。

.DESCRIPTION
  一条命令输出 5 项 PASS/FAIL/SKIP 及失败原因：
    1. Node 引擎语法：node --check plugins/dsh-presidio-pii/node_pii/server.mjs
    2. 统一插件集成测试：node tests/js/plugin_unified.mjs
    3. bundle enabled：检查 $DshHome/profiles/*/package.json 中是否已安装 dsh-presidio-pii
    4. 冲突与残留检查：确认 $DshHome/cordis.patch.yml 无内联 preset-presidio-pii 冲突，且无散装副本
    5. preset 插件校验：node tools/verify_preset_plugins.mjs
#>
[CmdletBinding()]
param(
  [string]$Repo = (Split-Path -Parent $PSScriptRoot),
  [string]$DshHome = $env:DSH_HOME
)

$ErrorActionPreference = "Continue"
$results = @()

function Add-Result {
  param(
    [string]$Name,
    [ValidateSet("PASS", "FAIL", "SKIP")][string]$Status,
    [string]$Detail
  )
  $script:results += [pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }
}

Write-Output "============================================================"
Write-Output " DSH Presidio PII 统一插件自检 (verify_install)"
Write-Output "============================================================"
Write-Output " Repo    : $Repo"
Write-Output " DshHome : $DshHome"
Write-Output ""

Push-Location $Repo
try {
  # ── 1. Node 引擎语法 ────────────────────────────────────────────────────
  try {
    $checkOut = & node --check plugins/dsh-presidio-pii/node_pii/server.mjs 2>&1
    if ($LASTEXITCODE -eq 0) {
      Add-Result -Name "Node 引擎语法" -Status PASS -Detail "node --check plugins/dsh-presidio-pii/node_pii/server.mjs exit 0"
    } else {
      Add-Result -Name "Node 引擎语法" -Status FAIL -Detail "exit=$LASTEXITCODE; 输出: $checkOut"
    }
  } catch {
    Add-Result -Name "Node 引擎语法" -Status FAIL -Detail "异常: $($_.Exception.Message)"
  }

  # ── 2. 统一插件测试 ──────────────────────────────────────────────────────
  try {
    $uniOut = & node tests/js/plugin_unified.mjs 2>&1
    if ($LASTEXITCODE -eq 0) {
      Add-Result -Name "统一插件集成测试" -Status PASS -Detail "tests/js/plugin_unified.mjs PASS"
    } else {
      Add-Result -Name "统一插件集成测试" -Status FAIL -Detail "exit=$LASTEXITCODE; 输出: $(($uniOut | Select-Object -Last 4) -join ' | ')"
    }
  } catch {
    Add-Result -Name "统一插件集成测试" -Status FAIL -Detail "异常: $($_.Exception.Message)"
  }

  # ── 3. DSH profile 安装检查 ──────────────────────────────────────────────
  if (-not $DshHome) {
    Add-Result -Name "bundle 安装状态" -Status SKIP -Detail "DSH_HOME 未设置，跳过 profile 安装检查"
  } else {
    $profilesDir = Join-Path $DshHome "profiles"
    $matched = @()
    if (Test-Path $profilesDir) {
      Get-ChildItem -Path $profilesDir -Directory | ForEach-Object {
        $pkgPath = Join-Path $_.FullName "package.json"
        if (Test-Path $pkgPath) {
          $pkgRaw = Get-Content $pkgPath -Raw -Encoding UTF8
          if ($pkgRaw -match '"dsh-presidio-pii"') {
            $matched += $_.Name
          }
        }
      }
    }
    if ($matched.Count -gt 0) {
      Add-Result -Name "bundle 安装状态" -Status PASS -Detail "已在 profile ($($matched -join ', ')) 安装 dsh-presidio-pii"
    } else {
      Add-Result -Name "bundle 安装状态" -Status FAIL -Detail "未在 $profilesDir/*/package.json 检测到 dsh-presidio-pii"
    }
  }

  # ── 4. 冲突与遗留散装插件检查 ───────────────────────────────────────────
  if (-not $DshHome) {
    Add-Result -Name "冲突与散装残留" -Status SKIP -Detail "DSH_HOME 未设置，跳过"
  } else {
    $issues = @()
    $homePatch = Join-Path $DshHome "cordis.patch.yml"
    if (Test-Path $homePatch) {
      $raw = Get-Content $homePatch -Raw -Encoding UTF8
      if ($raw -match 'id:\s*preset-presidio-pii\b') {
        $issues += "$homePatch 仍残留内联 preset-presidio-pii"
      }
    }
    foreach ($legacy in @('plugins/dsh-pii-guard', 'plugins/dsh-pii-guard-fs',
                          'plugins/dsh-pii-guard-terms')) {
      $lp = Join-Path $DshHome $legacy
      if (Test-Path $lp) { $issues += "仍存在遗留散装目录: $lp" }
    }
    # 统一包之前可能残留在 profile 依赖里的旧 bundle 名
    $profRoot = Join-Path $DshHome 'profiles'
    if (Test-Path $profRoot) {
      foreach ($prof in Get-ChildItem -Path $profRoot -Directory -ErrorAction SilentlyContinue) {
        $pj = Join-Path $prof.FullName 'package.json'
        if (-not (Test-Path $pj)) { continue }
        if ((Get-Content $pj -Raw -Encoding UTF8) -match 'dsh-pii-guard') {
          $issues += "$pj 仍引用旧 bundle 名 dsh-pii-guard*"
        }
      }
    }
    if ($issues.Count -eq 0) {
      Add-Result -Name "冲突与散装残留" -Status PASS -Detail "无内联重复 preset，无遗留散装目录"
    } else {
      Add-Result -Name "冲突与散装残留" -Status FAIL -Detail ($issues -join '; ')
    }
  }

  # ── 5. preset 插件可解析校验 ────────────────────────────────────────────
  try {
    $vpOut = $null
    $dshExe = $null
    if ($env:DSH_INSTALL_DIR -and $env:DSH_INSTALL_DIR -match '^(.*?)[\\/]+resources[\\/]+app\.asar') {
      $candExe = Join-Path $Matches[1] 'DeepSeek Harness.exe'
      if (Test-Path $candExe) { $dshExe = $candExe }
    }
    if ($dshExe) {
      $prevElectron = $env:ELECTRON_RUN_AS_NODE
      $env:ELECTRON_RUN_AS_NODE = '1'
      try {
        $vpOut = & $dshExe tools/verify_preset_plugins.mjs 2>&1
      } finally {
        if ($null -eq $prevElectron) { Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue }
        else { $env:ELECTRON_RUN_AS_NODE = $prevElectron }
      }
    } else {
      $vpOut = & node tools/verify_preset_plugins.mjs 2>&1
    }
    if ($LASTEXITCODE -eq 0) {
      Add-Result -Name "preset 插件校验" -Status PASS -Detail "verify_preset_plugins.mjs exit 0"
    } else {
      Add-Result -Name "preset 插件校验" -Status FAIL -Detail "exit=$LASTEXITCODE; 输出: $(($vpOut | Select-Object -Last 4) -join ' | ')"
    }
  } catch {
    Add-Result -Name "preset 插件校验" -Status FAIL -Detail "异常: $($_.Exception.Message)"
  }
} finally {
  Pop-Location
}

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
if ($failCount -gt 0) { exit 1 }
exit 0
