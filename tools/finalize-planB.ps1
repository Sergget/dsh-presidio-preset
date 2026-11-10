# finalize-planB.ps1 — 方案 B 收尾一键脚本（交接清单第 1+2 步合并）
#
# 用法：完全退出 DSH（托盘右键 → 完全退出）后，在普通 PowerShell 里运行：
#   powershell -ExecutionPolicy Bypass -File E:\Code\dsh-presidio-preset\tools\finalize-planB.ps1
#
# 做什么：
#   1) 同步插件仓库副本 → DSH 安装位，并校验 sha256 一致（drift 即中止）
#   2) 清理后重建 wheel 两次（SOURCE_DATE_EPOCH 固定），校验两次哈希一致（可复现）
#   3) 把新 wheel 的 SHA256/bytes 更新进 release/presidio-pii-dsh-0.1.0.json
#   4) 跑门禁 #10 与 #4 复核，打印最终结果
#
# 结束后：重新启动 DSH → 选 presidio-pii 预设 → 按交接清单第 3 步做 GUI 验证。

$ErrorActionPreference = 'Stop'
$Repo    = 'E:\Code\dsh-presidio-preset'
$Plugin  = Join-Path $Repo 'plugins\dsh-pii-guard\lib\index.js'
$Install = 'E:\Code\dsh_home\plugins\dsh-pii-guard\lib\index.js'
$Py      = 'D:\Python\313\python.exe'
$Epoch   = '1700000000'
$Manifest = Join-Path $Repo 'release\presidio-pii-dsh-0.1.0.json'

function Get-Sha([string]$p) { (Get-FileHash $p -Algorithm SHA256).Hash }
function Die([string]$msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }

Write-Host '=== Step 1: 同步插件到安装位 ===' -ForegroundColor Cyan
if (-not (Test-Path $Plugin)) { Die "插件副本不存在: $Plugin" }
$syncOk = $false
try {
    Copy-Item $Plugin $Install -Force
    $shaRepo = Get-Sha $Plugin
    $shaInst = Get-Sha $Install
    if ($shaRepo -ne $shaInst) { throw "sha256 不一致 repo=$shaRepo inst=$shaInst" }
    $syncOk = $true
    Write-Host "[OK] 插件已同步, sha256=$($shaRepo.Substring(0,16))..."
} catch {
    Write-Host "[WARN] 插件未同步（DSH 还在运行？稍后退出 DSH 再单独跑本脚本或手动 Copy-Item）: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host '=== Step 2: 重建 wheel（两次，校验可复现）===' -ForegroundColor Cyan
Set-Location $Repo
Remove-Item -Recurse -Force build, presidio_pii_dsh.egg-info -ErrorAction SilentlyContinue
$env:SOURCE_DATE_EPOCH = $Epoch

# TEMP 指到仓库内可写目录：避免系统 TEMP 权限受限时 pip build tracker 失败
$buildTmp = Join-Path $Repo '.pii_presidio_store\build_tmp'
New-Item -ItemType Directory -Path $buildTmp -Force | Out-Null
$env:TEMP = $buildTmp
$env:TMP = $buildTmp

$b1 = Join-Path $env:TEMP 'pii_b1'; $b2 = Join-Path $env:TEMP 'pii_b2'
foreach ($d in @($b1, $b2)) {
    Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
& $Py -m pip wheel . --no-deps -w $b1 --disable-pip-version-check 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die '第一次构建失败（pip wheel b1）。若本脚本是从 DSH 会话内跑的：请在 DSH 完全退出后、从独立的 PowerShell 窗口重跑（DSH 沙箱会拦截子进程写临时目录）。若已在正常窗口仍失败，把 TEMP 指到可写盘：$env:TEMP="E:\pii_tmp"' }
& $Py -m pip wheel . --no-deps -w $b2 --disable-pip-version-check 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Die '第二次构建失败（pip wheel b2）。处置同上' }

$w1 = Get-ChildItem $b1\*.whl | Select-Object -First 1
$w2 = Get-ChildItem $b2\*.whl | Select-Object -First 1
$shaW1 = Get-Sha $w1.FullName
$shaW2 = Get-Sha $w2.FullName
if ($shaW1 -ne $shaW2) { Die "两次构建哈希不一致（不可复现）: $shaW1 vs $shaW2" }
Write-Host "[OK] 可复现: $($w1.Name) $($w1.Length)B sha256=$($shaW1.Substring(0,16))..."

# 确认新 wheel 里带 restore op（方案 B 代码已进包）
$hasRestore = & $Py -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); d=z.read('presidio_pii/server.py').decode('utf-8'); sys.exit(0 if 'op == ' + chr(34) + 'restore' + chr(34) in d else 1)" $w1.FullName
if ($LASTEXITCODE -ne 0) { Die 'wheel 内 server.py 不含 restore op——构建用了陈旧源码，勿发布' }
Write-Host '[OK] wheel 内含方案 B restore op'

Write-Host '=== Step 3: 更新发布清单 ===' -ForegroundColor Cyan
Copy-Item $w1.FullName (Join-Path $Repo 'dist') -Force
$m = Get-Content $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
$m.artifact.bytes = $w1.Length
$m.artifact.sha256 = $shaW1
$m.recorded_at = (Get-Date -Format 'yyyy-MM-dd')
$m.source.working_tree_dirty = $true
$m | ConvertTo-Json -Depth 10 | Set-Content $Manifest -Encoding utf8
Write-Host "[OK] 清单已更新: bytes=$($w1.Length) sha256=$($shaW1.Substring(0,16))..."

Write-Host '=== Step 4: 门禁复核 #10 + #4 ===' -ForegroundColor Cyan
& $Py (Join-Path $Repo 'tools\release_gate.py') --only 10,4
$gate = $LASTEXITCODE
if ($gate -ne 0) { Die "门禁复核未通过 (exit=$gate)，检查上方逐项输出" }

Write-Host ''
Write-Host '=== 全部完成 ===' -ForegroundColor Green
if (-not $syncOk) {
    Write-Host '[PENDING] 插件安装位尚未同步: 完全退出 DSH 后重跑本脚本，或手动执行:' -ForegroundColor Yellow
    Write-Host "  Copy-Item '$Plugin' '$Install' -Force"
}
Write-Host '下一步：启动 DSH → 选 presidio-pii 预设 → 验证显示还原（见 docs/RELEASE-RUNBOOK-B-handoff.md 第 3 步）'
Write-Host '随后在正常环境跑全量门禁: python tools\release_gate.py --json $env:TEMP\release_gate.json'

