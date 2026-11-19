# check_paths.ps1 — 路径漂移前置校验（FIX-6 配置源部分）
#
# 用途：扫描仓库源码/配置里是否残留作者机器绝对路径 `E:[/\\]Code`。
#       命中则逐条列出 文件:行号 并 exit 1；无命中打印 PASS 并 exit 0。
#
# 扫描范围：
#   扩展名 *.js *.mjs *.py *.ps1 *.yml *.yaml *.json *.md
#   排除目录 .git/ node_modules/ .bak-*/ .review_tmp/ .pii_presidio_store/ dist/
#   排除 *.md —— 历史文档（README/docs）允许保留作者路径值，不作为漂移源
#   白名单豁免 tools/verify_preset_plugins.mjs —— 该文件由上游验收点名「不动」，
#     其 :37 的旧作者路径是校验基准常量而非可安装配置源，故单文件豁免。
#   注意：.agent-presets 是隐藏目录，-Force 必须开启才能扫到（之前 grep 漏扫的坑）。
#
# 用法：powershell -ExecutionPolicy Bypass -File <repo>\tools\check_paths.ps1 [-Repo <仓库根>]

param([string]$Repo)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Repo)) { $Repo = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path $Repo)) { Write-Host "[check_paths][FAIL] 仓库根不存在: $Repo"; exit 1 }
$Repo = (Resolve-Path $Repo).Path

$exts = @('.js', '.mjs', '.py', '.ps1', '.yml', '.yaml', '.json')
$excludedDirs = @('.git', 'node_modules', '.review_tmp', '.pii_presidio_store', 'dist')
$whitelist = @('tools/verify_preset_plugins.mjs')
# install.ps1 渲染产物（含本机真实路径）是生成物，不是可安装配置源，豁免。
$skipSuffix = '.installed'
$pattern = 'E:[/\\]Code'

$hits = [System.Collections.Generic.List[string]]::new()
$files = Get-ChildItem -LiteralPath $Repo -Recurse -Force -File | Where-Object {
    $exts -contains $_.Extension.ToLowerInvariant()
}

foreach ($f in $files) {
    $rel = $f.FullName.Substring($Repo.Length).TrimStart('\', '/').Replace('\', '/')
    # 排除目录段（含 .bak-* 前缀通配）
    $segs = $rel -split '/'
    if ($segs | Where-Object { $excludedDirs -contains $_ -or $_ -like '.bak-*' }) { continue }
    # 白名单豁免（正斜杠相对路径归一化后比对）
    if ($whitelist -contains $rel) { continue }
    # 安装渲染产物豁免（*.installed 由 install.ps1 生成，含本机真实路径）
    if ($rel.EndsWith($skipSuffix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }

    $lineNo = 0
    foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {
        $lineNo++
        if ($line -match $pattern) {
            $hits.Add("${rel}:${lineNo}: $($line.Trim())")
        }
    }
}

if ($hits.Count -gt 0) {
    Write-Host "[check_paths][FAIL] 发现 $($hits.Count) 处 E:[/\\]Code 硬编码路径：" -ForegroundColor Red
    $hits | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host '[check_paths][PASS] 源码/配置中未发现 E:[/\\]Code 硬编码路径（已排除 .md 文档与白名单文件）。' -ForegroundColor Green
exit 0
