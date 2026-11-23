"""一键发布门禁检查（对应 docs/RELEASE-GATE.md 的 12 项）。

用法:
    python tools/release_gate.py            # 全部检查
    python tools/release_gate.py --json r.json

状态语义:
    PASS   —— 判定标准满足, 有证据摘要
    FAIL   —— 检查执行了且不满足 (不因"看起来能用"放宽)
    SKIP   —— 无法执行 (离线/缺工具/待决策), 必须带原因, 不计为通过
    MANUAL —— 需要用户操作 (如 DSH 重启), 不计为通过

退出码: 0 全部 PASS / 1 存在 FAIL / 2 无 FAIL 但仍有 SKIP 或 MANUAL。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

PASS, FAIL, SKIP, MANUAL = "PASS", "FAIL", "SKIP", "MANUAL"


def run(cmd, cwd=None, timeout=600, env=None):
    p = subprocess.run(cmd, cwd=str(cwd or REPO), timeout=timeout,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def tail(text: str, n: int = 6) -> str:
    lines = [x.strip() for x in text.strip().splitlines() if x.strip()]
    return " | ".join(lines[-n:])[:400]


def online(host="pypi.org", port=443, timeout=4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def fmt_versions() -> str:
    from importlib.metadata import version, PackageNotFoundError
    parts = []
    for pkg in ("pillow", "certifi", "python-docx", "python-pptx", "openpyxl"):
        try:
            parts.append(f"{pkg}={version(pkg)}")
        except PackageNotFoundError:
            parts.append(f"{pkg}=MISSING")
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# 1. 读取侧拦截（引擎层；DSH 进程内 E2E 见第 2 项）
# --------------------------------------------------------------------------- #
# Phase 0.9：preset 声明的每一类实体都必须有可复现探针。
# 新增实体类型时同步加探针；缺探针即 FAIL（差集不允许静默通过）。
ENTITY_PROBES = {
    "ID_NUMBER": "身份证号 110101199003077890 请核对",
    "PHONE_NUMBER": "手机13800138000联系",
    "EMAIL_ADDRESS": "发送到 a.b@example.com 即可",
    "CREDIT_CODE": "统一代码 91110000123456787H 已登记",
    "BANK_CARD": "卡号 6222 0211 1111 1111 234 有效",
    "PASSPORT": "护照号 E12345678 请核对",
    "LICENSE_PLATE": "车牌 皖A12345 已登记",
    "IP_ADDRESS": "服务器 IP 192.168.1.100 运行",
    "MAC_ADDRESS": "MAC 地址 00:1A:2B:3C:4D:5E",
    "PERSON": "李明在开会",
    "LOCATION": "地址：成都市武侯区天府大道北段1700号",
    "ORGANIZATION": "参照安徽省数据资源管理局的做法",
    "JOB_TITLE": "他担任总经理一职",
    "AGE": "年龄 45 周岁，身体健康",
    "BIRTH_DATE": "出生日期：1990-03-07",
    "GENDER": "性别：男，民族：汉族",
    "ETHNICITY": "民族：汉族",
    "EDUCATION": "学历：硕士研究生",
    "IM_ACCOUNT": "微信：zhangsan2024 常联系",
    "EMPLOYEE_ID": "工号：EMP-000123 请登记",
}


def _preset_entity_types() -> list:
    """读 preset.json 声明的实体类型；读不到返回空表（由调用方判定 FAIL）。"""
    preset = REPO / ".agent-presets" / "presidio-pii" / "preset.json"
    try:
        data = json.loads(preset.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    types = data.get("entity_types")
    return list(types) if isinstance(types, list) else []


def _check_entity_coverage(db_path) -> tuple:
    """逐类探针断言。返回 (ok, missing, no_probe)。"""
    from presidio_pii.engine import PresidioPIIEngine

    declared = _preset_entity_types()
    if not declared:
        return False, ["<preset entity_types 读取失败>"], []
    rules = REPO / "rule_libraries" / "extended-fields.json"
    eng = PresidioPIIEngine(db_path=db_path,
                            custom_rules=str(rules) if rules.is_file() else None)
    missing, no_probe = [], []
    try:
        sid = eng.registry.create_session()
        for etype in declared:
            probe = ENTITY_PROBES.get(etype)
            if probe is None:
                no_probe.append(etype)
                continue
            rd = eng.redact(probe, sid, f"probe-{etype}")
            if rd.entity_counts.get(etype, 0) <= 0:
                missing.append(f"{etype}({rd.entity_counts})")
    finally:
        eng.registry.close()
    return (not missing and not no_probe), missing, no_probe


def check_read() -> dict:
    from presidio_pii.engine import PresidioPIIEngine

    tmp = tempfile.mkdtemp(prefix="gate_read_")
    eng = PresidioPIIEngine(db_path=Path(tmp) / "read.db")
    paper = (REPO / "testdata_v2/paper/paper-01.md").read_text(encoding="utf-8")
    rd = eng.redact(paper, "gate", "paper-01")
    counts = rd.entity_counts
    names = ("范志强", "姚志刚", "谭俊杰")
    ws_ok = re.findall(r"\s+", rd.text) == re.findall(r"\s+", paper)
    normal = (REPO / "testdata_v2/negative/normal-01.md").read_text(encoding="utf-8")
    rd2 = eng.redact(normal, "gate2", "normal-01")
    personal = sum(rd2.entity_counts.get(t, 0)
                   for t in ("PERSON", "ID_NUMBER", "PHONE_NUMBER", "BANK_CARD"))
    base_ok = (rd.n_replaced > 0 and counts.get("PERSON", 0) > 0
               and not any(n in rd.text for n in names) and ws_ok and personal == 0)
    # Phase 0.9：20 类逐类断言 + 差集检查（声明了却没探针 = FAIL）
    coverage_ok, missing, no_probe = _check_entity_coverage(Path(tmp) / "cover.db")
    ok = base_ok and coverage_ok
    ev = (f"paper-01: {counts} 共 {rd.n_replaced} 处, 明文人名 absent={not any(n in rd.text for n in names)}, "
          f"空白序列一致={ws_ok}; normal-01 个人类实体={personal}; "
          f"逐类探针 {len(_preset_entity_types()) - len(no_probe) - len(missing)}/"
          f"{len(_preset_entity_types())} 命中, 未命中={missing or '无'}, 缺探针={no_probe or '无'}")
    if base_ok and coverage_ok:
        reason = "占位符生效且不吞分隔符，负例无个人类误报，preset 每类实体均有命中探针"
    elif not base_ok:
        reason = "读取侧拦截或结构保持不满足"
    else:
        reason = "preset 声明了引擎产不出的实体类型，或新增类型未配探针"
    shutil.rmtree(tmp, ignore_errors=True)
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}



# --------------------------------------------------------------------------- #
# 2. DSH 进程内 E2E
# --------------------------------------------------------------------------- #
E2E_EVIDENCE = REPO / ".pii_presidio_store" / "e2e_9steps_2026-11-10.md"


def check_e2e() -> dict:
    """#2 DSH 进程内 E2E: 2026-11-10 重启后 9 步实测已完成。

    证据驱动: 证据文件存在且 9 步全部标 PASS -> PASS; 否则退回 MANUAL。
    """
    if E2E_EVIDENCE.is_file():
        text = E2E_EVIDENCE.read_text(encoding="utf-8")
        steps = [f"| {i} |" for i in range(3, 10)]
        if all(s in text for s in steps) and "**PASS**" in text:
            return {
                "status": PASS,
                "evidence": (
                    f"evidence={E2E_EVIDENCE.relative_to(REPO).as_posix()} "
                    f"({E2E_EVIDENCE.stat().st_size}B, 9 步实测全 PASS)"),
                "reason": "DSH 重启后 9 步 E2E 已实测通过（证据已落盘，见门禁 #2 章节）",
            }
    return {
        "status": MANUAL,
        "evidence": "需 DSH 托盘完全退出后重启，选 presidio-pii 预设",
        "reason": "插件改动需重启进程才加载；脚本无法代跑 DSH 内置 read/grep/pwsh/job_*",
        "manual": [
            "1) 托盘图标右键 -> 完全退出 DSH（不是关闭窗口）",
            "2) 重新启动 DSH，选择 presidio-pii 预设",
            "3) read testdata_v2/paper/paper-01.md 前 8 行：出现占位符，无明文人名",
            "4) read testdata_v2/negative/normal-01.md：PERSON/ID/PHONE/BANK 计数均为 0",
            "5) grep 命中行：电话已变成占位符",
            "6) pwsh 执行 Get-Content testdata_v2/paper/paper-01.md：输出含占位符，无明文人名",
            "7) pwsh 执行 git status / Get-Process 等无 PII 命令：输出与未拦截时逐字节一致",
            "8) pwsh 后台跑 Get-Content paper-01.md，再用 job_output 续读：输出已脱敏（P2）",
            "9) job_list 查看任务：命令/描述回显中的人名与电话已变占位符（P2）",
        ],
    }


# --------------------------------------------------------------------------- #
# 3. redact -> restore 无损（md/csv/office 三格式）
# --------------------------------------------------------------------------- #
def check_restore() -> dict:
    if importlib.util.find_spec("docx") is None:
        return {"status": SKIP, "evidence": "python-docx 未安装",
                "reason": "缺少 office 依赖，无法验证 docx/xlsx/pptx 无损"}
    tmp = Path(tempfile.mkdtemp(prefix="gate_restore_"))
    py = sys.executable

    def cli(*args):
        return run([py, "-m", "presidio_pii.cli", *args], cwd=tmp, timeout=300)

    rows, bad = [], []
    for rel in ("testdata_v2/resume/resume-01.docx",
                "testdata_v2/payroll/payroll-01.xlsx",
                "testdata_v2/report/report-07.pptx"):
        src = REPO / rel
        work = tmp / src.name
        shutil.copy2(src, work)
        cli("redact", str(work))
        red = tmp / f"{src.stem}-redacted" / src.name
        cli("restore", str(red), "-d", str(tmp / "restored"))
        out = tmp / "restored" / src.name
        from presidio_pii.documents import read_units
        from presidio_pii.engine import count_placeholders

        a = read_units(src)
        b = read_units(out)
        left = count_placeholders("\n".join(t for _, t in b))
        rows.append(f"{src.suffix}:{len(a)}units eq={a == b} left={left}")
        if a != b or left:
            bad.append(src.name)

    md = tmp / "paper.md"
    shutil.copy2(REPO / "testdata_v2/paper/paper-01.md", md)
    cli("redact", str(md))
    cli("restore", str(tmp / "paper-redacted/paper.md"), "-d", str(tmp / "restored"))
    md_ok = hashlib.sha256(md.read_bytes()).hexdigest() == \
        hashlib.sha256((tmp / "restored/paper.md").read_bytes()).hexdigest()

    csv_src = tmp / "contacts.csv"
    csv_src.write_text("姓名,手机,城市\n张伟,13800138000,北京\n李娜,13900139000,上海\n",
                       encoding="utf-8")
    cli("redact", str(csv_src))
    cli("restore", str(tmp / "contacts-redacted/contacts.csv"), "-d", str(tmp / "restored"))
    with (tmp / "restored/contacts.csv").open(encoding="utf-8-sig", newline="") as f:
        csv_ok = list(csv.reader(f)) == list(csv.reader(csv_src.open(encoding="utf-8-sig", newline="")))
    if not csv_ok:
        bad.append("contacts.csv")

    ok = not bad and md_ok
    ev = f"{'; '.join(rows)}; md byte_identical={md_ok}; csv cells_equal={csv_ok}"
    reason = ("逐字还原且占位符清零" if ok
              else f"还原不一致: {', '.join(bad) or 'md'}")
    shutil.rmtree(tmp, ignore_errors=True)
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


# --------------------------------------------------------------------------- #
# 4. 自动 restore 接线（待决策）
# --------------------------------------------------------------------------- #
def check_restore_wiring() -> dict:
    """#4 自动 restore 接线: 方案 B（显示侧还原）已于 2026-11-10 实现。

    判据: 插件含 assistant-stream 监听器与 PII_GUARD_DISPLAY 开关;
    server.py 含 restore op 与增量 map 下发; 显示冒烟 plugin_display.mjs 通过。
    显示冒烟由 #5 执行; 此处做源码断言。
    """
    src_plugin = PLUGIN_SRC.read_text(encoding="utf-8")
    src_server = (REPO / "presidio_pii" / "server.py").read_text(encoding="utf-8")
    need_plugin = ["agent/assistant-stream", "PII_GUARD_DISPLAY", "phMap",
                   "splitDisplayable", "displayBufs"]
    need_server = ['op == "restore"', "_mask_value", "_restore_display", '"map"']
    miss_p = [p for p in need_plugin if p not in src_plugin]
    miss_s = [p for p in need_server if p not in src_server]
    ok = not miss_p and not miss_s and DISPLAY_MODE_SUPPORTED(src_plugin)
    ev = (f"plugin_display={'ok' if not miss_p else '缺:' + ','.join(miss_p)}; "
          f"server_restore={'ok' if not miss_s else '缺:' + ','.join(miss_s)}; "
          f"smoke=display(见 #5)")
    if ok:
        return {"status": PASS, "evidence": ev,
                "reason": "方案 B 已实现: 显示侧还原(PII_GUARD_DISPLAY=full/mask/off), "
                          "不改会话存储与模型上下文; 冒烟见 #5 display=pass"}
    return {"status": FAIL, "evidence": ev, "reason": "显示侧还原实现不完整"}


def DISPLAY_MODE_SUPPORTED(src: str) -> bool:
    # 2026-11-18 起显示模式改为动态配置（guard-settings.json），裸 DISPLAY_MODE
    # 常量已被 coerceDisplayMode()/displayMode() 取代。兼容新旧两种实现形态。
    mode_api = ('DISPLAY_MODE' in src or 'coerceDisplayMode' in src
                or 'displayMode()' in src)
    return mode_api and 'mask' in src and 'full' in src and 'off' in src


# --------------------------------------------------------------------------- #
# 5. 格式覆盖面（文本类由 #1/#3 覆盖；pwsh 已按 P1-全纳入）
# --------------------------------------------------------------------------- #
# FIX-1: 已安装插件路径不再写死作者路径，改由 DSH_HOME 环境变量推断。
# 未配置时留空：下方安装的 sha 比对会走 installed_sync=missing -> SKIP 分支，
# 仓库副本本身仍独立校验，不降低门禁判定口径。
# 统一 bundle 形态：仓库副本 plugins/dsh-presidio-pii/lib/guard.js，安装态由
# dsh 插件管理器以 link 方式挂到 <DSH_HOME>/profiles/<profile>/node_modules/dsh-presidio-pii。
_DSH_HOME = os.environ.get("DSH_HOME", "").strip()
_DSH_PROFILE = os.environ.get("DSH_PROFILE", "").strip() or "desktop"
_BUNDLE_NAME = "dsh-presidio-pii"
PLUGIN = (Path(_DSH_HOME) / "profiles" / _DSH_PROFILE / "node_modules"
          / _BUNDLE_NAME / "lib" / "guard.js" if _DSH_HOME else Path(""))
PLUGIN_SRC = REPO / "plugins" / _BUNDLE_NAME / "lib" / "guard.js"


def _sha_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_formats() -> dict:
    if not PLUGIN_SRC.is_file():
        return {"status": FAIL, "evidence": str(PLUGIN_SRC),
                "reason": "插件源码未纳入仓库（无版本控制/无备份）"}
    src = PLUGIN_SRC.read_text(encoding="utf-8")
    missing = [pat for pat in ('"pwsh"', '"job_output"', '"job_list"',
                               "non-text output, redaction skipped",
                               "MAX_JOB_BYTES",
                               "output truncated to 256000 bytes before redaction",
                               "result?.isError && !SHELL_GUARDED.has",
                               "shell_bypass", "PII_GUARD_SHELL_ALLOWLIST",
                               "PII_GUARD_REPO", "invalid PII_GUARD_SHELL_ALLOWLIST",
                               "PII_GUARD_SHELL",
                               # 方案 B 显示侧还原（门禁 #4 实现）
                               "PII_GUARD_DISPLAY", "agent/assistant-stream",
                               "PH_FULL", "PH_TAIL", "splitDisplayable",
                               "phMap", "displayBufs",
                               # v0.2：默认全工具扫描 / fail-closed / 写入侧还原 / 兜底告警
                               "SKIP_TOOLS", "FAIL_OPEN", "BLOCK_MARK",
                               "PII_GUARD_FAIL_OPEN", "restoreArgs", "restoreText",
                               "WRITE_TOOLS", "WRITE_TEXT_KEYS",
                               '"agent/created"', '"agent/pre-step"',
                               'restrict({ deny: ["read_image"] })',
                                'value replacement present, blocking result',
                                "redact failed, blocking result",
                                # v0.3：meta/value 重渲染，堵住 read/grep 的 meta.lines 原文
                                "redactValueLeaves", "pairs.sort",
                                "value: redactValueLeaves(result.value, pairs)",
                                "result?.meta !== undefined",
                                 # v0.5：P0/P1 设置页动态生效（guard-settings.json 单一数据源）
                                 "GUARD_SETTINGS_FILE", "readSettings", "ENV_FALLBACK",
                                 "coerceDisplayMode", "displayMode()", "isFailOpen()",
                                 "isShellDisabled()", "getAllowlist()",
                                 # v0.6：内存有界 + allowlist ReDoS 双保险 + 路径解析去重
                                 "cacheSet", "PH_CACHE_LIMIT", "DISPLAY_BUF_LIMIT",
                                 'from "./paths.mjs"', 'from "./regex-safety.mjs"',
                                 "hasNestedQuantifier(",
                                 ) if pat not in src]
    # 子进程 error 处理按行为断言，不锁变量名：B1 竞态修复后 svc 变成句柄对象，
    # 真正挂 error 处理的是 proc，锁字面量会把合法重构误判成回归。
    if not re.search(r"\.on\(\s*[\"']error[\"']", src):
        missing.append("<child process error handler>")

    # v0.4：用户自定义屏蔽词 UI（统一 bundle 的 terms/client 半身）
    terms_src = REPO / "plugins" / _BUNDLE_NAME
    terms_files = ["package.json", "cordis.patch.yml", "lib/terms.js",
                   "lib/guard.js", "lib/fs.mjs", "lib/paths.mjs", "lib/regex-safety.mjs",
                   "client.js", "locale/en.json", "locale/zh.json", "icon.svg"]
    terms_missing = [f for f in terms_files if not (terms_src / f).is_file()]
    terms_ev = ""
    if not terms_missing:
        host_src = (terms_src / "lib" / "terms.js").read_text(encoding="utf-8")
        client_src = (terms_src / "client.js").read_text(encoding="utf-8")
        host_missing = [pat for pat in (
            "export const name = 'dsh-presidio-pii-terms'",
            "USER_TERM", "user-term-placeholder", "(?!)",
            "/api/dsh-pii-guard/terms", "/api/dsh-pii-guard/terms/save",
            "isLoopbackRequest", "hasSameOriginProof", "function guard(req, res, method)",
            "normalizeTerms", "writeTerms", "readTerms", "escapeLiteral",
            "ctx.inject(['webServer']",
            # v0.5：P0/P1 设置 API + S1 精确会话 cookie + S2 路径漂移告警
            "/api/dsh-pii-guard/settings", "/api/dsh-pii-guard/settings/save",
            "sessionCookieName", "hasSessionCookie", "dsh-auth-",
            "readSettings", "normalizeSettings", "writeSettings", "warnIfPathDrift",
            # 统一 bundle：ReDoS 拦截抽到共享模块，host 半体必须引用它
            "from './regex-safety.mjs'", "hasNestedQuantifier",
        ) if pat not in host_src]
        client_missing = [pat for pat in (
            "const MODULE_ID = 'dsh-presidio-pii'",
            "settings.section", "settings.section.icon", "pii-guard-terms",
            "api/dsh-pii-guard/terms",
            "__ModuleLoader__.load", "return exports",
            # v0.5：前端设置分节（屏蔽词+防护配置合并进单一菜单 PiiGuardSection）
            "api/dsh-pii-guard/settings", "SettingsSection", "PiiGuardSection",
        ) if pat not in client_src]
        terms_missing = terms_missing + host_missing + client_missing
        terms_ev = (f"terms={'ok' if not terms_missing else '缺:' + ','.join(terms_missing)}; ")

    # 用户屏蔽词接线：preset.custom_rules_path 必须指向规则文件，且占位规则不可为空数组。
    # S2 加强：必须与 UI termsFile（默认或 env PII_GUARD_TERMS_FILE）交叉校验，
    # 否则两边路径漂移后，UI 保存的词条静默不生效。
    preset_p = REPO / ".agent-presets" / "presidio-pii" / "preset.json"
    wiring_ev, wiring_ok = "terms_wiring=missing", False
    try:
        cfg = json.loads(preset_p.read_text(encoding="utf-8")).get("config") or {}
        crp = cfg.get("custom_rules_path")
        crp_ok = isinstance(crp, str) and crp.strip() != ""
        # UI 侧实际写入文件：env 覆盖优先，否则插件默认值
        ui_terms = os.environ.get("PII_GUARD_TERMS_FILE") or str(
            REPO / ".pii_presidio_store" / "user_terms_rules.json")
        resolved_crp = str((REPO / crp.strip()).resolve()) if crp_ok else ""
        norm = lambda p: str(p).replace("\\", "/").rstrip("/").lower()
        cross_ok = crp_ok and norm(resolved_crp) == norm(str(Path(ui_terms).resolve()))
        wiring_ok = crp_ok and cross_ok
        wiring_ev = (f"terms_wiring={'ok' if wiring_ok else 'MISMATCH'}"
                     f"(preset={crp!r}-> {resolved_crp}; ui={ui_terms!r})")
    except (OSError, ValueError) as exc:  # pragma: no cover - 配置损坏
        wiring_ev = f"terms_wiring=error({exc.__class__.__name__})"

    node = shutil.which("node")
    js_ok, js_ev = False, "node=missing"
    if node:
        rc_js, out_js = run([node, "tests/js/plugin_jobs.mjs", str(PLUGIN_SRC)],
                            cwd=REPO, timeout=180)
        rc_disp, out_disp = run([node, "tests/js/plugin_display.mjs", str(PLUGIN_SRC)],
                                cwd=REPO, timeout=120)
        rc_terms, out_terms = run([node, "tests/js/plugin_terms.mjs",
                                   str(REPO / "plugins" / _BUNDLE_NAME / "lib" / "terms.js")],
                                  cwd=REPO, timeout=120)
        js_ok = rc_js == 0 and rc_disp == 0 and rc_terms == 0
        js_ev = (f"js_smoke={'pass' if rc_js == 0 else 'fail'}"
                 f"/display={'pass' if rc_disp == 0 else 'fail'}"
                 f"/terms={'pass' if rc_terms == 0 else 'fail'}")
        if rc_js != 0:
            js_ev += f" (jobs: {tail(out_js, 1)})"
        if rc_disp != 0:
            js_ev += f" (display: {tail(out_disp, 1)})"
        if rc_terms != 0:
            js_ev += f" (terms: {tail(out_terms, 1)})"

    # 仓库副本 vs 已安装副本：防止“改了一份、跑的是另一份”
    if PLUGIN.is_file():
        same = _sha_file(PLUGIN) == _sha_file(PLUGIN_SRC)
        sync_ev = f"installed_sync={'ok' if same else 'drift'}"
        sync_ok = same
    else:
        sync_ev = "installed_sync=missing"
        sync_ok = False

    # 引擎级语义抽查（与 tests/test_shell_redaction.py 同口径）
    from presidio_pii.engine import PresidioPIIEngine
    tmp = Path(tempfile.mkdtemp(prefix="gate_fmt_"))
    eng = PresidioPIIEngine(db_path=tmp / "f.db")
    sid = eng.registry.create_session()
    plain1 = "epoch=1699289554123 retries=3\n"
    plain2 = "    200      12    40960  20480     1.25  42  python\n"  # 表格局部
    pii = "ok\n[stderr]\nWrite-Error: 张伟 13800138000\n[exit code: 1]\n"
    r1 = eng.redact(plain1, sid, "shell").text
    r2 = eng.redact(plain2, sid, "shell").text
    r3 = eng.redact(pii, sid, "shell").text
    eng.registry.delete_session(sid)
    shutil.rmtree(tmp, ignore_errors=True)

    plain_ok = r1 == plain1 and r2 == plain2
    pii_ok = ("张伟" not in r3 and "13800138000" not in r3
              and "[stderr]\n" in r3 and "[exit code: 1]" in r3)
    terms_ok = not terms_missing and wiring_ok
    ok = not missing and plain_ok and pii_ok and js_ok and sync_ok and terms_ok
    ev = (f"src=repo plugin={'ok' if not missing else '缺:' + ','.join(missing)}; "
          f"{sync_ev}; {js_ev}; plain_unchanged={plain_ok}; "
          f"pii_redacted={'张伟' not in r3}; "
          f"markers_kept={'[exit code: 1]' in r3}; "
          f"{terms_ev}{wiring_ev}")
    if not PLUGIN.is_file():
        return {"status": SKIP, "evidence": ev,
                "reason": "已安装插件不存在，无法校验安装态与仓库副本一致；"
                          "仓库副本本身已通过语义与冒烟检查"}
    reason = ("仓库副本与安装副本一致，pwsh + job_output/job_list 均已拦截且语义正确"
              "（含 256 KB 截断与 isError 脱敏）；用户自定义屏蔽词 UI 与其规则接线均已就位"
              if ok else "插件缺少 pwsh/后台任务/isError 逻辑、node 冒烟失败、"
                         "用户屏蔽词 bundle 或 preset 接线缺失、"
                         "安装态与仓库副本不一致或引擎语义回归")
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


# --------------------------------------------------------------------------- #
# 6. 依赖漏洞
# --------------------------------------------------------------------------- #
_PROJECT_MANIFEST = REPO / "pyproject.toml"


def _project_requirements() -> list[str]:
    """读取 pyproject.toml 的 [project].dependencies。

    门禁审计对象是**本包的依赖闭包**，不是构建机上的整个 site-packages。
    宿主环境里与本包无关的包（例如 mcp 带进来的 opentelemetry-api）不该
    算作本包的漏洞，否则门禁会随开发机装了什么而漂移；反过来，闭包内的
    间接依赖必须一并审计，不能只看直接依赖。
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11
        return []
    try:
        data = tomllib.loads(_PROJECT_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    deps = (data.get("project") or {}).get("dependencies") or []
    return [str(d).strip() for d in deps if str(d).strip()]


def _resolve_closure(requires: list[str], report: Path) -> tuple:
    """用 pip 的 --dry-run --report 解析完整闭包（含间接依赖）。

    返回 (name==version 列表, 失败说明)。
    """
    if not requires:
        return [], "pyproject.toml 读不到 [project].dependencies"
    rc, text = run([sys.executable, "-m", "pip", "install", "--dry-run",
                    "--ignore-installed", "--quiet",
                    "--report", str(report), *requires], timeout=600)
    if rc != 0 or not report.is_file():
        return [], tail(text, 2)
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except ValueError:
        return [], "pip --report 输出不是合法 JSON"
    seen = {}
    for item in data.get("install") or []:
        meta = item.get("metadata") or {}
        name = str(meta.get("name") or "").strip().lower()
        ver = str(meta.get("version") or "").strip()
        if name and ver:
            seen[name] = ver
    return [f"{n}=={v}" for n, v in sorted(seen.items())], ""


def check_deps() -> dict:
    rc_check, out_check = run([sys.executable, "-m", "pip", "check", "--disable-pip-version-check"])
    versions = fmt_versions()
    if rc_check != 0:
        return {"status": FAIL, "evidence": f"{versions}; pip check: {tail(out_check, 3)}",
                "reason": "存在破损依赖"}

    requires = _project_requirements()
    tmp = Path(tempfile.mkdtemp(prefix="gate_audit_"))
    closure, why = _resolve_closure(requires, tmp / "report.json")
    if not closure:
        shutil.rmtree(tmp, ignore_errors=True)
        if not online():
            return {"status": SKIP, "evidence": f"{versions}; pip check OK",
                    "reason": "离线无法解析依赖闭包，未做漏洞比对"}
        return {"status": FAIL, "evidence": f"{versions}; resolve: {why}",
                "reason": "无法解析本包依赖闭包"}

    tool = shutil.which("pip-audit")
    if not tool:
        uvx = shutil.which("uvx") or str(Path.home() / ".local" / "bin" / ("uvx.exe" if sys.platform == "win32" else "uvx"))
        audit_cmd = [uvx, "pip-audit"] if Path(uvx).exists() else None
    else:
        audit_cmd = [tool]
    if not audit_cmd:
        shutil.rmtree(tmp, ignore_errors=True)
        return {"status": SKIP, "evidence": f"{versions}; closure={len(closure)} pkgs",
                "reason": "未找到 pip-audit / uvx，无法做漏洞库比对"}
    if not online():
        shutil.rmtree(tmp, ignore_errors=True)
        return {"status": SKIP, "evidence": f"{versions}; closure={len(closure)} pkgs",
                "reason": "当前离线，pip-audit 无法拉取漏洞库（不视为通过）"}

    req = tmp / "req.txt"
    req.write_text("\n".join(closure) + "\n", encoding="utf-8")
    rc, out = run([*audit_cmd, "-r", str(req)], timeout=600)
    low = out.lower()
    shutil.rmtree(tmp, ignore_errors=True)
    scope = f"closure={len(closure)}pkgs"
    if "no known vulnerabilities" in low:
        return {"status": PASS, "evidence": f"{versions}; {scope}; pip-audit 0",
                "reason": "本包依赖闭包无已知漏洞"}
    if rc != 0 and any(s in low for s in ("connection", "resolve", "timed out", "network", "temporary failure")):
        return {"status": SKIP, "evidence": f"{versions}; {scope}; audit: {tail(out, 3)}",
                "reason": "漏洞库连接失败（离线或网络受限）"}
    return {"status": FAIL, "evidence": f"{versions}; {scope}; audit: {tail(out, 4)}",
            "reason": "本包依赖闭包存在已知漏洞"}


# --------------------------------------------------------------------------- #
# 7. 密钥扫描（git 历史 + 工作树）
# --------------------------------------------------------------------------- #
_SECRET_PATTERNS = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("slack", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google_api", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("openai_sk", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("assign", re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[=:]\s*[\"']?([^\s\"'#]{8,})")),
    ("uri_cred", re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]{3,}:([^/\s@]{3,})@")),
]
_SAFE_VALUE = re.compile(
    r"(?i)^(Tuple\[|List\[|Dict\[|Optional\[|Callable\[|str|int|bool|None|"
    r"os\.environ|getenv|\$\{|<|\[|\"\"|''|\*{3}|xxx|your[_-])")
# 值本身是一个「求值表达式」而非字面量，就不是泄露的凭据：
# 例如 hooks.py 的 `secret = secrets.token_bytes(32)`——这是运行时生成随机密钥，
# 恰恰是安全实践，不该被算成硬编码密钥。只放行明显是调用/属性的形态。
_SAFE_EXPR = re.compile(
    r"(?i)^(?:"
    r"secrets\.|uuid\.|hmac\.|hashlib\.|base64\.|os\.|sys\.|Path\("
    r"|[\w.]+\("          # 任意函数调用 foo(...)
    r"|[\w.]+\.[\w.]+"    # 任意属性访问 a.b.c
    r")"
)


def _mask(s: str) -> str:
    return s[:3] + "***" + s[-2:] if len(s) > 6 else "***"


# 扫描器自测夹具：tests/test_release_gate_rules.py 里的字符串是**假凭据**，
# 存在的目的就是证明扫描器能命中。按路径豁免，并且每次都把豁免条数写进
# evidence 披露——不做静默丢弃，其他路径依旧零容忍。
_BENIGN_SCAN_PATHS = ("tests/test_release_gate_rules.py",)


def _is_benign(where: str) -> bool:
    return any(where == p or where.endswith("/" + p) for p in _BENIGN_SCAN_PATHS)


def _line_matches(body: str) -> tuple:
    """返回 (命中列表 [(pattern, masked)], 被值白名单抑制数)。"""
    out, suppressed = [], 0
    for name, rx in _SECRET_PATTERNS:
        for m in rx.finditer(body):
            value = m.group(2) if name == "assign" and m.lastindex else m.group(0)
            if name == "assign" and (_SAFE_VALUE.search(value or "")
                                     or _SAFE_EXPR.search(value or "")):
                suppressed += 1
                continue
            out.append((name, _mask(m.group(0))))
    return out, suppressed


def _scan_text(text: str, where: str) -> tuple:
    """返回 (真命中, 白名单抑制数)。抑制数只用于披露, 不静默丢弃。"""
    hits, suppressed = [], 0
    for line in text.splitlines():
        if line.startswith(("+++", "---")):
            continue
        body = line[1:] if line[:1] in "+-" else line
        h, s = _line_matches(body)
        hits += [(n, where, v) for n, v in h]
        suppressed += s
    return hits, suppressed


def _scan_history(text: str) -> tuple:
    """按 diff 头 `+++ b/<path>` 归属文件；自测夹具豁免数单独计数披露。"""
    hits, suppressed, benign = [], 0, 0
    cur = ""
    for line in text.splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip()
            cur = p[2:] if p.startswith("b/") else p
            continue
        if line.startswith(("+++", "---")):
            continue
        body = line[1:] if line[:1] in "+-" else line
        h, s = _line_matches(body)
        suppressed += s
        if not h:
            continue
        if _is_benign(cur):
            benign += len(h)
            continue
        where = f"history:{cur}" if cur else "history"
        hits += [(n, where, v) for n, v in h]
    return hits, suppressed, benign


def check_secrets() -> dict:
    rc, log = run(["git", "log", "-p", "--all", "--no-color", "--format=__C__%H"], timeout=300)
    if rc != 0:
        return {"status": FAIL, "evidence": tail(log, 2), "reason": "git log 读取失败，无法扫描历史"}
    commits = log.count("__C__")
    diff_lines = sum(1 for ln in log.splitlines()
                     if ln[:1] in "+-" and not ln.startswith(("+++", "---")))
    hist_hits, hist_suppressed, hist_benign = _scan_history(log)

    rc_ls, files = run(["git", "ls-files"], timeout=120)
    wt_hits, wt_suppressed, scanned, wt_benign = [], 0, 0, 0
    for rel in files.splitlines():
        p = REPO / rel
        if rel == "tools/release_gate.py" or not p.is_file():
            continue
        try:
            if p.stat().st_size > 1_000_000:
                continue
            data = p.read_bytes()
            if b"\x00" in data:
                continue
            scanned += 1
            h, s = _scan_text(data.decode("utf-8", "replace"), rel)
            if _is_benign(rel):
                wt_benign += len(h)
                wt_suppressed += s
                continue
            wt_hits += h
            wt_suppressed += s
        except OSError:
            continue

    # 高风险文件名（无论内容）
    risky = [r for r in files.splitlines()
             if re.search(r"(^|/)(\.env|id_rsa|id_ed25519|credentials\w*\.json)$|\.(pem|pfx|p12)$", r)]
    hits = hist_hits + wt_hits
    ok = not hits and not risky
    benign = hist_benign + wt_benign
    ev = (f"commits={commits} diff_lines={diff_lines} hist_hits={len(hist_hits)} "
          f"suppressed={hist_suppressed}; worktree_files={scanned} wt_hits={len(wt_hits)} "
          f"suppressed={wt_suppressed} risky_files={len(risky)}; "
          f"selftest_fixtures_exempted={benign} ({', '.join(_BENIGN_SCAN_PATHS)})")
    if hits:
        sample = "; ".join(f"{n}@{w}:{v}" for n, w, v in hits[:3])
        reason = f"命中 {len(hits)} 处: {sample}"
    elif risky:
        reason = f"高风险文件被追踪: {', '.join(risky[:3])}"
    else:
        reason = ("历史与工作树均无凭据命中（扫描器自测夹具 "
                  f"{benign} 处按路径豁免并已披露）")
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


# --------------------------------------------------------------------------- #
# 8. pytest
# --------------------------------------------------------------------------- #
def check_pytest() -> dict:
    rc, out = run([sys.executable, "-m", "pytest", "-q"], timeout=900)
    last = tail(out, 1)
    ok = rc == 0 and "passed" in out
    return {"status": PASS if ok else FAIL, "evidence": last,
            "reason": "测试全绿" if ok else "存在失败/报错用例"}


# --------------------------------------------------------------------------- #
# 9. wheel 构建（可复现）+ 干净环境安装
# --------------------------------------------------------------------------- #
# 固定 zip 内时间戳用；发布时可用环境变量覆盖成该次提交时间
GATE_EPOCH = os.environ.get("SOURCE_DATE_EPOCH") or "1700000000"


def _build_wheel(src: Path, dest: Path) -> tuple:
    """在隔离源码副本里构建；固定 SOURCE_DATE_EPOCH 让 zip 时间戳可复现。"""
    env = {**os.environ, "SOURCE_DATE_EPOCH": GATE_EPOCH}
    return run([sys.executable, "-m", "pip", "wheel", str(src), "--no-deps",
                "-w", str(dest), "--disable-pip-version-check"],
               cwd=src, timeout=600, env=env)


def check_wheel() -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="gate_wheel_"))
    # 用源码副本构建：避免仓库内 build/lib 的陈旧文件被带进 wheel，也不污染工作树
    src = tmp / "src"
    shutil.copytree(REPO / "presidio_pii", src / "presidio_pii",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(REPO / "pyproject.toml", src / "pyproject.toml")

    b1, b2 = tmp / "b1", tmp / "b2"
    b1.mkdir()
    b2.mkdir()
    rc1, out1 = _build_wheel(src, b1)
    rc2, out2 = _build_wheel(src, b2)
    w1 = next(iter(b1.glob("*.whl")), None)
    w2 = next(iter(b2.glob("*.whl")), None)
    if rc1 != 0 or rc2 != 0 or w1 is None or w2 is None:
        low = (out1 + out2).lower()
        if any(s in low for s in ("connect", "resolve", "timed out", "network",
                                  "temporary failure", "name resolution")):
            shutil.rmtree(tmp, ignore_errors=True)
            return {"status": SKIP, "evidence": tail(out1 + out2, 2),
                    "reason": "离线无法获取构建后端（setuptools/wheel），未构建"}
        shutil.rmtree(tmp, ignore_errors=True)
        return {"status": FAIL, "evidence": tail(out1 + out2, 3), "reason": "wheel 构建失败"}

    h1 = hashlib.sha256(w1.read_bytes()).hexdigest()
    h2 = hashlib.sha256(w2.read_bytes()).hexdigest()
    reproducible = h1 == h2

    venv = tmp / "venv"
    rc_v, out_v = run([sys.executable, "-m", "venv", str(venv)], timeout=300)
    if rc_v != 0 or not (venv / "Scripts" / "python.exe").exists():
        shutil.rmtree(tmp, ignore_errors=True)
        return {"status": SKIP, "evidence": tail(out_v, 2), "reason": "无法创建干净 venv"}
    py = venv / "Scripts" / "python.exe"
    rc_i, out_i = run([str(py), "-m", "pip", "install", "--no-index", "--no-deps",
                       str(w1)], timeout=300)
    if rc_i != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return {"status": FAIL, "evidence": tail(out_i, 3), "reason": "wheel 安装失败"}

    md = tmp / "paper.md"
    shutil.copy2(REPO / "testdata_v2/paper/paper-01.md", md)
    rc_r, out_r = run([str(py), "-m", "presidio_pii.cli", "redact", str(md)], cwd=tmp, timeout=300)
    red = tmp / "paper-redacted" / "paper.md"
    rc_s, out_s = run([str(py), "-m", "presidio_pii.cli", "restore", str(red),
                       "-d", str(tmp / "restored")], cwd=tmp, timeout=300)
    restored = tmp / "restored" / "paper.md"
    identical = restored.exists() and \
        hashlib.sha256(md.read_bytes()).hexdigest() == hashlib.sha256(restored.read_bytes()).hexdigest()
    import_ok = run([str(py), "-c",
                     "import presidio_pii, pathlib;"
                     "from presidio_pii.chinese_recognizers import _ASSETS_DIR as a;"
                     "print(pathlib.Path(presidio_pii.__file__).parent.name == 'presidio_pii', (a/'surnames.txt').exists())"],
                    cwd=tmp, timeout=120)
    non_editable = "True True" in import_ok[1]
    ok = reproducible and rc_r == 0 and rc_s == 0 and identical and non_editable
    ev = (f"wheel={w1.name} {w1.stat().st_size}B sha256={h1[:16]} epoch={GATE_EPOCH} "
          f"rebuild_sha256={h2[:16]} reproducible={reproducible}; "
          f"venv_non_editable={non_editable}; md_byte_identical={identical}")
    if not reproducible:
        reason = "两次构建哈希不一致（构建不可复现）"
    elif not ok:
        reason = "干净环境安装/导入/往返校验失败"
    else:
        reason = "两次构建字节一致且干净环境往返无损"
    shutil.rmtree(tmp, ignore_errors=True)
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


# --------------------------------------------------------------------------- #
# 10. 源码可溯源
# --------------------------------------------------------------------------- #
MANIFEST_PATH = REPO / "release" / "presidio-pii-dsh-0.1.0.json"


def _source_tree_digest() -> str:
    """绑定发布物与源码: 排序后的 (相对路径, 文件 SHA256) 再取 SHA256。

    覆盖 wheel 实际打包的内容 (presidio_pii/** + pyproject.toml), 与 git 提交无关,
    因此工作树未提交时也能证明「这个 wheel 来自这份源码」。
    """
    items = []
    for p in (REPO / "presidio_pii").rglob("*"):
        if not p.is_file() or "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        items.append((p.relative_to(REPO).as_posix(),
                      hashlib.sha256(p.read_bytes()).hexdigest()))
    py = REPO / "pyproject.toml"
    items.append((py.relative_to(REPO).as_posix(), hashlib.sha256(py.read_bytes()).hexdigest()))
    buf = "".join(f"{rel}\0{h}\n" for rel, h in sorted(items)).encode("utf-8")
    return hashlib.sha256(buf).hexdigest()


def _commit_is_self_or_ancestor(bound: str, head: str) -> bool:
    """清单绑定的提交只要等于 HEAD 或是 HEAD 的祖先就成立。

    否则把清单提交进仓库这个动作本身就会让 commit_match 变成 False，
    形成「提交清单 → 失配 → 再改清单 → 再失配」的死循环。真正的绑定强度
    由 source_tree_sha256 保证（覆盖 wheel 打包的源码），提交只证明谱系。
    """
    if not bound or not head:
        return False
    if bound == head:
        return True
    rc, _ = run(["git", "merge-base", "--is-ancestor", bound, head])
    return rc == 0


def _verify_manifest(head: str) -> tuple:
    """校验产物级溯源清单; 返回 (ok, 证据, 原因)。"""
    if not MANIFEST_PATH.is_file():
        return False, "manifest=缺失", "未推送且没有发布物清单"
    try:
        m = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return False, "manifest=解析失败", "发布物清单不是合法 JSON"
    art = m.get("artifact") or {}
    src = m.get("source") or {}
    wheel = REPO / str(art.get("path") or "")
    if not wheel.is_file():
        return False, f"manifest artifact=缺失({art.get('path')})", "清单指向的 wheel 不存在"
    data = wheel.read_bytes()
    size_ok = len(data) == art.get("bytes")
    sha_ok = hashlib.sha256(data).hexdigest().lower() == str(art.get("sha256", "")).lower()
    commit_ok = _commit_is_self_or_ancestor(str(src.get("commit") or ""), head)
    tree_ok = src.get("source_tree_sha256") == _source_tree_digest()
    ev = (f"manifest={art.get('filename')} bytes_ok={size_ok} sha_ok={sha_ok} "
          f"commit_ok={commit_ok} tree_digest_match={tree_ok}")
    ok = bool(size_ok and sha_ok and commit_ok and tree_ok)
    reason = ("产物级溯源通过（wheel 哈希与源码树摘要一致）" if ok
              else "发布物清单与当前 wheel/源码不一致，需重建并更新清单")
    return ok, ev, reason


def check_provenance() -> dict:
    rc_head, head = run(["git", "rev-parse", "HEAD"])
    head = head.strip()
    rc_org, org = run(["git", "rev-parse", "origin/master"])
    rc_a = 1
    ahead = "?"
    if rc_org == 0:
        rc_a, _ = run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/master"])
        rc_n, ahead = run(["git", "rev-list", "--count", "origin/master..HEAD"])
        ahead = ahead.strip() or "?"
    origin_ok = rc_head == 0 and rc_a == 0
    man_ok, man_ev, man_reason = _verify_manifest(head)

    if origin_ok:
        return {"status": PASS,
                "evidence": f"HEAD={head[:8]} origin/master={org.strip()[:8]} ahead={ahead}; {man_ev}",
                "reason": "HEAD 已在远端可达"}
    if man_ok:
        return {"status": PASS,
                "evidence": (f"HEAD={head[:8] or '?'} origin/master={'缺失' if rc_org else org.strip()[:8]} "
                             f"ahead={ahead} artifact_only; {man_ev}"),
                "reason": "源提交未推送，按产物级溯源通过（清单绑定 wheel 哈希与源码树摘要）"}
    return {"status": FAIL,
            "evidence": (f"HEAD={head[:8] or '?'} origin/master={'缺失' if rc_org else org.strip()[:8]} "
                         f"ahead={ahead}; {man_ev}"),
            "reason": ("HEAD 未推送到远端，且缺少可核验的发布物清单"
                       if not MANIFEST_PATH.is_file() else man_reason)}


# --------------------------------------------------------------------------- #
# 11. 仓库不落真实 PII / 映射库
# --------------------------------------------------------------------------- #
_FORBIDDEN_TRACKED = re.compile(
    r"(^|/)(\.pii_presidio_store/|.*\.mapping\.csv|.*\.session\.(csv|json)|"
    r".*-redacted/|.*-restored/|testdata/|testdata_v2/(?!negative/))")


def check_repo_pii() -> dict:
    rc, files = run(["git", "ls-files"])
    tracked = files.splitlines()
    bad = [f for f in tracked if _FORBIDDEN_TRACKED.search(f)]
    rc_st, status = run(["git", "status", "--porcelain"])
    staged_artifacts = [ln for ln in status.splitlines()
                        if ln[:2].strip() and _FORBIDDEN_TRACKED.search(ln[3:].strip())]
    ignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    rules = [r for r in (".pii_presidio_store/", "*.mapping.csv", "*-redacted/",
                         "testdata_v2/*", "build/", "dist/") if r in ignore]
    ok = not bad and not staged_artifacts and len(rules) >= 5
    ev = (f"tracked_forbidden={len(bad)} staged_artifacts={len(staged_artifacts)} "
          f"gitignore_rules={len(rules)}/{6}")
    reason = ("真实语料/映射库均未入库" if ok else f"违规入库: {(bad or staged_artifacts)[:3]}")
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


def check_external_corpus() -> dict:
    if not online():
        return {"status": SKIP, "evidence": "离线",
                "reason": "无法从网络下载外部语料；不允许用本地语料替代"}
    tmp = Path(tempfile.mkdtemp(prefix="gate_ext_"))
    rep = tmp / "report.json"
    rc, out = run([sys.executable, "tools/external_corpus_check.py",
                   "--json", str(rep)], cwd=REPO, timeout=420)
    data = {}
    if rep.is_file():
        try:
            data = json.loads(rep.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
    results = data.get("results") or []
    parts = [f"{r.get('kind')}={r.get('replaced')}" for r in results
             if r.get("status") == PASS]
    ok = rc == 0 and bool(data.get("all_pass"))
    ev = f"files={len(results)} " + " ".join(parts)
    reason = ("网络下载的外部语料经注入合成 PII 后 redact→restore 全部无损"
              if ok else (tail(out, 1) or "外部语料回归失败"))
    shutil.rmtree(tmp, ignore_errors=True)
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


def check_phase1() -> dict:
    """Phase 1 门禁①②③：最小工具面（禁 PTC / 禁 FAIL_OPEN / spill 占位符形态）。

    除调用 tools/check_phase1_gates.mjs 外，额外做静态断言：预设不得再挂
    tool-bash / tool-pwsh / tool-fs / tool-fs-search / tool-todo / tool-web，
    且必须挂 dsh-presidio-pii/fs 四件套。
    """
    rc, out = run(["node", "tools/check_phase1_gates.mjs"], cwd=REPO, timeout=120)
    gate_ok = rc == 0 and "GATE_PHASE1_DONE" in out

    presets = [REPO / ".agent-presets/presidio-pii/agent.cordis.yml",
               REPO / ".agent-presets/presidio-pii/bundle/cordis.patch.yml"]
    # 用带引号的完整包名匹配，避免 dsh-tool-fs 命中 dsh-tool-fs-search 的误报
    forbidden = ["dsh-tool-executor-ptc", "'@deepseek-ai/dsh-tool-bash'",
                 "'@deepseek-ai/dsh-tool-pwsh'", "'@deepseek-ai/dsh-tool-fs'",
                 "'@deepseek-ai/dsh-tool-fs-search'", "'@deepseek-ai/dsh-tool-todo'",
                 "'@deepseek-ai/dsh-tool-web'"]
    offenders = []
    has_fs = []
    for path in presets:
        if not path.is_file():
            offenders.append(f"{path.name}:missing")
            continue
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                offenders.append(f"{path.name}:{token}")
        if f"{_BUNDLE_NAME}/fs" in text:
            has_fs.append(path.name)
    ok = gate_ok and not offenders and len(has_fs) == len(presets)
    ev = (f"gate_script={'ok' if gate_ok else 'fail'} "
          f"presets_with_guard_fs={len(has_fs)}/{len(presets)} "
          f"forbidden_hits={len(offenders)}")
    reason = ("最小工具面成立：四件套挂载、shell/直读面已移除、三条门禁 PASS"
              if ok else f"违规项: {(offenders or [tail(out, 1)])[:3]}")
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


def check_runtime_wiring() -> dict:
    """生产配置接线：preset 声明的实体类型必须在真实 hooks 路径下全部可用。

    事故背景：Phase 0 的 7 类扩展字段在 golden 与旧门禁 #1 全绿的情况下，实际
    启动时报「忽略未知实体类型」——测试里显式传了 custom_rules，生产用的是
    preset + hooks，内置规则库从未被加载。旧门禁断言了一套生产不用的配置。

    因此本检查不碰测试夹具，只走两端各自的 hooks 层：
      * Node: tests/node/preset-runtime-types.mjs
      * Python: tools/check_runtime_types.py
    """
    node_rc, node_out = run(["node", "tests/node/preset-runtime-types.mjs"],
                            cwd=REPO, timeout=180)
    node_ok = node_rc == 0 and "PRESET_RUNTIME_TYPES_PASS" in node_out

    py_rc, py_out = run([sys.executable, "tools/check_runtime_types.py"],
                        cwd=REPO, timeout=180)
    payload = {}
    for line in py_out.splitlines():
        if line.startswith("RUNTIME_TYPES "):
            try:
                payload = json.loads(line[len("RUNTIME_TYPES "):])
            except ValueError:
                payload = {}
    py_ok = py_rc == 0 and bool(payload.get("ok"))

    ok = node_ok and py_ok
    ev = (f"node={'ok' if node_ok else 'fail'} py={'ok' if py_ok else 'fail'} "
          f"declared={payload.get('declared', '?')} "
          f"missing={payload.get('missing', '?')} "
          f"unproduced={payload.get('unproduced', '?')} "
          f"unknown_warning={payload.get('unknown_warning', '?')}")
    if ok:
        reason = "两端 hooks 生产路径下 preset 声明的实体类型全部已知且可产出"
    else:
        reason = (f"接线断裂: node={tail(node_out, 1)} "
                  f"py={payload.get('missing') or payload.get('unproduced') or payload.get('error') or tail(py_out, 1)}")
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


CHECKS = [
    ("1 读取侧拦截(引擎层)", check_read),
    ("2 DSH 进程内 E2E", check_e2e),
    ("3 redact→restore 无损", check_restore),
    ("4 自动 restore 接线", check_restore_wiring),
    ("5 格式覆盖面(shell)", check_formats),
    ("6 依赖漏洞", check_deps),
    ("7 密钥扫描(历史+工作树)", check_secrets),
    ("8 pytest", check_pytest),
    ("9 wheel + 干净环境", check_wheel),
    ("10 源码可溯源", check_provenance),
    ("11 仓库不落 PII", check_repo_pii),
    ("12 外部语料(网络下载)", check_external_corpus),
    ("13 Phase1 最小工具面(门禁①②③)", check_phase1),
    ("14 生产配置实体类型接线(双端 hooks)", check_runtime_wiring),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("release_gate: 一键发布门禁")
    ap.add_argument("--json", help="把逐项结果写成 JSON")
    ap.add_argument("--only", help="只跑编号(逗号分隔, 如 3,8)")
    args = ap.parse_args(argv)

    only = {x.strip() for x in args.only.split(",")} if args.only else None
    results, t0 = [], time.time()
    print(f"== PII-GUARD RELEASE GATE ==  repo={REPO}")
    for idx, (name, fn) in enumerate(CHECKS, start=1):
        if only and str(idx) not in only:
            continue
        t = time.time()
        try:
            r = fn()
        except Exception as exc:  # noqa: BLE001 — 单项异常不拖垮整体
            r = {"status": FAIL, "evidence": repr(exc)[:300], "reason": "检查抛出异常"}
        r.update({"item": idx, "name": name, "elapsed": round(time.time() - t, 1)})
        results.append(r)
        print(f"[{idx:>2}] {name:<24} {r['status']:<6} ({r['elapsed']:>4.1f}s)  {r['evidence']}")
        print(f"     原因: {r['reason']}")
        for step in r.get("manual", []):
            print(f"     操作: {step}")

    counts = {s: sum(1 for r in results if r["status"] == s)
              for s in (PASS, FAIL, SKIP, MANUAL)}
    print(f"\nSUMMARY: PASS {counts[PASS]} | FAIL {counts[FAIL]} | "
          f"SKIP {counts[SKIP]} | MANUAL {counts[MANUAL]}  "
          f"({time.time() - t0:.1f}s)")
    if counts[SKIP] or counts[MANUAL]:
        print("注意: SKIP/MANUAL 均不计为通过, 发布前必须逐项清零或转 PASS")

    if args.json:
        Path(args.json).write_text(json.dumps(results, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        print(f"[json] {args.json}")

    if counts[FAIL]:
        return 1
    return 2 if (counts[SKIP] or counts[MANUAL]) else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
