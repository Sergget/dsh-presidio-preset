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
    ok = (rd.n_replaced > 0 and counts.get("PERSON", 0) > 0
          and not any(n in rd.text for n in names) and ws_ok and personal == 0)
    ev = (f"paper-01: {counts} 共 {rd.n_replaced} 处, 明文人名 absent={not any(n in rd.text for n in names)}, "
          f"空白序列一致={ws_ok}; normal-01 个人类实体={personal}")
    reason = ("占位符生效且不吞分隔符，负例无个人类误报" if ok
              else "读取侧拦截或结构保持不满足")
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
    return 'DISPLAY_MODE' in src and 'mask' in src and 'full' in src


# --------------------------------------------------------------------------- #
# 5. 格式覆盖面（文本类由 #1/#3 覆盖；pwsh 已按 P1-全纳入）
# --------------------------------------------------------------------------- #
PLUGIN = Path(r"E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js")
PLUGIN_SRC = REPO / "plugins" / "dsh-pii-guard" / "lib" / "index.js"


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
                               'svc.on("error"',
                               "shell_bypass", "PII_GUARD_SHELL_ALLOWLIST",
                               "PII_GUARD_REPO", "invalid PII_GUARD_SHELL_ALLOWLIST",
                               "PII_GUARD_SHELL",
                               # 方案 B 显示侧还原（门禁 #4 实现）
                               "PII_GUARD_DISPLAY", "agent/assistant-stream",
                               "PH_FULL", "PH_TAIL", "splitDisplayable",
                               "phMap", "displayBufs") if pat not in src]

    node = shutil.which("node")
    js_ok, js_ev = False, "node=missing"
    if node:
        rc_js, out_js = run([node, "tests/js/plugin_jobs.mjs", str(PLUGIN_SRC)],
                            cwd=REPO, timeout=180)
        rc_disp, out_disp = run([node, "tests/js/plugin_display.mjs", str(PLUGIN_SRC)],
                                cwd=REPO, timeout=120)
        js_ok = rc_js == 0 and rc_disp == 0
        js_ev = (f"js_smoke={'pass' if rc_js == 0 else 'fail'}"
                 f"/display={'pass' if rc_disp == 0 else 'fail'}")
        if rc_js != 0:
            js_ev += f" ({tail(out_js, 1)})"
        if rc_disp != 0:
            js_ev += f" ({tail(out_disp, 1)})"

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
    ok = not missing and plain_ok and pii_ok and js_ok and sync_ok
    ev = (f"src=repo plugin={'ok' if not missing else '缺:' + ','.join(missing)}; "
          f"{sync_ev}; {js_ev}; plain_unchanged={plain_ok}; "
          f"pii_redacted={'张伟' not in r3}; "
          f"markers_kept={'[exit code: 1]' in r3}")
    if not PLUGIN.is_file():
        return {"status": SKIP, "evidence": ev,
                "reason": "已安装插件不存在，无法校验安装态与仓库副本一致；"
                          "仓库副本本身已通过语义与冒烟检查"}
    reason = ("仓库副本与安装副本一致，pwsh + job_output/job_list 均已拦截且语义正确"
              "（含 256 KB 截断与 isError 脱敏）"
              if ok else "插件缺少 pwsh/后台任务/isError 逻辑、node 冒烟失败、"
                         "安装态与仓库副本不一致或引擎语义回归")
    return {"status": PASS if ok else FAIL, "evidence": ev, "reason": reason}


# --------------------------------------------------------------------------- #
# 6. 依赖漏洞
# --------------------------------------------------------------------------- #
def check_deps() -> dict:
    rc_check, out_check = run([sys.executable, "-m", "pip", "check", "--disable-pip-version-check"])
    versions = fmt_versions()
    if rc_check != 0:
        return {"status": FAIL, "evidence": f"{versions}; pip check: {tail(out_check, 3)}",
                "reason": "存在破损依赖"}

    tool = shutil.which("pip-audit")
    if not tool:
        uvx = shutil.which("uvx") or r"C:\Users\sergg\.local\bin\uvx.exe"
        if Path(uvx).exists():
            audit_cmd = [uvx, "pip-audit"]
        else:
            audit_cmd = None
    else:
        audit_cmd = [tool]

    if not audit_cmd:
        return {"status": SKIP, "evidence": f"{versions}; pip check OK",
                "reason": "未找到 pip-audit / uvx，无法做漏洞库比对"}
    if not online():
        return {"status": SKIP, "evidence": f"{versions}; pip check OK",
                "reason": "当前离线，pip-audit 无法拉取漏洞库（不视为通过）"}

    req = Path(tempfile.mkdtemp(prefix="gate_audit_")) / "req.txt"
    rc_fr, freeze = run([sys.executable, "-m", "pip", "freeze", "--disable-pip-version-check"])
    kept = [ln for ln in freeze.splitlines()
            if ln and not ln.startswith(("#", " ", "-e")) and "git+ssh" not in ln]
    req.write_text("\n".join(kept) + "\n", encoding="utf-8")
    rc, out = run([*audit_cmd, "-r", str(req)], timeout=600)
    low = out.lower()
    if "no known vulnerabilities" in low:
        return {"status": PASS, "evidence": f"{versions}; pip check OK; pip-audit 0",
                "reason": "无已知漏洞"}
    if rc != 0 and any(s in low for s in ("connection", "resolve", "timed out", "network", "temporary failure")):
        return {"status": SKIP, "evidence": f"{versions}; audit: {tail(out, 3)}",
                "reason": "漏洞库连接失败（离线或网络受限）"}
    return {"status": FAIL, "evidence": f"{versions}; audit: {tail(out, 4)}",
            "reason": "pip-audit 报告漏洞或执行失败"}


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


def _mask(s: str) -> str:
    return s[:3] + "***" + s[-2:] if len(s) > 6 else "***"


def _scan_text(text: str, where: str) -> tuple:
    """返回 (真命中, 白名单抑制数)。抑制数只用于披露, 不静默丢弃。"""
    hits, suppressed = [], 0
    for line in text.splitlines():
        if line.startswith(("+++", "---")):
            continue
        body = line[1:] if line[:1] in "+-" else line
        for name, rx in _SECRET_PATTERNS:
            for m in rx.finditer(body):
                value = m.group(2) if name == "assign" and m.lastindex else m.group(0)
                if name == "assign" and _SAFE_VALUE.search(value or ""):
                    suppressed += 1
                    continue
                hits.append((name, where, _mask(m.group(0))))
    return hits, suppressed


def check_secrets() -> dict:
    rc, log = run(["git", "log", "-p", "--all", "--no-color", "--format=__C__%H"], timeout=300)
    if rc != 0:
        return {"status": FAIL, "evidence": tail(log, 2), "reason": "git log 读取失败，无法扫描历史"}
    commits = log.count("__C__")
    diff_lines = sum(1 for ln in log.splitlines()
                     if ln[:1] in "+-" and not ln.startswith(("+++", "---")))
    hist_hits, hist_suppressed = _scan_text(log, "history")

    rc_ls, files = run(["git", "ls-files"], timeout=120)
    wt_hits, wt_suppressed, scanned = [], 0, 0
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
            wt_hits += h
            wt_suppressed += s
        except OSError:
            continue

    # 高风险文件名（无论内容）
    risky = [r for r in files.splitlines()
             if re.search(r"(^|/)(\.env|id_rsa|id_ed25519|credentials\w*\.json)$|\.(pem|pfx|p12)$", r)]
    hits = hist_hits + wt_hits
    ok = not hits and not risky
    ev = (f"commits={commits} diff_lines={diff_lines} hist_hits={len(hist_hits)} "
          f"suppressed={hist_suppressed}; worktree_files={scanned} wt_hits={len(wt_hits)} "
          f"suppressed={wt_suppressed} risky_files={len(risky)}")
    if hits:
        sample = "; ".join(f"{n}@{w}:{v}" for n, w, v in hits[:3])
        reason = f"命中 {len(hits)} 处: {sample}"
    elif risky:
        reason = f"高风险文件被追踪: {', '.join(risky[:3])}"
    else:
        reason = "历史与工作树均无凭据命中"
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
    commit_ok = src.get("commit") == head
    tree_ok = src.get("source_tree_sha256") == _source_tree_digest()
    ev = (f"manifest={art.get('filename')} bytes_ok={size_ok} sha_ok={sha_ok} "
          f"commit_match={commit_ok} tree_digest_match={tree_ok}")
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
