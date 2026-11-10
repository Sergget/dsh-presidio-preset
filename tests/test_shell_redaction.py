"""shell（pwsh）输出脱敏的引擎级语义回归。

对应 docs/DECISION-shell-redaction.md 第 8 节验收判据：
- §8.A 含 PII 的 shell 输出必须脱敏，且结构标记（[stderr]、[exit code]、
  截断提示、diff 前缀、ANSI 转义）与空白布局不被破坏；
- §8.B 不含 PII 的日常命令输出必须逐字节不变。

插件层（JS）的文本性判定与逃生开关由门禁脚本 #5 做源码级断言，
进程内 E2E 属 MANUAL（需重启 DSH）。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.engine import PresidioPIIEngine  # noqa: E402


@pytest.fixture()
def engine(tmp_path):
    return PresidioPIIEngine(db_path=tmp_path / "test.db")


def redact(engine, text):
    sid = engine.registry.create_session()
    try:
        return engine.redact(text, sid, "shell").text
    finally:
        engine.registry.delete_session(sid)


# --------------------------------------------------------------------------- #
# §8.B 不含 PII 的日常命令输出：脱敏后必须逐字节相同
# --------------------------------------------------------------------------- #
PLAIN_OUTPUTS = [
    # git status / log / diff
    "On branch master\nnothing to commit, working tree clean\n",
    "ea22be4 fix detector whitespace\nea22be3 bump pillow\n",
    "diff --git a/x.py b/x.py\n@@ -1,2 +1,2 @@\n-old\n+new\n",
    # Get-ChildItem 表格
    "Mode                 LastWriteTime         Length Name\n"
    "----                 -------------         ------ ----\n"
    "-a----        2026/11/6     10:29           4396 index.js\n",
    # pytest / pip / node
    "132 passed in 15.27s\n",
    "pillow         13.0.0\ncertifi        2026.10.18\n",
    "v22.11.0\n",
    # docker ps（无端口映射，避免 0.0.0.0 被当作 IP 实体）
    "CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS   NAMES\n"
    "a1b2c3d4e5f6   redis     \"redis\"   2 days    Up 2d             cache\n",
    # Get-Process 表格
    "Handles  NPM(K)    PM(K)  WS(K)   CPU(s)  Id  ProcessName\n"
    "    200      12    40960  20480     1.25  42  python\n",
    # 无 PII 的 JSON
    '{"exitCode": 0, "items": [1, 2, 3], "name": "build"}\n',
    # 进度条
    "[=========>     ] 45% 138/300 12.3MB/s\n",
    # 13 位毫秒时间戳（历史误报）
    "epoch=1699289554123 retries=3\n",
    # UUID（历史局部替换缺陷）
    "request_id=550e8400-e29b-41d4-a716-446655440000\n",
    # pwsh 错误文本（路径无 PII）
    "Get-Content : Cannot find path 'E:\\tmp\\missing.txt'\n[exit code: 1]\n",
]


@pytest.mark.parametrize("text", PLAIN_OUTPUTS)
def test_plain_shell_output_is_byte_identical(engine, text):
    assert redact(engine, text) == text


# --------------------------------------------------------------------------- #
# §8.A 含 PII 的输出：脱敏 + 结构保持
# --------------------------------------------------------------------------- #
def test_pii_in_stdout_is_redacted(engine):
    out = redact(engine, "负责人：张伟，手机 13800138000\n")
    assert "张伟" not in out and "13800138000" not in out
    assert "⟦PII:PERSON:" in out and "⟦PII:PHONE_NUMBER:" in out
    assert out.endswith("\n")


def test_pii_in_stderr_section_redacted_markers_kept(engine):
    text = "ok\n[stderr]\nWrite-Error: 张伟 13800138000\n[exit code: 1]\n"
    out = redact(engine, text)
    assert "张伟" not in out and "13800138000" not in out
    assert "[stderr]\n" in out and "[exit code: 1]" in out


def test_nonzero_exit_marker_preserved(engine):
    text = "type secret.txt 失败\n[exit code: 2]\n"
    out = redact(engine, "张伟\n[exit code: 2]\n")
    assert "张伟" not in out
    assert "[exit code: 2]" in out
    assert text == redact(engine, text)


def test_truncation_marker_preserved(engine):
    marker = "[output truncated; full output: E:\\tmp\\spill_64000.txt]"
    text = f"联系人 张伟\n{marker}\n"
    out = redact(engine, text)
    assert "张伟" not in out
    assert marker in out


def test_json_with_pii_stays_parseable(engine):
    text = '{"user":"张伟","phone":"13800138000"}\n'
    out = redact(engine, text)
    data = json.loads(out)
    assert data["user"].startswith("⟦PII:") and data["phone"].startswith("⟦PII:")
    assert "张伟" not in out and "13800138000" not in out


def test_ansi_escapes_preserved(engine):
    text = "\x1b[31m13800138000\x1b[0m\n"
    out = redact(engine, text)
    assert "\x1b[31m" in out and "\x1b[0m" in out
    assert "13800138000" not in out


def test_table_whitespace_layout_preserved(engine):
    text = "张伟           13800138000\n李明  13900139000\n"
    out = redact(engine, text)
    assert out.count(" ") == text.count(" ")
    assert out.count("\n") == text.count("\n")
    assert "张伟" not in out and "李明" not in out


def test_diff_lines_keep_prefix_and_count(engine):
    text = "+ 联系人: 张伟<zhang@example.com>\n- 联系人: 无\n"
    out = redact(engine, text)
    lines = out.splitlines()
    assert lines[0].startswith("+ ") and lines[1].startswith("- ")
    assert len(lines) == 2
    assert "张伟" not in out and "zhang@example.com" not in out


def test_no_placeholder_leakage_through_restore(engine):
    """占位符可还原：shell 输出里的 PII 走同一映射，restore 后逐字一致。"""
    text = "负责人：张伟，手机 13800138000\n"
    sid = engine.registry.create_session()
    try:
        rd = engine.redact(text, sid, "shell")
        rs = engine.restore(rd.text, sid, "shell")
        assert rs.text == text
    finally:
        engine.registry.delete_session(sid)
