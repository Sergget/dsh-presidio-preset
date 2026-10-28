"""端到端流程测试: hooks 日志、DSH 模拟器、真实文档检测工具。"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from presidio_pii import hooks


@pytest.fixture()
def hook_env(tmp_path, monkeypatch):
    """将 hooks 的存储/日志重定向到临时目录并重置单例。"""
    monkeypatch.setenv("PII_DSH_DB_PATH", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("PII_DSH_LOG_PATH", str(tmp_path / "hook_log.jsonl"))
    hooks.reset_singleton()
    yield tmp_path
    hooks.reset_singleton()


# --------------------------------------------------------------------------- #
# hooks + journal
# --------------------------------------------------------------------------- #
def test_hooks_before_after_logging(hook_env):
    text = "张伟的身份证是110101199003077890"
    red = hooks.before_llm(text, conversation_id="conv-1")
    assert "张伟" not in red and "110101199003077890" not in red
    assert "⟦PII:PERSON:" in red

    restored, stats = hooks.after_llm(f"结果:{red}", conversation_id="conv-1")
    assert stats["n_unrestored"] == 0
    assert "110101199003077890" in restored

    recs = [json.loads(l) for l in
            (hook_env / "hook_log.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["event"] for r in recs] == ["before_llm", "after_llm"]
    assert recs[0]["raw"] == text and recs[0]["transformed"] == red
    assert recs[1]["raw"].startswith("结果:") and recs[1]["n_restored"] >= 1
    assert recs[0]["entities"]  # 实体类型统计非空


def test_hook_session_isolation_via_conversation_id(hook_env):
    red = hooks.before_llm("李明的手机号是13800138000", conversation_id="conv-A")
    # 不同 conversation_id 无映射, 占位符保留
    other, stats = hooks.after_llm(red, conversation_id="conv-B")
    assert other == red and stats["n_restored"] == 0


# --------------------------------------------------------------------------- #
# dsh_sim 模拟器
# --------------------------------------------------------------------------- #
def test_dsh_sim_end_to_end(hook_env):
    import dsh_sim
    log_out = hook_env / "sim.jsonl"
    turns = ["张伟的身份证是110101199003077890,帮我查",
             "再查李明, 手机 13800138000"]
    rc = dsh_sim.main(["--turn", turns[0], "--turn", turns[1],
                       "--conversation-id", "test-conv", "--log-out", str(log_out)])
    assert rc == 0
    recs = [json.loads(l) for l in log_out.read_text(encoding="utf-8").splitlines()]
    stages = [(r["turn_no"], r["stage"]) for r in recs]
    assert stages == [(1, "outgoing"), (1, "incoming"), (2, "outgoing"), (2, "incoming")]
    # outgoing 记录不含明文 PII
    for r in recs:
        if r["stage"] == "outgoing":
            for pii in ["110101199003077890", "13800138000", "张伟", "李明"]:
                assert pii not in r["sent_to_llm"]
    # incoming 记录占位符清零
    assert all(r["placeholders_left"] == 0 for r in recs if r["stage"] == "incoming")


# --------------------------------------------------------------------------- #
# standalone_check 真实文档检测
# --------------------------------------------------------------------------- #
def test_standalone_check_docx_roundtrip(hook_env, tmp_path):
    import docx
    import standalone_check

    src = tmp_path / "t.docx"
    d = docx.Document()
    d.add_paragraph("客户张伟, 身份证 110101199003077890。")
    d.add_paragraph("无敏感信息的普通段落。")
    d.save(str(src))

    report_path = tmp_path / "report.json"
    rc = standalone_check.main([str(src), "--report", str(report_path)])
    assert rc == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["all_pass"] is True
    r = report["results"][0]
    assert r["n_replaced"] == 2
    assert r["leaked_pii"] == []
    assert all(u["roundtrip_equal"] and u["no_placeholder_left"]
               for u in r["unit_results"])


def test_standalone_check_missing_file(hook_env, tmp_path):
    import standalone_check
    report_path = tmp_path / "report.json"
    rc = standalone_check.main([str(tmp_path / "nope.txt"),
                                "--report", str(report_path)])
    assert rc == 1
