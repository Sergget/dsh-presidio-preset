"""DSH 流程模拟器: 在无 DSH 环境下模拟完整多轮对话, 并记录结构化流程日志。

每轮流程:
  用户输入 -> hooks.before_llm (脱敏, 发出) -> mock LLM (保持占位符生成回复, 接收)
          -> hooks.after_llm (还原) -> 用户可见文本

日志: 每轮产生两条结构化记录 (outgoing / incoming), 写入
  .pii_presidio_store/sim_<conversation_id>.jsonl
同时 hooks 自身会写 hook_log.jsonl (引擎级日志)。

用法:
  python tools/dsh_sim.py --turn "张伟的身份证是110101199003077890,帮我查" \
                          --turn "再查一下他的手机号 13800138000" \
                          [--conversation-id demo] [--log-out PATH.jsonl]
退出码: 全部占位符成功还原=0, 否则=1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from presidio_pii import hooks
from presidio_pii.journal import JsonlJournal

_PH = re.compile(r"⟦PII:[A-Z_]+:\d{4}⟧")


def mock_llm(redacted_text: str) -> str:
    """模拟 LLM 行为: 像真实模型一样在回复中原样引用占位符 (可能重排/复述)。"""
    phs = list(dict.fromkeys(_PH.findall(redacted_text)))
    if not phs:
        return f"[模拟LLM] 已收到: {redacted_text} (未涉及受保护实体)"
    first = phs[0]
    mention = "、".join(phs)
    return (f"[模拟LLM] 已完成处理。查询对象 {first} 的资料核验通过; "
            f"本次请求共涉及受保护实体: {mention}。"
            f"提示: {first} 的相关结果已生成。")


def run_turn(journal: JsonlJournal, turn_no: int, user_text: str,
             conversation_id: str) -> dict:
    # ---- 发出方向 ----
    redacted = hooks.before_llm(user_text, conversation_id,
                                doc_id=f"turn{turn_no}")
    journal.record("turn", turn_no=turn_no, stage="outgoing",
                   conversation_id=conversation_id,
                   raw_prompt=user_text, sent_to_llm=redacted,
                   n_redacted=len(_PH.findall(redacted)))

    # ---- 模拟 LLM ----
    llm_response = mock_llm(redacted)

    # ---- 接收方向 ----
    restored, stats = hooks.after_llm(llm_response, conversation_id,
                                      doc_id=f"turn{turn_no}")
    placeholders_left = len(_PH.findall(restored))
    journal.record("turn", turn_no=turn_no, stage="incoming",
                   conversation_id=conversation_id,
                   llm_response=llm_response, restored=restored,
                   n_restored=stats["n_restored"],
                   n_unrestored=stats["n_unrestored"],
                   placeholders_left=placeholders_left)

    return {
        "turn": turn_no,
        "sent_to_llm": redacted,
        "llm_response": llm_response,
        "restored": restored,
        "placeholders_left": placeholders_left,
        "ok": placeholders_left == 0 and stats["n_unrestored"] == 0,
    }


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser("dsh_sim: DSH 流程模拟器")
    ap.add_argument("--turn", dest="turns", action="append", default=[],
                    help="一轮用户输入, 可重复")
    ap.add_argument("--conversation-id", default="sim-demo")
    ap.add_argument("--log-out", help="流程日志输出路径 "
                    "(默认 .pii_presidio_store/sim_<conversation-id>.jsonl)")
    args = ap.parse_args(argv)
    if not args.turns:
        ap.error("至少提供一个 --turn")

    log_path = (Path(args.log_out) if args.log_out else
                _REPO_ROOT / ".pii_presidio_store" / f"sim_{args.conversation_id}.jsonl")
    journal = JsonlJournal(log_path)

    print(f"conversation_id={args.conversation_id}  日志: {log_path}\n")
    results = []
    for i, text in enumerate(args.turns, 1):
        r = run_turn(journal, i, text, args.conversation_id)
        results.append(r)
        print(f"── 第 {i} 轮 {'PASS' if r['ok'] else 'FAIL'} ──")
        print(f"  用户输入 : {text}")
        print(f"  发出(LLM): {r['sent_to_llm']}")
        print(f"  LLM 回复 : {r['llm_response']}")
        print(f"  还原输出 : {r['restored']}\n")

    ok = all(r["ok"] for r in results)
    print("[result] ALL TURNS PASS" if ok else "[result] 存在未还原占位符")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
