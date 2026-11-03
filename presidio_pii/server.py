"""PII 脱敏常驻服务（stdio JSON 行协议）。

供 dsh-pii-guard Node 插件作为子进程调用：启动一次，词表加载一次，
之后每次请求走 stdin/stdout 的 JSON 行协议，单次 <100ms。

协议（每行一个 JSON）:
  请求: {"id": "r1", "text": "...", "sid": "s1"}
  响应: {"id": "r1", "redacted": "...", "n": 3}
  响应(错误): {"id": "r1", "error": "..."}

用法:
  echo '{"id":"1","text":"张伟的身份证是110101199003077890"}' | python presidio_pii/server.py
"""
from __future__ import annotations

import json
import sys

try:
    from .hooks import before_llm
except ImportError:  # 直接以脚本运行时无包上下文
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from presidio_pii.hooks import before_llm


def _serve() -> int:
    """逐行读 stdin，逐行写 stdout。任何单行错误不中断服务。"""
    # 协议强制 UTF-8: 宿主(Node spawn)与管道测试都必须以 UTF-8 读写
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    # 首条请求到达前不初始化引擎（lazy）；由 before_llm 内部单例完成
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        rid = None
        try:
            req = json.loads(line)
            rid = req.get("id")
            text = req.get("text", "")
            sid = req.get("sid", "svc")
            redacted = before_llm(text, sid, doc_id="svc")
            _emit({"id": rid, "redacted": redacted, "n": redacted.count("⟦PII:")})
        except Exception as exc:  # noqa: BLE001 — 单行错误不中断服务
            _emit({"id": rid, "error": repr(exc)})
    return 0


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    # stderr 留给告警；stdout 只走协议
    sys.exit(_serve())
