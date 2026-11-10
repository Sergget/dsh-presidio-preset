"""PII 脱敏常驻服务（stdio JSON 行协议）。

供 dsh-pii-guard Node 插件作为子进程调用：启动一次，词表加载一次，
之后每次请求走 stdin/stdout 的 JSON 行协议，单次 <100ms。

协议（每行一个 JSON）:
  请求(redact, 缺省): {"id": "r1", "text": "...", "sid": "s1"}
  响应: {"id": "r1", "redacted": "...", "n": 3}
  请求(restore, 方案B显示侧): {"id": "r2", "op": "restore", "text": "...", "sid": "s1", "mode": "full|mask"}
  响应: {"id": "r2", "restored": "...", "n": 2}
  响应(错误): {"id": "r1", "error": "..."}

restore 说明: 仅供显示侧把占位符还原为原文（full）或打码（mask，保留首字符
+ '*' 填充，Python 端完成，原文不过 Node 侧）。结果只用于 GUI 显示，
不回模型上下文。打码规则: 首尾各保留 1 字符（长度>4 时），中间以 '*' 填充；
长度<=4 保留首字符 + '*'*(len-1)；邮箱/URL 类整体打码本地段。

用法:
  echo '{"id":"1","text":"⟦PII:PERSON:0028⟧的身份证是⟦PII:ID_NUMBER:0001⟧"}' | python presidio_pii/server.py
"""
from __future__ import annotations

import json
import re
import sys

try:
    from . import hooks as _hooks
    from .hooks import before_llm
except ImportError:  # 直接以脚本运行时无包上下文
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from presidio_pii import hooks as _hooks
    from presidio_pii.hooks import before_llm

_PH = re.compile(r"⟦PII:([A-Z_]+):(\d+)⟧")


def _mask_value(value: str, etype: str) -> str:
    """显示打码: 保留少量首尾字符, 其余以 '*' 填充。"""
    v = value
    if etype == "EMAIL_ADDRESS" and "@" in v:
        local, _, domain = v.partition("@")
        head = local[:1] if local else "*"
        return f"{head}***@{domain}" if domain else head + "***"
    if len(v) <= 4:
        return v[:1] + "*" * (len(v) - 1)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


def _restore_display(text: str, sid: str, mode: str) -> tuple[str, int]:
    """占位符 → 显示文本。mode=full 还原原文; mode=mask 打码。

    返回 (显示文本, 替换数)。查不到映射的占位符原样保留并在计数中不计入。
    键口径与 before_llm 一致: hooks.session_id() 会把传入 id 哈希为映射库键。
    """
    engine = _hooks._get_engine()  # 复用单例引擎, 含同一映射库
    key = _hooks.session_id(sid)
    mapping = engine.registry.get_restore_map(key, "svc")
    rs = engine.restore(text, key, "svc", mapping=mapping)
    n = len(rs.restored)
    if mode == "mask":
        by_ph = mapping if isinstance(mapping, dict) else \
            {m["placeholder"]: m["original"] for m in mapping}

        def _sub(m: "re.Match[str]") -> str:
            orig = by_ph.get(m.group(0))
            return _mask_value(orig, m.group(1)) if orig else m.group(0)

        display = _PH.sub(_sub, rs.text)
    else:
        display = rs.text
    return display, n


def _serve() -> int:
    """逐行读 stdin，逐行写 stdout。任何单行错误不中断服务。"""
    # 协议强制 UTF-8: 宿主(Node spawn)与管道测试都必须以 UTF-8 读写
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    # 首条请求到达前不初始化引擎（lazy）；由 hooks 内部单例完成
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        rid = None
        try:
            req = json.loads(line)
            rid = req.get("id")
            op = req.get("op", "redact")
            text = req.get("text", "")
            sid = req.get("sid", "svc")
            if op == "restore":
                mode = req.get("mode", "full")
                if mode not in ("full", "mask"):
                    raise ValueError(f"bad mode: {mode!r}")
                display, n = _restore_display(text, sid, mode)
                _emit({"id": rid, "restored": display, "n": n})
            else:
                engine = _hooks._get_engine()
                skey = _hooks.session_id(sid)  # 与 before_llm 的映射键一致
                # 先取脱敏前已存在的映射快照, redact 后 diff 出本次新增
                before = engine.registry.get_restore_map(skey, "svc")
                before_keys = set(before if isinstance(before, dict) else
                                  (m["placeholder"] for m in before))
                redacted = before_llm(text, sid, doc_id="svc")
                after = engine.registry.get_restore_map(skey, "svc")
                by_ph = after if isinstance(after, dict) else \
                    {m["placeholder"]: m["original"] for m in after}
                mode = (req.get("mode") or "full").lower()
                ph_map = {}
                for ph, orig in by_ph.items():
                    if ph in before_keys:
                        continue  # 只增量下发新映射, 控制响应体积
                    ph_map[ph] = _mask_value(orig, ph.strip("⟦⟧").split(":")[1]) \
                        if mode == "mask" else orig
                _emit({"id": rid, "redacted": redacted,
                       "n": redacted.count("⟦PII:"), "map": ph_map})
        except Exception as exc:  # noqa: BLE001 — 单行错误不中断服务
            _emit({"id": rid, "error": repr(exc)})
    return 0


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    # stderr 留给告警；stdout 只走协议
    sys.exit(_serve())
