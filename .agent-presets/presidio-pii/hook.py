"""DSH hook 适配层 (薄 shim)。

实际实现位于 presidio_pii.hooks, 此文件保持 DSH preset 的入口契约:
  hook.before_llm(prompt, conversation_id) -> str
  hook.after_llm(response, conversation_id) -> str | (str, dict)

注意: after_llm 现返回 (text, stats) 元组; DSH 只需文本时取 [0]。
"""
from presidio_pii.hooks import before_llm, after_llm, session_id, get_journal  # noqa: F401
