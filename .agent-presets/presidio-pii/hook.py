"""DSH hook 适配层 (薄 shim) —— DEPRECATED / 在 DSH 0.2.x 中不生效。

本文件仅为兼容旧版 harness 的 preset 入口契约而保留:
  hook.before_llm(prompt, conversation_id) -> str
  hook.after_llm(response, conversation_id) -> str | (str, dict)

⚠ DSH 0.2.x 不挂载 Python hooks, 因此 preset.json 里的 entrypoint/hooks 声明
   永远不会触发。真正生效的脱敏接缝是运行时插件 dsh-pii-guard 的
   `tools/post-execute`（安装位置 <DSH_HOME>/plugins/dsh-pii-guard/lib/index.js）。
   请勿修改本文件来试图改变运行时行为——它不是主防线。

preset.json 本身仍是活配置源: entity_types、config.whitelist_path、
config.custom_rules_path 由 presidio_pii/hooks.py 读取, 设置页会写它。

注意: after_llm 现返回 (text, stats) 元组; DSH 只需文本时取 [0]。
"""
from presidio_pii.hooks import before_llm, after_llm, session_id, get_journal  # noqa: F401
