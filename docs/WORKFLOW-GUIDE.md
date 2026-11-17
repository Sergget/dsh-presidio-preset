
# 规范化工作流：处理本地文件/网页
对于需要读取的本地文件（特别是 docx/xlsx）或网页：
1. 优先使用内置 read 工具：它自带脱敏+重渲染链路。
2. 若必须手动解析：
   a. 使用脚本工具将内容转换为 Markdown：`python -m pii_guard.utils.to_md <file> > <file>.md`。
   b. 读取转换后的 MD 文件，此时 PII 已被脱敏。
   c. 不要直接用 pwsh/python 原始解析，以免产生 GBK 乱码或绕过脱敏。
