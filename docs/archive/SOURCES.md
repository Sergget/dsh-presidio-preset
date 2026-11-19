# 模板来源尝试记录

记录语料 v2 的模板获取尝试，供复核与复现。

## 结论

**未获取到可用的空白模板**，改用程序化生成（python-docx / openpyxl / python-pptx）。
尝试日期：2026-10-29。

## 探测记录

| 来源 | 方式 | 结果 |
|---|---|---|
| WebSearch（中/英文查询） | 搜索接口 | 返回"检测到敏感内容"，无法检索 |
| github.com | curl | 连接超时（不可达） |
| arxiv.org | curl | 连接超时（不可达） |
| chinacourt.org | curl | 连接超时（不可达） |
| samr.gov.cn | curl | HTTP 403 |
| www.gov.cn | curl | HTTP 200，政策页为 HTML，无 Office 附件 |
| www.mof.gov.cn | curl | HTTP 200；`/gkml/caizhengwengao/` 页面 16KB，`.doc/.docx/.xls/.xlsx/.ppt/.pptx` 链接数 **0** |
| openstd.samr.gov.cn | curl | HTTP 301（需跳转/在线阅读器） |
| ndrc.gov.cn / stats.gov.cn / moe.gov.cn | curl | 200 / 200 / 302，均为 HTML 政策页 |

## 未采用真实文档的原因

1. **合规**：公开通知、简历、合同、工资表多为真实填写样本，含真人 PII，授权不明；
   下载即把真实个人信息引入测试语料。
2. **可用性**：可达站点不提供空白 Office 模板；模板站（文库类）需登录或付费，不在允许范围。
3. **可复现**：程序化生成可固定种子、可版本化、可精确记录真值。

## 后续

若网络条件变化，可重新尝试：
- `openstd.samr.gov.cn` 的 GB/T 9704-2012 全文（仅作版式参照，不入库）
- 政府网站"表格下载"栏目中的**空白**表格（确认无个人数据后再使用）

任何下载物须记录：URL、许可、抓取时间、sha256，存入 `testdata_v2/sources/`（gitignore）。
