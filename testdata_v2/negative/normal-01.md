# 误伤率测试样本（不含任何 PII）

本文件用于验证 pii-guard 守护插件的误伤率：正常文本读入模型上下文时，不应出现任何 ⟦PII:...⟧ 占位符。

以下内容刻意包含历史上容易误报的词形（来自 docs/TEST-MATRIX 的负样本经验）：

## 项目背景

本项目内容要求分三个部分：第一部讲架构，第二部讲实施，第三部讲运维。
预算总额约一百二十万元，其中人工成本占比最高。

## 技术要点

1. 使用 Redis 连接池时注意 maxmemory 设置，建议 4GB 起步。
2. 部门之间的数据同步采用每日增量，截止时间每晚 23:00。
3. 所有委员单位需在月底前提交材料，政协办公室汇总。

## 代码示例

```python
def transfer_all(amounts):
    total = sum(amounts)          # 汇总各部门金额
    if total <= 0:
        raise ValueError("金额必须为正")
    return round(total, 2)
```

## 联系与版本

- 文档版本：v1.0.0（2024-06-01 发布）
- 适用系统：Windows Server 2019 / 国产化环境
- 修订记录：2024-08-15 增加第三章；2024-11-20 修订预算口径

以上均不含身份证、手机号、银行卡、人名等个人信息。

## 判定基准（实测 2026-11-06）

- 引擎 analyze 命中数：1（「政协办公室」→ ORGANIZATION，属机构名识别，非个人信息误伤）；
- 验收口径：PERSON / ID_NUMBER / PHONE_NUMBER / BANK_CARD 命中数应为 **0**；
  ORGANIZATION / LOCATION 类命中可接受（机构/地名不是个人信息）。
- pii-guard 端到端读本文件时：不应出现 PERSON 等占位符；ORGANIZATION 占位符出现属预期。
