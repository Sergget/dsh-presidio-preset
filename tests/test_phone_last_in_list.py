"""回归测试: 列表最后一项的裸手机号不得漏检。

实测缺陷: 「28 人名 + 3 手机号」文档 redact 后只替换 2 个 PHONE_NUMBER,
列表末尾的 153 号裸漏并进入模型上下文。根因见 presidio_pii/normalize.py:
数字之间的单个分隔符 (含空格/换行) 被无条件吞噬, 末号与其后以数字开头的
日常文本 ("2024 年汇总" / 换行后的页码) 粘连成超长数字串, 手机号正则的
(?!\\d) 右边界随即失效。前两个号码后面是分隔符 + 人名, 边界完好, 故正常替换。

全部为合成数据, 不含任何真实 PII。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.engine import PresidioPIIEngine  # noqa: E402

N1, N2, N3 = "13800138000", "13900139000", "15385322046"
PHONES = (N1, N2, N3)


@pytest.fixture()
def engine(tmp_path):
    return PresidioPIIEngine(db_path=tmp_path / "test.db", custom_rules=[])


# --------------------------------------------------------------------------- #
# 复现: 单行内「多个 人名+手机号、最后一个是 153 号」
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    # 斜杠分隔 + 末号后换行 + 下一行以数字开头 (实测 28 人 + 2 号的形态)
    f"参会人员：张三 {N1} / 李四 {N2} / 王五 {N3}\n2024 年 12 月汇总，共 28 人\n",
    # 单行: 末号后是「空格 + 数字开头的日常文本」
    f"张三 {N1} / 李四 {N2} / 王五 {N3} 2024 年汇总",
    # 空格分隔版本
    f"张三 {N1} 李四 {N2} 王五 {N3} 2024 年汇总",
    # 末尾裸换行/句末 (边界回归: 修复不得破坏这三种已通过的形态)
    f"张三 {N1} / 李四 {N2} / 王五 {N3}",
    f"张三 {N1} / 李四 {N2} / 王五 {N3}\n",
    f"张三 {N1} 李四 {N2} 王五 {N3}。",
])
def test_last_phone_in_list_is_redacted(engine, text):
    """三个号码必须全部替换, 末号不得残留明文。"""
    sid = engine.registry.create_session()
    rd = engine.redact(text, sid, "last-phone")
    assert rd.entity_counts.get("PHONE_NUMBER") == 3, (text, rd.entity_counts)
    for num in PHONES:
        assert num not in rd.text, (num, rd.text)
        assert num in rd.restored.values(), (num, rd.restored)
    # 换出来的占位符仍可无损还原
    assert engine.restore(rd.text, sid, "last-phone").text == text


def test_last_phone_28_people_document(engine):
    """完整合成文档: 28 人名 + 3 号, 末号裸漏曾导致 28 PERSON + 2 PHONE。"""
    people = ["张三", "李四", "王五", "赵六", "孙七", "周八", "吴九", "郑十",
              "钱一", "陈二", "褚三", "卫四", "蒋五", "沈六", "韩七", "杨八",
              "朱九", "秦十", "尤一", "许二", "何三", "吕四", "施五", "张六",
              "孔七", "曹八", "严九", "王某某"]
    text = ("参会人员（28 人）：\n" + "、".join(people[:27]) + "\n"
            + f"联系方式：{people[0]} {N1} / {people[1]} {N2} / {people[27]} {N3}\n"
            + "2024 年 12 月汇总，共 28 人\n")
    sid = engine.registry.create_session()
    rd = engine.redact(text, sid, "doc28")
    assert rd.entity_counts.get("PHONE_NUMBER") == 3, rd.entity_counts
    for num in PHONES:
        assert num not in rd.text, (num, rd.text)
    assert engine.restore(rd.text, sid, "doc28").text == text


# --------------------------------------------------------------------------- #
# 精度: 无 PII 的日常数字串不得误报
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    "epoch_ms=1699289554123",                                  # 13 位毫秒时间戳
    "ts 1762400000000 end",                                    # 13 位时间戳 + 空格
    "id=550e8400-e29b-41d4-a716-446655440000",                  # UUID
    "commit a3f0c9b2e1d8a7c6f5b4e3d2c1b0a9f8e7d6c5b4",        # 40 位 hex
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "const TIMEOUT_MS = 30000; const MAX_RETRY = 3;",            # 代码数字常量
    "ORDER_SEQ = 12345678901; VERSION = 1.38.0;",                # 11 位订单号/版本号
    "订单号 12345678901 已发货",                                  # 普通长订单号
])
def test_everyday_numbers_are_not_pii(engine, text):
    """修复不得放宽成「任意 11 位数字都是手机号」。"""
    rd = engine.redact(text, "no-pii", "t")
    assert rd.n_replaced == 0, (text, rd.entity_counts)
    assert rd.text == text
