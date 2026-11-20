"""生成 Node 引擎等价性 golden 样本（Python 强制无 jieba fallback 模式）。

输出：tests/node/golden.json —— 供 engine-equivalence.mjs 逐条比对。
每条样本用独立 session + 独立 db，保证序号从 0001 起，输出确定。
"""
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# 强制无 jieba，对齐 Node 基准
from presidio_pii import segmentation
segmentation._HAS_JIEBA = False

from presidio_pii.engine import PresidioPIIEngine

SAMPLES = [
    # 数字类
    ("手机13800138000联系", None),
    ("发送到 a.b@example.com 即可", None),
    ("身份证号 110101199003077890 请核对", None),
    ("证件号 110101199003077899", None),           # 校验位错，降级保留
    ("证件号 11010119900307789X", None),           # X 校验位
    ("统一代码 91110000123456787H 已登记", None),
    ("办公电话 0551-64845129 工作日联系", None),
    ("服务器 IP 192.168.1.100 和 8.8.8.8", None),
    ("MAC 地址 00:1A:2B:3C:4D:5E", None),
    # 归一化变体
    ("手机号 １３８００１３８０００ 请查收", None),     # 全角
    ("手机 138 0013 8000 谢谢", None),              # 数字间空格
    ("身份证 110101-19900307-7890 已登记", None),   # 连字符插值
    ("卡号 6222 0211 1111 1111 234 有效", None),    # 卡号插值
    # 人名 / 边界
    ("李明在开会", None),
    ("电话留给李飞", None),
    ("张伟是中国人", None),
    ("项目负责人：刘志强；", None),
    ("由张三负责该项目的实施", None),
    ("联系人：高鹏", None),
    ("马晓东、宋佳参加评审", None),
    ("2名学生荣获宋庆龄奖学金", None),
    ("再查李明, 手机 13800138000", None),
    # 地点 / 机构 / 职务
    ("张伟是中国银行北京市朝阳区支行行长", None),
    ("合肥市政协信息化平台项目", None),
    ("参照安徽省数据资源管理局的做法", None),
    ("他担任总经理一职", None),
    ("地址：成都市武侯区天府大道北段1700号", None),
    ("重庆市渝北区经纪有限公司", None),
    # 精度闸门（应零命中）
    ("内容要求如下", None),
    ("本项目分为第一部", None),
    ("所有部门都要参与", None),
    ("名单：身份证、手机号、银行卡、人名等个人信息。", None),
    ("我校学生在比赛中荣获佳绩", None),
    ("全市共有德育工作者8300余人", None),
    ("阳光总在风雨后", None),
    ("今天天气很好, 我们去公园散步吧。", None),
    # 白名单
    ("张伟和李明开会", ["张伟"]),
    ("合肥市数据资源局由王建国负责", ["合肥市数据资源局"]),
    ("李明的手机号是13800138000", ["张伟"]),
    # 多实体混合
    ("张伟, 身份证 110101199003077890, 手机 13800138000, 邮箱 a.b@bank.com", None),
    ("联系人李明 13800138000 住北京市朝阳区", None),
]


def main():
    golden = []
    with tempfile.TemporaryDirectory() as td:
        for i, (text, whitelist) in enumerate(SAMPLES, 1):
            db = str(Path(td) / f"g{i}.db")
            eng = PresidioPIIEngine(db_path=db, whitelist=whitelist)
            sid = eng.registry.create_session()
            rd = eng.redact(text, sid, "golden")
            golden.append({
                "id": i,
                "text": text,
                "whitelist": whitelist or [],
                "redacted": rd.text,
                "n": rd.n_replaced,
                "map": rd.restored,
                "entity_counts": rd.entity_counts,
                "n_whitelisted": rd.n_whitelisted,
            })
            eng.registry.close()
    out = REPO / "tests" / "node" / "golden.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(golden, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"GOLDEN_WRITTEN {out} count={len(golden)}")


if __name__ == "__main__":
    main()
