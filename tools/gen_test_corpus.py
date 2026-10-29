"""生成混入合成 PII 的测试文档集。

把国家级/省部级/市级/县级单位、公司、公司简称、人名、地址、身份证号、手机号、
邮箱、统一社会信用代码混入一份基础 docx, 再切分成多个小 docx, 并输出真值清单
(manifest.json), 供脱敏召回/精度评估使用。

所有生成内容均为虚构数据; 身份证号按 GB/T 11643 规则生成有效校验位。

用法:
  python tools/gen_test_corpus.py --base 报告.docx --out testdata/
  python tools/gen_test_corpus.py --base 报告.docx --mapping 报告.docx.mapping.csv \\
      --out testdata/ --parts 12 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

import docx

# --------------------------------------------------------------------------- #
# 合成数据池 (全部虚构)
# --------------------------------------------------------------------------- #
NATIONAL_ORGS = [
    "国家发展和改革委员会", "工业和信息化部", "国家互联网信息办公室",
    "财政部", "教育部", "国家数据局", "国务院办公厅", "公安部",
    "国家统计局", "国家税务总局",
]
PROVINCE_ORGS = [
    "安徽省数据资源管理局", "安徽省发展和改革委员会", "江苏省工业和信息化厅",
    "浙江省财政厅", "广东省政务服务数据管理局", "山东省大数据局",
]
CITY_ORGS = [
    "合肥市数据资源局", "南京市大数据管理局", "苏州市行政审批局",
    "杭州市数据资源管理局", "芜湖市信息中心", "宁波市大数据发展管理局",
]
COUNTY_ORGS = [
    "肥东县数据资源局", "长丰县财政局", "庐江县发展和改革委员会",
    "无为市信息中心", "巢湖市政务服务管理局", "桐城市数据资源局",
]
COMPANIES = [
    "安徽智数科技有限公司", "合肥云启信息技术有限公司",
    "中科云谷（合肥）数据科技有限公司", "皖信通网络科技有限公司",
    "安徽数安信息技术股份有限公司", "合肥联创软件有限公司",
]
# 公司简称: 现实里最难识别的一类, 单独标记为 hard
COMPANY_ABBR = {
    "安徽智数科技有限公司": "智数科技",
    "合肥云启信息技术有限公司": "云启信息",
    "中科云谷（合肥）数据科技有限公司": "中科云谷",
    "皖信通网络科技有限公司": "皖信通",
    "安徽数安信息技术股份有限公司": "数安信息",
    "合肥联创软件有限公司": "联创软件",
}
ORG_ABBR = {
    "国家数据局": "数据局",
    "安徽省数据资源管理局": "省数据局",
    "合肥市数据资源局": "市数据局",
}
PERSONS = [
    "王建国", "李芳", "张伟", "刘志强", "陈晓东", "杨静", "赵磊", "黄敏",
    "周涛", "吴婷", "徐鹏", "孙丽", "马晓东", "朱海波", "胡文华", "郭强",
    "何静怡", "高鹏", "林峰", "罗雪梅", "郑晓燕", "谢文博", "韩雪", "曹阳",
]
ADDRESSES = [
    "安徽省合肥市蜀山区黄山路600号", "合肥市包河区中山路1号",
    "江苏省南京市鼓楼区北京西路70号", "浙江省杭州市西湖区文三路90号",
    "芜湖市镜湖区文化路8号", "肥东县店埠镇人民路12号",
]
EMAIL_DOMAINS = ["example.com", "example.org", "example.net"]

# 身份证前 6 位 (行政区划) + 出生日期范围
ID_PREFIXES = ["340102", "320106", "330106", "340202", "340122", "340111"]
_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 5, 7, 9, 10, 5, 8, 4, 2, 1]
_MOD_MAP = "10X98765432"

# 统一社会信用代码字符集 (排除 I/O/S/V/Z)
_CREDIT_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"

# 句模板: {org} 等占位符在运行时填充
TEMPLATES = [
    "项目负责人：{person}，联系电话：{phone}。",
    "承建单位{company}（以下简称“{abbr}”）负责系统开发。",
    "本项目由{org}牵头，{company}配合实施。",
    "联系地址：{address}，联系人：{person}，手机：{phone}。",
    "法定代表人{person}，身份证号{id}，邮箱：{email}。",
    "{org}于2024年印发《关于加快数据资源开发利用的通知》。",
    "统一社会信用代码：{credit}，登记机关：{city_org}。",
    "{county_org}配合{province_org}开展数据治理与共享交换工作。",
    "项目组成员{person}、{person2}、{person3}参与需求调研。",
    "运维服务由{company}承担，服务窗口地址：{address}。",
    "{org}要求各地市参照{city_org}的做法推进平台建设。",
    "开户名称：{company}，纳税人识别号：{credit}。",
]


def _id_check_digit(body17: str) -> str:
    total = sum(int(body17[i]) * _WEIGHTS[i] for i in range(17))
    return _MOD_MAP[total % 11]


def make_id(rng: random.Random) -> str:
    """生成校验位有效的 18 位身份证号 (虚构)。"""
    prefix = rng.choice(ID_PREFIXES)
    year = rng.randint(1975, 1998)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = rng.randint(1, 999)
    body = f"{prefix}{year:04d}{month:02d}{day:02d}{seq:03d}"
    return body + _id_check_digit(body)


def make_phone(rng: random.Random) -> str:
    return rng.choice(["138", "139", "150", "158", "186", "177"]) + "".join(
        str(rng.randint(0, 9)) for _ in range(8))


def make_credit(rng: random.Random) -> str:
    return "91340100" + "".join(rng.choice(_CREDIT_CHARS) for _ in range(10))


def make_email(rng: random.Random) -> str:
    local = "user" + "".join(str(rng.randint(0, 9)) for _ in range(5))
    return f"{local}@{rng.choice(EMAIL_DOMAINS)}"


def build_sentence(rng: random.Random) -> tuple[str, list]:
    """生成一句话及其真值实体列表 [(text, type, hard)]。"""
    company = rng.choice(COMPANIES)
    org = rng.choice(NATIONAL_ORGS + PROVINCE_ORGS)
    person = rng.choice(PERSONS)
    address = rng.choice(ADDRESSES)
    phone = make_phone(rng)
    email = make_email(rng)
    id_no = make_id(rng)
    credit = make_credit(rng)
    city_org = rng.choice(CITY_ORGS)
    county_org = rng.choice(COUNTY_ORGS)
    province_org = rng.choice(PROVINCE_ORGS)
    person2, person3 = rng.sample(PERSONS, 2)

    tpl = rng.choice(TEMPLATES)
    text = tpl.format(
        person=person, person2=person2, person3=person3, phone=phone,
        company=company, abbr=COMPANY_ABBR[company], org=org, address=address,
        email=email, id=id_no, credit=credit, city_org=city_org,
        county_org=county_org, province_org=province_org,
    )

    truth = []
    def add(value, etype, hard=False):
        if value and value in text:
            truth.append({"text": value, "type": etype, "hard": hard})

    add(person, "PERSON")
    if "{person2}" in tpl:
        add(person2, "PERSON")
    if "{person3}" in tpl:
        add(person3, "PERSON")
    add(phone, "PHONE_NUMBER")
    add(company, "ORGANIZATION")
    add(COMPANY_ABBR[company], "ORGANIZATION", hard=True)
    add(org, "ORGANIZATION")
    add(address, "LOCATION")
    add(email, "EMAIL_ADDRESS")
    add(id_no, "ID_NUMBER")
    add(credit, "CREDIT_CODE")
    add(city_org, "ORGANIZATION")
    add(county_org, "ORGANIZATION")
    add(province_org, "ORGANIZATION")
    # 单位简称 (hard): 仅当模板里出现对应全称时
    for full, short in ORG_ABBR.items():
        if full in text:
            add(short, "ORGANIZATION", hard=True)
    return text, truth


# --------------------------------------------------------------------------- #
# 基础文档读取
# --------------------------------------------------------------------------- #
def load_base_paragraphs(base: Path, mapping: Path | None) -> list[str]:
    """读取基础 docx; 若给了映射 CSV, 先把 ⟦PII:...⟧ 还原成 (已脱敏的) 原文。"""
    d = docx.Document(str(base))
    texts = [p.text for p in d.paragraphs]
    if mapping and mapping.exists():
        with mapping.open(encoding="utf-8-sig", newline="") as f:
            by_ph = {r["placeholder"]: r["original"] for r in csv.DictReader(f)}
        texts = [t for t in texts]
        for ph, orig in by_ph.items():
            texts = [t.replace(ph, orig) for t in texts]
    return texts


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def generate(base: Path, out_dir: Path, mapping: Path | None = None,
             parts: int = 10, seed: int = 42, insert_every: int = 12) -> dict:
    rng = random.Random(seed)
    base_paras = load_base_paragraphs(base, mapping)

    # 每隔 insert_every 段插入 1-3 句合成内容
    merged: list[str] = []
    truth_by_para: dict[int, list] = {}
    for i, para in enumerate(base_paras):
        merged.append(para)
        if i and i % insert_every == 0:
            for _ in range(rng.randint(1, 3)):
                sentence, truth = build_sentence(rng)
                truth_by_para[len(merged)] = truth
                merged.append(sentence)

    # 末尾追加一份联系人名单 (表格型内容)
    merged.append("项目联系人名单")
    for _ in range(4):
        person = rng.choice(PERSONS)
        phone = make_phone(rng)
        text = f"{person}，{rng.choice(COUNTY_ORGS)}，{phone}"
        truth_by_para[len(merged)] = [
            {"text": person, "type": "PERSON", "hard": False},
            {"text": phone, "type": "PHONE_NUMBER", "hard": False},
        ]
        merged.append(text)

    out_dir.mkdir(parents=True, exist_ok=True)
    parts = max(1, parts)
    chunk = max(1, (len(merged) + parts - 1) // parts)
    manifest = {"seed": seed, "base": base.name, "parts": []}

    for idx in range(parts):
        start = idx * chunk
        if start >= len(merged):
            break
        block = merged[start:start + chunk]
        doc = docx.Document()
        for text in block:
            doc.add_paragraph(text)
        name = f"part-{idx + 1:02d}.docx"
        doc.save(str(out_dir / name))

        entities = []
        for offset in range(start, start + len(block)):
            entities.extend(truth_by_para.get(offset, []))
        manifest["parts"].append({
            "file": name,
            "paragraphs": len(block),
            "entities": entities,
        })

    manifest["whitelist"] = ["国家数据局", "智数科技", "合肥市数据资源局"]
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "whitelist.txt").write_text(
        "# 测试用白名单: 这些词不应被替换\n" + "\n".join(manifest["whitelist"]) + "\n",
        encoding="utf-8")
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser("生成混入合成 PII 的测试文档集")
    ap.add_argument("--base", required=True, help="基础 docx (建议用脱敏产物)")
    ap.add_argument("--mapping", help="基础 docx 对应的 .mapping.csv (用于还原占位符)")
    ap.add_argument("--out", default="testdata", help="输出目录 (默认 testdata/)")
    ap.add_argument("--parts", type=int, default=10, help="切分成几份 (默认 10)")
    ap.add_argument("--seed", type=int, default=42, help="随机种子, 保证可复现")
    ap.add_argument("--insert-every", type=int, default=12,
                    help="每隔多少段插入合成内容 (默认 12)")
    args = ap.parse_args(argv)

    base = Path(args.base)
    if not base.exists():
        print(f"[error] 基础文档不存在: {base}", file=sys.stderr)
        return 1

    manifest = generate(base, Path(args.out),
                        Path(args.mapping) if args.mapping else None,
                        parts=args.parts, seed=args.seed,
                        insert_every=args.insert_every)
    total = sum(len(p["entities"]) for p in manifest["parts"])
    print(f"[gen] 生成 {len(manifest['parts'])} 份文档 -> {args.out}")
    print(f"[gen] 注入真值实体 {total} 条 (seed={args.seed})")
    print(f"[gen] 真值清单: {Path(args.out) / 'manifest.json'}")
    print(f"[gen] 白名单示例: {Path(args.out) / 'whitelist.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
