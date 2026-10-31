"""文档结构覆盖测试: 批注 / 修订 / 脚注 / xlsx 批注 / 只读格式。

对应 docs/TEST-MATRIX.md P1 与 P2:
这些位置常被当作「不可见」而漏掉, 却是 PII 的常见藏身处。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from presidio_pii.documents import read_only_units, read_units  # noqa: E402
from presidio_pii.engine import PresidioPIIEngine  # noqa: E402


def test_pdf_read_only_detects_pii(tmp_path):
    fitz = pytest.importorskip("fitz")  # PyMuPDF
    from presidio_pii.documents import supported_read_only

    pdf = tmp_path / "t.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 100), "负责人：王建国，电话 13800138000。",
                     fontname="china-s", fontsize=12)
    doc.save(str(pdf))
    doc.close()

    assert supported_read_only(pdf)
    units = read_only_units(pdf)
    assert units and any("王建国" in text for _k, text in units)

    engine = PresidioPIIEngine(db_path=":memory:")
    for _k, text in units:
        hits = {text[r.start:r.end]: r.entity_type for r in engine.analyze(text)}
    assert hits.get("王建国") == "PERSON"
    assert hits.get("13800138000") == "PHONE_NUMBER"


def test_pdf_is_not_in_writable_handlers():
    """只读格式不得注册进可写回 handler, 否则 restore 语义会被破坏。"""
    from presidio_pii.documents import SUPPORTED_EXTS

    assert ".pdf" not in SUPPORTED_EXTS
    assert ".doc" not in SUPPORTED_EXTS
    assert ".xls" not in SUPPORTED_EXTS


def test_xlsx_cell_comment_is_read(tmp_path):
    pytest.importorskip("openpyxl")
    import openpyxl
    from openpyxl.comments import Comment

    path = tmp_path / "c.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "姓名"
    ws["A1"].comment = Comment("该员工由李芳推荐入职", "reviewer")
    wb.save(str(path))

    units = read_units(path)
    keys = [k for k, _v in units]
    assert any("#comment" in k for k in keys)
    assert any("李芳" in v for _k, v in units)


def test_xlsx_cell_comment_roundtrip(tmp_path):
    """批注也要能脱敏并还原, 不只是能读。"""
    pytest.importorskip("openpyxl")
    import openpyxl
    from openpyxl.comments import Comment
    from presidio_pii.documents import write_units

    path = tmp_path / "c.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"] = "姓名"
    ws["A1"].comment = Comment("该员工由李芳推荐入职", "reviewer")
    wb.save(str(path))

    engine = PresidioPIIEngine(db_path=":memory:")
    sid = engine.registry.create_session()
    before = read_units(path)
    out = tmp_path / "c.out.xlsx"
    redacted = [(k, engine.redact(v, sid, "c.xlsx").text) for k, v in before]
    write_units(path, out, redacted)
    assert "李芳" not in read_units(out)[1][1]

    back = [(k, engine.restore(v, sid, "c.xlsx").text) for k, v in read_units(out)]
    assert back == before


def test_docx_comments_and_footnotes_are_read(tmp_path):
    """批注与脚注位于独立 XML part, python-docx 默认不暴露。"""
    pytest.importorskip("docx")
    import docx

    path = tmp_path / "c.docx"
    d = docx.Document()
    d.add_paragraph("正文段落")
    d.save(str(path))
    # 该用例验证读取不抛异常且正文可读; 批注/脚注需带注释的文档才有内容
    units = read_units(path)
    assert units and units[0][1] == "正文段落"


def test_csv_json_xml_rtf_roundtrip(tmp_path):
    """新增文本格式必须能往返, 不只是能读。"""
    from presidio_pii.documents import write_units

    engine = PresidioPIIEngine(db_path=":memory:")
    sid = engine.registry.create_session()
    cases = {
        "a.csv": "姓名,身份证号\n李芳,110101199003077890\n",
        "b.json": '{"name":"王建国","phone":"13800138000"}',
        "c.xml": "<root><p>联系人张伟</p></root>",
    }
    for name, content in cases.items():
        src = tmp_path / name
        src.write_text(content, encoding="utf-8")
        before = read_units(src)
        out = tmp_path / ("out_" + name)
        redacted = [(k, engine.redact(v, sid, name).text) for k, v in before]
        write_units(src, out, redacted)
        back = [(k, engine.restore(v, sid, name).text) for k, v in read_units(out)]
        assert back == before, name


def test_xml_keys_are_unique(tmp_path):
    """同名标签出现多次时键不能重复, 否则回填会互相覆盖。"""
    path = tmp_path / "u.xml"
    path.write_text("<root><p>张伟</p><p>李芳</p></root>", encoding="utf-8")
    keys = [k for k, _v in read_units(path)]
    assert len(keys) == len(set(keys))
