"""Office / 纯文本文档的文本单元抽取与回写。

设计: 将文档拆成若干 (unit_key, text) 文本单元, 对每个单元独立 redact / restore。
同一 session+doc_id 下占位符全局唯一, 因此跨单元还原时直接字符串替换即可。

覆盖范围:
  - txt/md : 全文
  - docx   : 正文段落、表格 (含嵌套)、页眉页脚、文本框
  - xlsx   : 单元格文本
  - pptx   : 文本框、表格单元格、备注

键格式 (同一文档内稳定, 供真值定位与回填):
  para:i | table:t:r:c:pN | header:s:i | footer:s:i | textbox:t:i
  slide:i:shape:s:pN | slide:i:shape:s:table:r:c:pN | slide:i:notes:pN
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, List, Tuple

TextUnit = Tuple[str, str]  # (unit_key, text)


def _iter_txt(path: Path) -> List[TextUnit]:
    return [("text", path.read_text(encoding="utf-8"))]


def _write_txt(_src: Path, out: Path, units: List[TextUnit]) -> None:
    assert len(units) == 1
    out.write_text(units[0][1], encoding="utf-8")


# --------------------------------------------------------------------------- #
# docx
# --------------------------------------------------------------------------- #
def _set_docx_paragraph(p, text: str) -> None:
    """最小实现: 重写首个 run, 其余 run 清空 (丢失段内混合格式)。"""
    if p.runs:
        p.runs[0].text = text
        for r in p.runs[1:]:
            r.text = ""
    else:
        p.add_run(text)


def _table_units(tables, prefix: str):
    """表格单元格内的段落, 递归处理嵌套表格。

    合并单元格在 row.cells 中会以多个坐标出现, 这里不做去重:
    lxml 代理对象的 id() 会被回收复用, 用它去重会误删正常单元格;
    重复键按坐标区分, 回填同一文本两次无副作用。
    """
    for ti, table in enumerate(tables):
        for ri, row in enumerate(table.rows):
            for ci, cell in enumerate(row.cells):
                base = f"{prefix}:{ti}:{ri}:{ci}"
                for pi, p in enumerate(cell.paragraphs):
                    yield f"{base}:p{pi}", p
                yield from _table_units(cell.tables, f"{base}:table")


def _docx_units(doc):
    """遍历 docx 中所有可写文本, 产出 (key, paragraph)。"""
    from docx.text.paragraph import Paragraph
    from docx.oxml.ns import qn

    for i, p in enumerate(doc.paragraphs):
        yield f"para:{i}", p

    yield from _table_units(doc.tables, "table")

    for si, section in enumerate(doc.sections):
        for label, hf in (("header", section.header), ("footer", section.footer)):
            if hf.is_linked_to_previous:   # 避免读取时创建空白页眉部件
                continue
            for i, p in enumerate(hf.paragraphs):
                yield f"{label}:{si}:{i}", p
            yield from _table_units(hf.tables, f"{label}:{si}:table")

    # 文本框: 内容位于 w:txbxContent, 不属于所在段落的 runs
    for ti, txbx in enumerate(doc.element.body.iter(qn("w:txbxContent"))):
        for pi, p_el in enumerate(txbx.iter(qn("w:p"))):
            yield f"textbox:{ti}:{pi}", Paragraph(p_el, doc)


def _iter_docx(path: Path) -> List[TextUnit]:
    import docx
    d = docx.Document(str(path))
    return [(key, p.text) for key, p in _docx_units(d)]


def _write_docx(src: Path, out: Path, units: List[TextUnit]) -> None:
    import docx
    d = docx.Document(str(src))
    texts = dict(units)
    for key, p in _docx_units(d):
        new = texts.get(key)
        if new is not None and new != p.text:
            _set_docx_paragraph(p, new)
    d.save(str(out))


def _iter_xlsx(path: Path) -> List[TextUnit]:
    import openpyxl
    wb = openpyxl.load_workbook(str(path))
    units: List[TextUnit] = []
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value:
                    units.append((f"{ws.title}!{cell.coordinate}", cell.value))
    return units


def _write_xlsx(src: Path, out: Path, units: List[TextUnit]) -> None:
    import openpyxl
    wb = openpyxl.load_workbook(str(src))
    texts = dict(units)
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                key = f"{ws.title}!{cell.coordinate}"
                if key in texts:
                    cell.value = texts[key]
    wb.save(str(out))


# --------------------------------------------------------------------------- #
# pptx
# --------------------------------------------------------------------------- #
def _pptx_units(prs):
    """遍历幻灯片中的文本框、表格单元格、备注页, 产出 (key, paragraph)。"""
    for si, slide in enumerate(prs.slides):
        for shape in slide.shapes:
            if shape.has_text_frame:
                for pi, para in enumerate(shape.text_frame.paragraphs):
                    yield f"slide:{si}:shape:{shape.shape_id}:p{pi}", para
            if shape.has_table:
                for ri, row in enumerate(shape.table.rows):
                    for ci, cell in enumerate(row.cells):
                        for pi, para in enumerate(cell.text_frame.paragraphs):
                            yield (f"slide:{si}:shape:{shape.shape_id}:table:{ri}:{ci}:p{pi}",
                                   para)
        if slide.has_notes_slide:
            frame = slide.notes_slide.notes_text_frame
            if frame is not None:
                for pi, para in enumerate(frame.paragraphs):
                    yield f"slide:{si}:notes:p{pi}", para


def _iter_pptx(path: Path) -> List[TextUnit]:
    from pptx import Presentation
    prs = Presentation(str(path))
    units = []
    for key, para in _pptx_units(prs):
        text = "".join(run.text for run in para.runs)
        if text:
            units.append((key, text))
    return units


def _write_pptx(src: Path, out: Path, units: List[TextUnit]) -> None:
    from pptx import Presentation
    prs = Presentation(str(src))
    texts = dict(units)
    for key, para in _pptx_units(prs):
        new = texts.get(key)
        if new is None:
            continue
        old = "".join(run.text for run in para.runs)
        if new != old:
            para.text = new   # python-pptx 会重写为单个 run
    prs.save(str(out))


_HANDLERS = {
    ".txt": (_iter_txt, _write_txt),
    ".md": (_iter_txt, _write_txt),
    ".docx": (_iter_docx, _write_docx),
    ".xlsx": (_iter_xlsx, _write_xlsx),
    ".pptx": (_iter_pptx, _write_pptx),
}

SUPPORTED_EXTS = sorted(_HANDLERS)


def read_units(path: Path) -> List[TextUnit]:
    handler = _HANDLERS.get(path.suffix.lower())
    if not handler:
        raise ValueError(f"不支持的格式: {path.suffix} (支持: {', '.join(SUPPORTED_EXTS)})")
    return handler[0](path)


def write_units(src: Path, out: Path, units: List[TextUnit]) -> None:
    """从 src 读取原文档结构, 将替换后的文本单元回写到 out。"""
    handler = _HANDLERS.get(src.suffix.lower())
    if not handler:
        raise ValueError(f"不支持的格式: {src.suffix} (支持: {', '.join(SUPPORTED_EXTS)})")
    handler[1](src, out, units)
