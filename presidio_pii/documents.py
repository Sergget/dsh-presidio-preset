"""Office / 纯文本文档的文本单元抽取与回写。

设计: 将文档拆成若干 (unit_key, text) 文本单元 (段落 / 单元格),
对每个单元独立 redact / restore。同一 session+doc_id 下占位符全局唯一,
因此跨单元还原时直接字符串替换即可。

支持格式: .txt / .md / .docx / .xlsx / .pptx
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


def _iter_docx(path: Path) -> List[TextUnit]:
    import docx
    d = docx.Document(str(path))
    return [(f"para:{i}", p.text) for i, p in enumerate(d.paragraphs)]


def _write_docx(src: Path, out: Path, units: List[TextUnit]) -> None:
    import docx
    d = docx.Document(str(src))
    texts = dict(units)
    for i, p in enumerate(d.paragraphs):
        new = texts.get(f"para:{i}")
        if new is not None and new != p.text:
            # 最小实现: 重写首个 run, 其余 run 清空 (丢失段内混合格式)
            if p.runs:
                p.runs[0].text = new
                for r in p.runs[1:]:
                    r.text = ""
            else:
                p.add_run(new)
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


def _iter_pptx(path: Path) -> List[TextUnit]:
    from pptx import Presentation
    prs = Presentation(str(path))
    units: List[TextUnit] = []
    for si, slide in enumerate(prs.slides):
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            for pi, para in enumerate(shape.text_frame.paragraphs):
                text = "".join(run.text for run in para.runs)
                if text:
                    units.append((f"slide{si}:shape{shape.shape_id}:{pi}", text))
    return units


def _write_pptx(src: Path, out: Path, units: List[TextUnit]) -> None:
    from pptx import Presentation
    prs = Presentation(str(src))
    texts = dict(units)
    for si, slide in enumerate(prs.slides):
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            for pi, para in enumerate(shape.text_frame.paragraphs):
                key = f"slide{si}:shape{shape.shape_id}:{pi}"
                if key in texts:
                    new = texts[key]
                    old = "".join(run.text for run in para.runs)
                    if new != old and para.runs:
                        para.runs[0].text = new
                        for r in para.runs[1:]:
                            r.text = ""
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
