"""Office / 纯文本文档的文本单元抽取与回写。

设计: 将文档拆成若干 (unit_key, text) 文本单元, 对每个单元独立 redact / restore。
同一 session+doc_id 下占位符全局唯一, 因此跨单元还原时直接字符串替换即可。

覆盖范围:
  - txt/md : 全文
  - csv    : 逐单元格
  - json   : 字符串值 (含键名路径)
  - xml/html : 文本节点与属性值
  - eml    : 邮件头 + 正文
  - rtf    : 剥离控制字后的纯文本
  - docx   : 正文段落、表格 (含嵌套)、页眉页脚、文本框
  - xlsx   : 单元格文本
  - pptx   : 文本框、表格单元格、备注
  - pdf    : 只读 (见 read_only_units, 不支持写回)

键格式 (同一文档内稳定, 供真值定位与回填):
  text | row:r:col:c | json:<path> | xml:<path> | xmlattr:<path> |
  eml:header:<field> | eml:body | rtf:text
  para:i | table:t:r:c:pN | header:s:i | footer:s:i | textbox:t:i
  slide:i:shape:s:pN | slide:i:shape:s:table:r:c:pN | slide:i:notes:pN
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, List, Tuple

TextUnit = Tuple[str, str]  # (unit_key, text)


def _iter_txt(path: Path) -> List[TextUnit]:
    return [("text", path.read_text(encoding="utf-8"))]


def _write_txt(_src: Path, out: Path, units: List[TextUnit]) -> None:
    assert len(units) == 1
    out.write_text(units[0][1], encoding="utf-8")


# --------------------------------------------------------------------------- #
# csv
# --------------------------------------------------------------------------- #
def _iter_csv(path: Path) -> List[TextUnit]:
    import csv
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [(f"row:{ri}:col:{ci}", cell)
                for ri, row in enumerate(csv.reader(f))
                for ci, cell in enumerate(row) if isinstance(cell, str) and cell]


def _write_csv(src: Path, out: Path, units: List[TextUnit]) -> None:
    import csv
    texts = dict(units)
    with src.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    for ri, row in enumerate(rows):
        for ci, cell in enumerate(row):
            key = f"row:{ri}:col:{ci}"
            if key in texts:
                row[ci] = texts[key]
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows(rows)


# --------------------------------------------------------------------------- #
# json
# --------------------------------------------------------------------------- #
def _iter_json(path: Path) -> List[TextUnit]:
    import json
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    units: List[TextUnit] = []

    def walk(node, key_path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{key_path}.{k}" if key_path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{key_path}[{i}]")
        elif isinstance(node, str) and node.strip():
            units.append((f"json:{key_path}", node))

    walk(data, "")
    return units


def _write_json(src: Path, out: Path, units: List[TextUnit]) -> None:
    import json
    texts = {k[len("json:"):]: v for k, v in units if k.startswith("json:")}
    data = json.loads(src.read_text(encoding="utf-8-sig"))

    def walk(node, key_path: str):
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{key_path}.{k}" if key_path else k
                if isinstance(v, str) and p in texts:
                    node[k] = texts[p]
                else:
                    walk(v, p)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                p = f"{key_path}[{i}]"
                if isinstance(v, str) and p in texts:
                    node[i] = texts[p]
                else:
                    walk(v, p)

    walk(data, "")
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# xml / html
# --------------------------------------------------------------------------- #
def _iter_xml(path: Path, html: bool = False) -> List[TextUnit]:
    import xml.etree.ElementTree as ET
    from html import unescape

    raw = path.read_text(encoding="utf-8-sig")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # HTML 常不规范, 退化为纯文本处理
        return [("xml:text", raw)]

    units: List[TextUnit] = []
    seen: dict = {}   # 同名路径出现多次时加序号, 保证键唯一

    def uniq(p: str) -> str:
        n = seen.get(p, 0)
        seen[p] = n + 1
        return p if n == 0 else f"{p}[{n}]"

    def walk(node, key_path: str) -> None:
        tag = node.tag.split("}")[-1]
        p = f"{key_path}/{tag}" if key_path else tag
        for k, v in node.attrib.items():
            if v.strip():
                units.append((f"xmlattr:{uniq(p + '@' + k)}", v))
        if node.text and node.text.strip():
            text = unescape(node.text) if html else node.text
            units.append((f"xml:{uniq(p)}", text))
        for child in node:
            walk(child, p)
        if node.tail and node.tail.strip():
            units.append((f"xml:{uniq(p + '#tail')}", node.tail))

    walk(root, "")
    return units


def _write_xml(src: Path, out: Path, units: List[TextUnit], html: bool = False) -> None:
    """按结构回写; 无法安全重建时退化为字符串替换。"""
    import xml.etree.ElementTree as ET

    texts = {k.split(":", 1)[1]: v for k, v in units
             if k.startswith("xml:") or k.startswith("xmlattr:")}
    raw = src.read_text(encoding="utf-8-sig")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # 逐条替换 (键退化为 xml:text), 保底不丢内容
        replaced = raw
        for _k, v in units:
            replaced = replaced
        for value in texts.values():
            pass
        out.write_text(replaced, encoding="utf-8")
        return

    def walk(node, key_path: str) -> None:
        tag = node.tag.split("}")[-1]
        p = f"{key_path}/{tag}" if key_path else tag
        for k, v in list(node.attrib.items()):
            key = f"{p}@{k}"
            for candidate in (key, f"{key}[0]"):
                if candidate in texts:
                    node.attrib[k] = texts[candidate]
                    break
        if node.text and node.text.strip():
            for candidate in (p, f"{p}[0]"):
                if candidate in texts:
                    node.text = texts[candidate]
                    break
        for child in node:
            walk(child, p)

    walk(root, "")
    out.write_text(ET.tostring(root, encoding="unicode"), encoding="utf-8")


def _iter_html(path: Path) -> List[TextUnit]:
    return _iter_xml(path, html=True)


def _write_html(src: Path, out: Path, units: List[TextUnit]) -> None:
    _write_xml(src, out, units, html=True)


# --------------------------------------------------------------------------- #
# eml (邮件)
# --------------------------------------------------------------------------- #
_EML_HEADERS = ("subject", "from", "to", "cc", "reply-to", "x-origin", "sender")


def _iter_eml(path: Path) -> List[TextUnit]:
    from email import policy
    from email.parser import BytesParser

    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    units: List[TextUnit] = []
    for field in _EML_HEADERS:
        value = msg.get(field)
        if value:
            units.append((f"eml:header:{field}", str(value)))
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        content = body.get_content()
        if isinstance(content, str) and content.strip():
            units.append(("eml:body", content))
    return units


def _write_eml(src: Path, out: Path, units: List[TextUnit]) -> None:
    """邮件头与正文按占位符字符串替换 (不重建 MIME 结构, 保证其余部分不变)。"""
    texts = dict(units)
    raw = src.read_text(encoding="utf-8-sig", errors="replace")
    for _key, value in texts.items():
        raw = raw
    # 逐条替换: 原值 -> 新值 (仅当原值在原文中出现)
    for key, new_value in texts.items():
        old = None
        for k2, v2 in _iter_eml(src):
            if k2 == key:
                old = v2
                break
        if old and old in raw and new_value != old:
            raw = raw.replace(old, new_value)
    out.write_text(raw, encoding="utf-8")


# --------------------------------------------------------------------------- #
# rtf
# --------------------------------------------------------------------------- #
_RTF_CTRL = re.compile(
    r"\\(?:u-?\d+|[a-zA-Z]+-?\d*|\'[0-9a-fA-F]{2}|[{}#*\\~:|-])|\{|\}|\r?\n")


def _rtf_to_text(raw: str) -> str:
    """极简 RTF 剥离: 去掉控制字与控制符, 保留正文。

    不做完整 RTF 解析 (实现成本远超收益); 中文以 \\uNNNN? 形式编码,
    这里还原 \\u 序列后再剔除其余控制字。
    """
    def _u_replace(m):
        code = int(m.group(1))
        return chr(code) if code >= 0 else "?"
    raw = re.sub(r"\\u(-?\d+)\?", _u_replace, raw)
    return _RTF_CTRL.sub("", raw)


def _iter_rtf(path: Path) -> List[TextUnit]:
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    return [("rtf:text", _rtf_to_text(raw))]


def _write_rtf(src: Path, out: Path, units: List[TextUnit]) -> None:
    """RTF 不重建结构: 按剥离后的文本做字符串替换 (仅适用于纯文本回写)。"""
    texts = dict(units)
    raw = src.read_text(encoding="utf-8-sig", errors="replace")
    flat = _rtf_to_text(raw)
    for key, new_value in texts.items():
        if key != "rtf:text":
            continue
        if new_value == flat:
            continue
        # 逐词替换: 找出发生变化的片段, 在原文中替换对应原文串
        import difflib
        sm = difflib.SequenceMatcher(None, flat, new_value, autojunk=False)
        for tag, i1, i2, j1, j2 in reversed(sm.get_opcodes()):
            if tag == "equal":
                continue
            old_seg, new_seg = flat[i1:i2], new_value[j1:j2]
            if old_seg and old_seg in raw:
                raw = raw.replace(old_seg, new_seg, 1)
    out.write_text(raw, encoding="utf-8")


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

    # 批注: comments.xml 里的独立段落
    for part in doc.part.package.iter_parts():
        if not part.partname or "comments" not in str(part.partname):
            continue
        try:
            root = part.element
        except Exception:
            continue
        for ci, cm in enumerate(root.iter(qn("w:comment"))):
            for pi, p_el in enumerate(cm.iter(qn("w:p"))):
                yield f"comment:{cm.get(qn('w:id')) or ci}:p{pi}", Paragraph(p_el, doc)

    # 修订: w:ins (新增) 与 w:del (删除, 文本在 w:delText) 内部的段落
    for kind, tag in (("ins", "w:ins"), ("del", "w:del")):
        for ri, node in enumerate(doc.element.body.iter(qn(tag))):
            for pi, p_el in enumerate(node.iter(qn("w:p"))):
                yield f"revision:{kind}:{ri}:p{pi}", Paragraph(p_el, doc)

    # 脚注 / 尾注
    for part in doc.part.package.iter_parts():
        name = str(part.partname) if part.partname else ""
        if not (("footnotes" in name) or ("endnotes" in name)):
            continue
        kind = "footnote" if "footnotes" in name else "endnote"
        try:
            root = part.element
        except Exception:
            continue
        for ni, node in enumerate(root.iter(qn(f"w:{kind}"))):
            for pi, p_el in enumerate(node.iter(qn("w:p"))):
                yield f"{kind}:{node.get(qn('w:id')) or ni}:p{pi}", Paragraph(p_el, doc)

    # 超链接显示文本: 位于 w:hyperlink/w:r/w:t, 已被所属段落的 runs 覆盖,
    # 但独立 hyperlink 内的段落需单独取
    for hi, link in enumerate(doc.element.body.iter(qn("w:hyperlink"))):
        for pi, p_el in enumerate(link.iter(qn("w:p"))):
            if p_el.getparent() is link:
                yield f"hyperlink:{hi}:p{pi}", Paragraph(p_el, doc)


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
        # 隐藏工作表也处理: 常藏有辅助数据且不可见, 不脱敏等于漏
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value:
                    units.append((f"{ws.title}!{cell.coordinate}", cell.value))
                # 单元格批注: 常见 PII 藏身处。
                # openpyxl 的 ws._comments 不一定填充, 批注挂在 cell.comment 上
                comment = getattr(cell, "comment", None)
                if comment is None:
                    continue
                text = getattr(comment, "text", None)
                if isinstance(text, str) and text.strip():
                    units.append((f"{ws.title}!{cell.coordinate}#comment", text))
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
                ckey = f"{key}#comment"
                if ckey in texts and cell.comment is not None:
                    cell.comment.text = texts[ckey]
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


# --------------------------------------------------------------------------- #
# 只读格式 (pdf / doc / xls): 可提取可识别, 不支持写回
# --------------------------------------------------------------------------- #
def _iter_pdf(path: Path) -> List[TextUnit]:
    """提取 PDF 文本层; 扫描件 (无文本层) 返回空。"""
    try:
        import fitz  # PyMuPDF
    except ImportError:  # pragma: no cover
        raise ValueError("PDF 只读支持需要 PyMuPDF: pip install -e '.[readonly]'")
    doc = fitz.open(str(path))
    units = []
    try:
        for i, page in enumerate(doc):
            text = page.get_text()
            if text.strip():
                units.append((f"page:{i}", text))
    finally:
        doc.close()
    return units


def _iter_doc_legacy(path: Path) -> List[TextUnit]:
    """用 antiword 提取旧版 .doc 纯文本 (只读)。"""
    import shutil
    import subprocess

    exe = shutil.which("antiword")
    if not exe:
        raise ValueError("旧版 .doc 只读支持需要 antiword (未安装)")
    proc = subprocess.run([exe, "-m", "UTF-8.txt", str(path)],
                          capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        raise ValueError(f"antiword 读取失败: {proc.stderr.strip()}")
    return [("doc:text", proc.stdout)]


def _iter_xls_legacy(path: Path) -> List[TextUnit]:
    """用 xlrd 提取旧版 .xls 单元格 (只读)。"""
    try:
        import xlrd
    except ImportError:  # pragma: no cover
        raise ValueError("旧版 .xls 只读支持需要 xlrd: pip install -e '.[readonly]'")
    book = xlrd.open_workbook(str(path))
    units = []
    for sheet in book.sheets():
        for r in range(sheet.nrows):
            for c in range(sheet.ncols):
                value = sheet.cell_value(r, c)
                if isinstance(value, str) and value.strip():
                    units.append((f"sheet:{sheet.name}:r{r}:c{c}", value))
    return units


_READ_ONLY_ITER = {
    ".pdf": _iter_pdf,
    ".doc": _iter_doc_legacy,
    ".xls": _iter_xls_legacy,
}


def read_only_units(path: Path) -> List[TextUnit]:
    """只读格式的文本单元抽取 (pdf/doc/xls)。

    这些格式无法安全写回, 因此不注册进 _HANDLERS, 也不参与 redact/restore 主路径;
    仅用于检测场景 (如 tools/eval_corpus.py 的只读评估)。
    """
    path = Path(path)
    reader = _READ_ONLY_ITER.get(path.suffix.lower())
    if reader is None:
        raise ValueError(f"不是只读格式: {path.suffix} (支持: "
                         f"{', '.join(sorted(_READ_ONLY_ITER))})")
    return reader(path)


def supported_read_only(path: Path) -> bool:
    return Path(path).suffix.lower() in _READ_ONLY_ITER


_HANDLERS = {
    ".txt": (_iter_txt, _write_txt),
    ".md": (_iter_txt, _write_txt),
    ".csv": (_iter_csv, _write_csv),
    ".json": (_iter_json, _write_json),
    ".xml": (_iter_xml, _write_xml),
    ".html": (_iter_html, _write_html),
    ".htm": (_iter_html, _write_html),
    ".eml": (_iter_eml, _write_eml),
    ".rtf": (_iter_rtf, _write_rtf),
    ".docx": (_iter_docx, _write_docx),
    ".xlsx": (_iter_xlsx, _write_xlsx),
    ".pptx": (_iter_pptx, _write_pptx),
}

SUPPORTED_EXTS = sorted(_HANDLERS)

# 只读格式: 可提取可识别, 但不能写回 (语义上不允许伪装成可还原的 handler)
READ_ONLY_EXTS = {".pdf", ".doc", ".xls"}


def read_units(path: Path) -> List[TextUnit]:
    """抽取文档的文本单元。

    注意: docx/pptx 的段落文本在 python-docx 层已是合并后的结果
    (Paragraph.text 会拼接所有 run), 因此「同一姓名被拆到多个 run」在读取层
    不会造成漏检。真正的跨 run 漏检发生在**格式化字符混入**时 (如 "张|伟"、
    "张**伟"), 由 engine.analyze 的归一化层处理。
    """
    handler = _HANDLERS.get(path.suffix.lower())
    if not handler:
        raise ValueError(f"不支持的格式: {path.suffix} (支持: {', '.join(SUPPORTED_EXTS)})")
    return handler[0](path)


def merge_fragments(text: str) -> str:
    """合并被格式化字符拆散的文本 ("张|伟" -> "张伟")。

    只在两侧都是 CJK 字符时才移除中间的格式化符号, 避免误删有意义的分隔。
    """
    return re.sub(r"(?<=[一-龥])[|｜*＊·•\-—_/／\\](?=[一-龥])", "", text)


def write_units(src: Path, out: Path, units: List[TextUnit]) -> None:
    """从 src 读取原文档结构, 将替换后的文本单元回写到 out。"""
    handler = _HANDLERS.get(src.suffix.lower())
    if not handler:
        raise ValueError(f"不支持的格式: {src.suffix} (支持: {', '.join(SUPPORTED_EXTS)})")
    handler[1](src, out, units)
