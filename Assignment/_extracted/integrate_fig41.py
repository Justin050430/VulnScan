# -*- coding: utf-8 -*-
"""
Integrate the new Figure 4.1 (layered architecture) into FYP.docx:
 1) insert Heading 3 '4.1.1 Layered System Architecture (Logical View)'
 2) rename the Figure 4.1 caption
 3) replace the old image (rId9) with the new monochrome PNG and fix display size
"""
import docx, zipfile, shutil, os
from copy import deepcopy
from docx.oxml.ns import qn
from lxml import etree

SRC  = r"c:\FYP\VulnScan\Assignment\FYP.docx"
DOCX = r"c:\FYP\VulnScan\Assignment\FYP_updated.docx"
PNG  = r"c:\FYP\VulnScan\docs\design\Fig4.1_Layered_System_Architecture.png"
NEW_CAPTION = "Figure 4.1: Layered System Architecture of VulnScan (Logical View)"
HEADING = "4.1.1 Layered System Architecture (Logical View)"

# ---------- Step 1: text edits via python-docx ----------
import shutil as _sh
_sh.copyfile(SRC, DOCX)
d = docx.Document(DOCX)
paras = d.paragraphs

def find_para(pred):
    for p in paras:
        if pred(p):
            return p
    return None

h41 = find_para(lambda p: p.style.name == "Heading 2" and p.text.strip().startswith("4.1 Architecture Design"))
cap = find_para(lambda p: p.text.strip().startswith("Figure 4.1: Overall System Architecture"))
h3t = find_para(lambda p: p.style.name == "Heading 3" and p.text.strip().startswith("4.4.1 User Authentication"))
assert h41 is not None and cap is not None and h3t is not None, (h41, cap, h3t)

# insert 4.1.1 heading right after the 4.1 heading
new_h = deepcopy(h3t._p)
h41._p.addnext(new_h)
from docx.text.paragraph import Paragraph
np = Paragraph(new_h, h3t._parent)
runs = np.runs
if runs:
    runs[0].text = HEADING
    for r in runs[1:]:
        r._element.getparent().remove(r._element)
else:
    np.add_run(HEADING)

# rename caption
runs = cap.runs
if runs:
    runs[0].text = NEW_CAPTION
    for r in runs[1:]:
        r._element.getparent().remove(r._element)
else:
    cap.add_run(NEW_CAPTION)

d.save(DOCX)
print("text edits saved")

# ---------- Step 2: swap image bytes + size ----------
RID = "rId9"
aspect = 2240 / 1840.0            # new PNG aspect
W_EMU = int(6.0 * 914400)         # 6.0 inch width
H_EMU = int(W_EMU / aspect)
new_png = open(PNG, "rb").read()

zin = zipfile.ZipFile(DOCX, "r")
items = zin.namelist()
rels = zin.read("word/_rels/document.xml.rels")
rels_x = etree.fromstring(rels)
ns_r = "http://schemas.openxmlformats.org/package/2006/relationships"
target = None
for rel in rels_x:
    if rel.get("Id") == RID:
        target = rel.get("Target")
        break
print("rId9 target:", target)
assert target
media_name = "word/" + target.lstrip("/")

# build new document.xml with updated extent
doc_x = etree.fromstring(zin.read("word/document.xml"))
ns_w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
ns_a = "http://schemas.openxmlformats.org/drawingml/2006/main"
ns_r_draw = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
ns_wp = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"

def q(ns, name):
    return "{%s}%s" % (ns, name)

changed = False
for blip in doc_x.iter(q(ns_r_draw, "blip")):
    if blip.get(q(ns_r_draw, "embed")) == RID:
        # walk up to the drawing to find wp:extent
        anc = blip
        while anc is not None:
            parent = anc.getparent()
            if parent is None:
                break
            if parent.tag == q(ns_wp, "extent"):
                parent.set("cx", str(W_EMU))
                parent.set("cy", str(H_EMU))
            anc = parent
        # set pic a:ext
        for aext in blip.iter(q(ns_a, "ext")):
            aext.set("cx", str(W_EMU))
            aext.set("cy", str(H_EMU))
        changed = True
print("extent changed:", changed)
new_doc = etree.tostring(doc_x, xml_declaration=True, encoding="UTF-8", standalone=True)

# write new zip
tmp = DOCX + ".tmp"
zout = zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED)
for it in items:
    data = zin.read(it)
    if it == "word/document.xml":
        data = new_doc
    elif it == media_name:
        data = new_png
    zout.writestr(it, data)
zout.close()
zin.close()
os.replace(tmp, DOCX)
print("image replaced; size EMU:", W_EMU, H_EMU)
