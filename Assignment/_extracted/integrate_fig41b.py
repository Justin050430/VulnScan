# -*- coding: utf-8 -*-
"""
Robust integration of Figure 4.1 into a fresh copy (FYP_updated.docx from FYP.docx):
 1) insert Heading 3 '4.1.1 Layered System Architecture (Logical View)'
 2) rename Figure 4.1 caption
 3) replace the actual media part of the figure drawing with the new PNG
 4) update the drawing extent
Uses python-docx part mapping so the correct media file is always replaced.
"""
import shutil, docx
from copy import deepcopy
from docx.text.paragraph import Paragraph

SRC = r"c:\FYP\VulnScan\Assignment\FYP.docx"
DST = r"c:\FYP\VulnScan\Assignment\FYP_updated.docx"
PNG = r"c:\FYP\VulnScan\docs\design\Fig4.1_Layered_System_Architecture.png"
NEW_CAPTION = "Figure 4.1: Layered System Architecture of VulnScan (Logical View)"
HEADING = "4.1.1 Layered System Architecture (Logical View)"
NS_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"

shutil.copyfile(SRC, DST)
d = docx.Document(DST)
paras = d.paragraphs

def has_blip(p):
    return len(p._p.findall('.//{%s}blip' % NS_A)) > 0

h41 = next(p for p in paras if p.style.name == "Heading 2" and p.text.strip().startswith("4.1 Architecture Design"))
h3t = next(p for p in paras if p.style.name == "Heading 3" and p.text.strip().startswith("4.4.1 User Authentication"))
cap = next(p for p in paras if p.text.strip().startswith("Figure 4.1: Overall System Architecture"))

# insert 4.1.1 heading directly after the 4.1 heading
new_el = deepcopy(h3t._p)
h41._p.addnext(new_el)
np = Paragraph(new_el, h3t._parent)
if np.runs:
    np.runs[0].text = HEADING
    for r in np.runs[1:]:
        r._element.getparent().remove(r._element)
else:
    np.add_run(HEADING)

# rename caption
if cap.runs:
    cap.runs[0].text = NEW_CAPTION
    for r in cap.runs[1:]:
        r._element.getparent().remove(r._element)
else:
    cap.add_run(NEW_CAPTION)

# re-locate: refresh paragraph list, then the image is right after the 4.1.1 heading
paras = d.paragraphs
idx = next(i for i, p in enumerate(paras) if p.style.name == "Heading 3" and p.text.strip() == HEADING)
img = None
for j in range(idx + 1, min(idx + 4, len(paras))):
    if has_blip(paras[j]):
        img = paras[j]
        break
assert img is not None, "figure image paragraph not found"
blip = img._p.findall('.//{%s}blip' % NS_A)[0]
embed = blip.get('{%s}embed' % NS_R)
print("figure blip embed:", embed)

rel = d.part.rels[embed]
media_target = rel.target_ref
print("media target:", media_target)

# replace media bytes
new_bytes = open(PNG, "rb").read()
rel.target_part._blob = new_bytes

# update display extent (wp:extent) and image natural size (a:ext)
W_EMU = int(6.0 * 914400)
H_EMU = int(W_EMU / (2240 / 1840.0))
for ext in img._p.iter('{%s}extent' % NS_WP):
    ext.set('cx', str(W_EMU))
    ext.set('cy', str(H_EMU))
for aext in blip.iter('{%s}ext' % NS_A):
    aext.set('cx', str(W_EMU))
    aext.set('cy', str(H_EMU))
print("extent set to", W_EMU, H_EMU)

d.save(DST)
print("saved", DST)
