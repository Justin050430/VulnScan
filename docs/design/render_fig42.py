# -*- coding: utf-8 -*-
"""
Render Fig4.2_Deployment_Diagram.drawio -> monochrome PNG (white boxes, black lines).
Handles container nesting (children get parent origin added) and labelled edges.
Same conventions as the other VulnScan figure PNGs (2x scale, white box fill).
Run:  python docs/design/render_fig42.py
"""
import os, re, sys, math
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

SCALE = 2.0
MARGIN = 10
ARIAL = r"C:\Windows\Fonts\arial.ttf"
ARIALBD = r"C:\Windows\Fonts\arialbd.ttf"

def _local(tag):
    return tag.split("}")[-1]

def _first(el, name):
    for c in el.iter():
        if _local(c.tag) == name:
            return c
    return None

_font_cache = {}
def _font(px, bold):
    key = (px, bold)
    if key not in _font_cache:
        try:
            _font_cache[key] = ImageFont.truetype(ARIALBD if bold else ARIAL, px)
        except Exception:
            _font_cache[key] = ImageFont.load_default()
    return _font_cache[key]

def _label_parts(value):
    """-> (plain_text_with_newlines, bold)"""
    bold = ("<b>" in value) or ("font-weight: 700" in value)
    s = value
    s = re.sub(r"<br\s*/?>", "\n", s)
    s = re.sub(r"</?div[^>]*>", "\n", s)
    s = s.replace("<b>", "").replace("</b>", "")
    s = re.sub(r"<[^>]+>", "", s)
    s = s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return s, bold

def _wrap(text, font, max_w):
    lines = []
    for raw in text.split("\n"):
        words = raw.split(" ")
        cur = ""
        for w in words:
            trial = ((cur + " " + w).strip())
            if not cur or font.getlength(trial) <= max_w:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = w
        lines.append(cur)
    return lines

def render(src, dst):
    tree = ET.parse(src)
    root = tree.getroot()
    model = None
    for el in root.iter():
        if _local(el.tag) == "mxGraphModel":
            model = el
            break
    if model is None:
        raise RuntimeError("no mxGraphModel")
    pw = float(model.get("pageWidth", "1200"))
    ph = float(model.get("pageHeight", "880"))

    cells = {}
    order = []
    for el in root.iter():
        if _local(el.tag) == "mxCell":
            cells[el.get("id")] = el
            if el.get("vertex") == "1" or el.get("edge") == "1":
                order.append(el)

    def geom_abs(cell):
        # sum ancestor container origins (container vertices that parent this cell)
        ox = oy = 0.0
        cur = cell
        while cur is not None:
            par = cells.get(cur.get("parent"))
            if par is not None and par.get("vertex") == "1":
                g = _first(par, "mxGeometry")
                if g is not None and g.get("x") is not None:
                    ox += float(g.get("x"))
                    oy += float(g.get("y"))
            cur = par
        g = _first(cell, "mxGeometry")
        if g is None:
            return None
        x = ox + float(g.get("x") or 0)
        y = oy + float(g.get("y") or 0)
        w = float(g.get("width") or 0)
        h = float(g.get("height") or 0)
        pts = []
        arr = g.find("Array")
        if arr is not None:
            for p in arr.findall("mxPoint"):
                pts.append((float(p.get("x")), float(p.get("y"))))
        return {"x": x, "y": y, "w": w, "h": h, "pts": pts}

    verts = []
    edges = []
    for cell in order:
        style = cell.get("style") or ""
        if cell.get("vertex") == "1":
            ga = geom_abs(cell)
            if ga is None:
                continue
            verts.append({"el": cell, "geo": ga, "style": style,
                          "container": any(v.get("parent") == cell.get("id") and v.get("vertex") == "1"
                                           for v in root.iter() if _local(v.tag) == "mxCell")})
        elif cell.get("edge") == "1":
            ga = geom_abs(cell)
            edges.append({"pts": ga["pts"] if ga else [], "label": cell.get("value") or ""})

    S = SCALE
    W = int((pw + 2 * MARGIN) * S)
    H = int((ph + 2 * MARGIN) * S)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    X = lambda u: (u + MARGIN) * S
    Y = lambda v: (v + MARGIN) * S

    # ---- edges ----
    for e in edges:
        pts = e["pts"]
        if len(pts) < 2:
            continue
        xy = [(X(px), Y(py)) for (px, py) in pts]
        d.line(xy, fill="black", width=max(2, int(1.3 * S)))
        x0, y0 = xy[-2]; x1, y1 = xy[-1]
        ang = math.atan2(y1 - y0, x1 - x0)
        sz = 7 * S
        a1 = ang + math.pi * 0.78; a2 = ang - math.pi * 0.78
        d.polygon([(x1, y1),
                   (x1 + sz * math.cos(a1), y1 + sz * math.sin(a1)),
                   (x1 + sz * math.cos(a2), y1 + sz * math.sin(a2))], fill="black")
        # label placement on longest segment
        best = None
        for (ax, ay), (bx, by) in zip(xy, xy[1:]):
            ln = abs(bx - ax) + abs(by - ay)
            if best is None or ln > best[0]:
                best = (ln, ((ax + bx) / 2, (ay + by) / 2), abs(bx - ax) < abs(by - ay))
        if best and e["label"]:
            _ln, mid, vertical = best
            mx, my = mid
            fnt = _font(int(8.5 * S), False)
            txt = e["label"].replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            bb = d.textbbox((0, 0), txt, font=fnt)
            tw, th = bb[2] - bb[0], bb[3] - bb[1]
            if vertical:
                lx, ly = mx + 9, my - th / 2
            else:
                lx, ly = mx - tw / 2, my - th - 5
            d.rectangle([lx - 3, ly - 2, lx + tw + 3, ly + th + 2], fill="white")
            d.text((lx, ly), txt, font=fnt, fill="black")

    # ---- boxes ----
    for v in verts:
        x0, y0, x1, y1 = X(v["geo"]["x"]), Y(v["geo"]["y"]), X(v["geo"]["x"] + v["geo"]["w"]), Y(v["geo"]["y"] + v["geo"]["h"])
        d.rectangle([x0, y0, x1, y1], fill="white", outline="black", width=max(2, int(1.4 * S)))

    # ---- labels ----
    for v in verts:
        val = v["el"].get("value") or ""
        if not val.strip():
            continue
        text, bold = _label_parts(val)
        fnt = _font(int(10.5 * S), bold)
        box_w = (v["geo"]["w"] - 8)
        lines = _wrap(text, fnt, X(box_w) - X(0))
        lh = int(fnt.size * 1.28)
        x0, y0 = X(v["geo"]["x"]), Y(v["geo"]["y"])
        wpx = X(v["geo"]["w"]) - X(0)
        if v["container"]:
            # title at top, centred horizontally
            ty = y0 + 8
        else:
            ty = y0 + (Y(v["geo"]["h"]) - Y(0) - lh * len(lines)) / 2
        for ln in lines:
            tw = fnt.getlength(ln)
            d.text((x0 + (wpx - tw) / 2, ty), ln, font=fnt, fill="black")
            ty += lh

    os.makedirs(os.path.dirname(dst), exist_ok=True)
    img.save(dst)
    print("saved", dst, img.size)

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else r"c:\FYP\VulnScan\docs\design\Fig4.2_Deployment_Diagram.drawio"
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".png"
    render(src, dst)
