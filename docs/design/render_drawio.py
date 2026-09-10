# -*- coding: utf-8 -*-
"""
Minimal monochrome renderer for the simple draw.io subset used in VulnScan figures.
Reads .drawio (mxGraphModel) -> PNG. Supports: plain/rounded rects with labels,
layer containers (fill=none), orthogonal polylines via explicit edge <mxPoint>s
(fallback: simple L/Z orthogonal routing between centres).
"""
import sys, os, re, math
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

NS = "http://www.w3.org/1999/xhtml"
SCALE = 2.0
MARGIN = 10

def _no_ns(tag):
    return tag.split('}')[-1]

def load(path):
    tree = ET.parse(path)
    root = tree.getroot()
    # first mxGraphModel
    model = None
    for el in root.iter():
        if _no_ns(el.tag) == "mxGraphModel":
            model = el
            break
    return model

def cells(model):
    out = []
    for el in model.iter():
        if _no_ns(el.tag) == "mxCell":
            out.append(el)
    return out

def cell_text(el):
    return el.get("value") or ""

def cell_geom(el):
    g = el.find(".//*mxGeometry") or el.find(".//{*}mxGeometry")
    return g

def parse_points(el):
    """Return list of (x,y) waypoints from <Array as='points'> in geometry."""
    pts = []
    if el is None:
        return pts
    arr = el.find("{*}Array")
    if arr is None:
        arr = el.find("Array")
    if arr is not None:
        for p in arr.findall("{*}mxPoint"):
            pts.append((float(p.get("x")), float(p.get("y"))))
    return pts

class FONT:
    reg = None
    bold = None
    def ensure(self, size):
        sz = int(round(size * SCALE))
        key = sz
        if self.reg is None:
            self.reg = {}
            self.bold = {}
        if key not in self.reg:
            try:
                self.reg[key] = ImageFont.truetype(r"C:\Windows\Fonts\arial.ttf", sz)
            except Exception:
                self.reg[key] = ImageFont.load_default()
            try:
                self.bold[key] = ImageFont.truetype(r"C:\Windows\Fonts\arialbd.ttf", sz)
            except Exception:
                self.bold[key] = self.reg[key]
        return self.reg[key], self.bold[key]

F = FONT()

def wrap_text(text, font, max_w):
    lines = text.split("\n")
    out = []
    for ln in lines:
        words = ln.split(" ")
        cur = ""
        for w in words:
            trial = (cur + " " + w).strip()
            if font.getlength(trial) <= max_w or not cur:
                cur = trial
            else:
                out.append(cur)
                cur = w
        out.append(cur)
    return out

def draw_centered(draw, x, y, w, h, text, bold=False, size=11, fill="black"):
    reg, bd = F.ensure(size)
    font = bd if bold else reg
    max_w = w - 8
    lines = wrap_text(text, font, max_w)
    lh = int(font.size * 1.25)
    total = lh * len(lines)
    ty = y + (h - total) / 2
    for ln in lines:
        tw = font.getlength(ln)
        draw.text((x + (w - tw) / 2, ty), ln, font=font, fill=fill)
        ty += lh

def draw_topleft(draw, x, y, w, text, bold=False, size=11, fill="black", pad=6):
    reg, bd = F.ensure(size)
    font = bd if bold else reg
    draw.text((x + pad, y + pad), text, font=font, fill=fill)

def arrow_head(draw, x, y, angle, size=7):
    import math as _m
    a1 = angle + _m.pi * 0.8
    a2 = angle - _m.pi * 0.8
    p1 = (x + size * _m.cos(a1), y + size * _m.sin(a1))
    p2 = (x + size * _m.cos(a2), y + size * _m.sin(a2))
    draw.polygon([(x, y), p1, p2], outline="black", fill="black")

def render(drawio_path, png_path):
    model = load(drawio_path)
    if model is None:
        raise RuntimeError("no mxGraphModel")
    # page size
    pw = float(model.get("pageWidth", "1100"))
    ph = float(model.get("pageHeight", "900"))
    cs = cells(model)
    # vertices in file order
    verts = []
    edges = []
    for el in cs:
        v = el.get("vertex") == "1"
        e = el.get("edge") == "1"
        if v:
            g = cell_geom(el)
            x = float(g.get("x")); y = float(g.get("y"))
            w = float(g.get("width")); h = float(g.get("height"))
            style = el.get("style") or ""
            verts.append({"el": el, "x": x, "y": y, "w": w, "h": h,
                          "fill_none": ("fillColor=none" in style),
                          "label_align": ("align=left" in style)})
        elif e:
            edges.append({"el": el, "src": el.get("source"), "tgt": el.get("target"),
                          "pts": parse_points(el)})

    def rect_of(cid):
        for v in verts:
            if v["el"].get("id") == cid:
                return v
        return None

    # canvas size
    W = (pw + 2 * MARGIN) * SCALE
    H = (ph + 2 * MARGIN) * SCALE
    img = Image.new("RGB", (int(W), int(H)), "white")
    draw = ImageDraw.Draw(img)
    X = lambda px: (px + MARGIN) * SCALE
    Y = lambda py: (py + MARGIN) * SCALE

    # resolve edge polylines
    polylines = []
    for e in edges:
        src = rect_of(e["src"]); tgt = rect_of(e["tgt"])
        if src is None or tgt is None:
            continue
        pts = [(p[0], p[1]) for p in e["pts"]]
        if not pts:
            # fallback orthogonal
            sx, sy, sw, sh = src["x"], src["y"], src["w"], src["h"]
            tx, ty, tw, th = tgt["x"], tgt["y"], tgt["w"], tgt["h"]
            sc = (sx + sw / 2, sy + sh / 2); tc = (tx + tw / 2, ty + th / 2)
            if tc[1] > sc[1]:
                a = (sc[0], sy + sh); b = (tc[0], ty)
                if abs(a[0] - b[0]) < 1:
                    pts = [a, b]
                else:
                    my = (a[1] + b[1]) / 2
                    pts = [a, (a[0], my), (b[0], my), b]
            elif tc[1] < sc[1]:
                a = (sc[0], sy); b = (tc[0], ty + th)
                if abs(a[0] - b[0]) < 1:
                    pts = [a, b]
                else:
                    my = (a[1] + b[1]) / 2
                    pts = [a, (a[0], my), (b[0], my), b]
            else:
                a = (sx + sw, sc[1]); b = (tx, tc[1])
                mx = (a[0] + b[0]) / 2
                pts = [a, (mx, a[1]), (mx, b[1]), b]
        polylines.append(pts)

    # 1) edges (under boxes)
    for pts in polylines:
        xy = [ (X(px), Y(py)) for (px, py) in pts ]
        draw.line(xy, fill="black", width=max(1, int(1.2 * SCALE)))
        # arrow head at end
        if len(xy) >= 2:
            x0, y0 = xy[-2]; x1, y1 = xy[-1]
            ang = math.atan2(y1 - y0, x1 - x0)
            arrow_head(draw, x1, y1, ang, size=6 * SCALE)

    # 2) containers (fill none) & boxes
    for v in verts:
        x0, y0 = X(v["x"]), Y(v["y"])
        x1, y1 = X(v["x"] + v["w"]), Y(v["y"] + v["h"])
        if v["fill_none"]:
            draw.rectangle([x0, y0, x1, y1], outline="black", width=max(1, int(1.2 * SCALE)))
        else:
            draw.rectangle([x0, y0, x1, y1], fill="white", outline="black", width=max(1, int(1.2 * SCALE)))

    # 3) labels
    for v in verts:
        label = cell_text(v["el"])
        if not label.strip():
            continue
        style = v["el"].get("style") or ""
        bold = ("fontStyle=1" in style)
        size = 11
        m = re.search(r"fontSize=(\d+)", style)
        if m:
            size = int(m.group(1))
        if v["fill_none"]:
            draw_topleft(draw, X(v["x"]), Y(v["y"]), X(1), label.replace("\n", " "), bold=True, size=size)
            # top-left label -> put as text at top-left of the container
            # (reuse draw_topleft but at coords)
        else:
            draw_centered(draw, X(v["x"]), Y(v["y"]), X(v["w"]) - X(0), Y(v["h"]) - Y(0),
                          label.replace("\n", " \n ").replace(" \n ", "\n"), bold=bold, size=size)
    img.save(png_path)
    print("saved", png_path, img.size)

if __name__ == "__main__":
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".png"
    render(src, dst)
