# -*- coding: utf-8 -*-
"""
Minimal monochrome renderer for the simple draw.io subset used in VulnScan figures.
Reads .drawio (mxGraphModel) -> PNG.
Supports: rectangles with centred or top-left labels, layer containers (fillColor=none),
orthogonal edge polylines via explicit <mxPoint>s inside edge geometry.
Usage: python drawio_render.py <file.drawio> [out.png]
"""
import sys, os, re, math
import xml.etree.ElementTree as ET
from PIL import Image, ImageDraw, ImageFont

SCALE = 2.0
MARGIN = 10

def local(tag):
    return tag.split('}')[-1]

def descendants(el, name):
    return [c for c in el.iter() if local(c.tag) == name]

def first(el, name):
    for c in el.iter():
        if local(c.tag) == name:
            return c
    return None

class Fonts:
    cache = {}
    def get(self, size_px, bold):
        key = (size_px, bold)
        if key not in self.cache:
            try:
                path = r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf"
                self.cache[key] = ImageFont.truetype(path, size_px)
            except Exception:
                self.cache[key] = ImageFont.load_default()
        return self.cache[key]

_F = Fonts()

def parse_geometry(el):
    g = first(el, "mxGeometry")
    if g is None:
        return None
    x = float(g.get("x") or 0); y = float(g.get("y") or 0)
    w = float(g.get("width") or 0); h = float(g.get("height") or 0)
    pts = []
    arr = first(g, "Array")
    if arr is not None:
        for p in descendants(arr, "mxPoint"):
            pts.append((float(p.get("x")), float(p.get("y"))))
    return {"x": x, "y": y, "w": w, "h": h, "pts": pts}

def wrap(text, font, max_w):
    lines = []
    for raw in text.split("\n"):
        words = raw.split(" ")
        cur = ""
        for w in words:
            trial = (cur + " " + w).strip()
            if not cur or font.getlength(trial) <= max_w:
                cur = trial
            else:
                lines.append(cur)
                cur = w
        lines.append(cur)
    return lines

def render(src, dst):
    tree = ET.parse(src)
    root = tree.getroot()
    model = first(root, "mxGraphModel")
    if model is None:
        raise RuntimeError("no mxGraphModel")
    pw = float(model.get("pageWidth", "1100"))
    ph = float(model.get("pageHeight", "900"))

    verts = []
    edges = []
    for el in descendants(root, "mxCell"):
        if el.get("vertex") == "1":
            geo = parse_geometry(el)
            if geo is None:
                continue
            style = el.get("style") or ""
            verts.append({"id": el.get("id"), "x": geo["x"], "y": geo["y"],
                          "w": geo["w"], "h": geo["h"],
                          "label": el.get("value") or "",
                          "fill_none": "fillColor=none" in style,
                          "align_center": "align=center" in style,
                          "bold": "fontStyle=1" in style,
                          "actor": "shape=actor" in style,
                          "lifeline": "lifeline" in style,
                          "diamond": "rhombus" in style,
                          "rounded": "rounded=1" in style and "shape=actor" not in style,
                          "filled_node": "fillNode" in style,
                          "ring_node": "ringNode" in style,
                          "ellipse": ("shape=ellipse" in style) or ("ellipse;" in style or style.strip().startswith("ellipse")),
                          "size": 11})
            m = re.search(r"fontSize=(\d+)", style)
            if m:
                verts[-1]["size"] = int(m.group(1))
        elif el.get("edge") == "1":
            geo = parse_geometry(el)
            style = el.get("style") or ""
            edges.append({"src": el.get("source"), "tgt": el.get("target"),
                          "pts": geo["pts"] if geo else [],
                          "label": el.get("value") or "",
                          "arrow": "endArrow=none" not in style,
                          "dashed": "dashed=1" in style,
                          "open": "endArrow=open" in style or "startArrow=open" in style})

    byid = {v["id"]: v for v in verts}
    S = SCALE
    W = int((pw + 2 * MARGIN) * S)
    H = int((ph + 2 * MARGIN) * S)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    X = lambda u: (u + MARGIN) * S
    Y = lambda u: (u + MARGIN) * S

    polys = []
    for e in edges:
        s = byid.get(e["src"]); t = byid.get(e["tgt"])
        if s is None or t is None:
            continue
        if e["pts"]:
            pts = e["pts"]
        else:
            sc = (s["x"] + s["w"] / 2, s["y"] + s["h"] / 2)
            tc = (t["x"] + t["w"] / 2, t["y"] + t["h"] / 2)
            if tc[1] > sc[1] + 1:
                a = (sc[0], s["y"] + s["h"]); b = (tc[0], t["y"])
                if abs(a[0] - b[0]) < 1:
                    pts = [a, b]
                else:
                    my = (a[1] + b[1]) / 2
                    pts = [a, (a[0], my), (b[0], my), b]
            elif tc[1] < sc[1] - 1:
                a = (sc[0], s["y"]); b = (tc[0], t["y"] + t["h"])
                if abs(a[0] - b[0]) < 1:
                    pts = [a, b]
                else:
                    my = (a[1] + b[1]) / 2
                    pts = [a, (a[0], my), (b[0], my), b]
            else:
                a = (s["x"] + s["w"], sc[1]); b = (t["x"], tc[1])
                mx = (a[0] + b[0]) / 2
                pts = [a, (mx, a[1]), (mx, b[1]), b]
        polys.append([(X(px), Y(py)) for (px, py) in pts])

    lw = max(1, int(1.2 * S))
    for idx, pts in enumerate(polys):
        e = edges[idx]
        if e["dashed"]:
            dash = (6 * S, 4 * S)
            for a, b in zip(pts[:-1], pts[1:]):
                d.line([a, b], fill="black", width=lw, joint="curve")
            # re-draw with dash pattern by segments
            for a, b in zip(pts[:-1], pts[1:]):
                x0, y0 = a; x1, y1 = b
                length = max(abs(x1 - x0), abs(y1 - y0))
                if length == 0:
                    continue
                dx = (x1 - x0) / length; dy = (y1 - y0) / length
                t = 0.0; on = True
                while t < length:
                    seg = min(dash[0] if on else dash[1], length - t)
                    if on:
                        d.line([(x0 + dx * t, y0 + dy * t), (x0 + dx * (t + seg), y0 + dy * (t + seg))], fill="black", width=lw)
                    t += seg; on = not on
        else:
            d.line(pts, fill="black", width=lw)
        if len(pts) >= 2 and e["arrow"]:
            x0, y0 = pts[-2]; x1, y1 = pts[-1]
            ang = math.atan2(y1 - y0, x1 - x0)
            s_ = 6 * S
            if e["open"]:
                for da in (math.pi * 0.75, -math.pi * 0.75):
                    d.line([(x1, y1), (x1 + s_ * math.cos(ang + da), y1 + s_ * math.sin(ang + da))], fill="black", width=lw)
            else:
                a1 = ang + math.pi * 0.8; a2 = ang - math.pi * 0.8
                d.polygon([(x1, y1), (x1 + s_ * math.cos(a1), y1 + s_ * math.sin(a1)),
                           (x1 + s_ * math.cos(a2), y1 + s_ * math.sin(a2))], outline="black", fill="black")

    for v in verts:
        x0, y0 = X(v["x"]), Y(v["y"])
        x1, y1 = X(v["x"] + v["w"]), Y(v["y"] + v["h"])
        if v["lifeline"]:
            cx = (x0 + x1) / 2
            dash = (4 * S, 4 * S)
            length = y1 - y0
            t = 0.0; on = True
            while t < length:
                seg = min(dash[0] if on else dash[1], length - t)
                if on:
                    d.line([(cx, y0 + t), (cx, y0 + t + seg)], fill="black", width=lw)
                t += seg; on = not on
            continue
        if v["actor"]:
            continue  # drawn separately below
        if v["filled_node"]:
            cx = (x0 + x1) / 2; cy = (y0 + y1) / 2
            r = min(wpx := (x1 - x0), hpx := (y1 - y0)) / 2
            d.ellipse([cx - r, cy - r, cx + r, cy + r], outline="black", fill="black", width=1)
            continue
        if v["ring_node"]:
            cx = (x0 + x1) / 2; cy = (y0 + y1) / 2
            r = min(x1 - x0, y1 - y0) / 2
            d.ellipse([cx - r, cy - r, cx + r, cy + r], outline="black", fill="white", width=lw)
            continue
        if v["diamond"]:
            cx = (x0 + x1) / 2; cy = (y0 + y1) / 2
            d.polygon([(cx, y0), (x1, cy), (cx, y1), (x0, cy)], outline="black", fill="white", width=lw)
            continue
        if v["ellipse"]:
            d.ellipse([x0, y0, x1, y1], outline="black", width=lw, fill="white")
        elif v["fill_none"]:
            d.rectangle([x0, y0, x1, y1], outline="black", width=lw)
        elif v["rounded"]:
            d.rounded_rectangle([x0, y0, x1, y1], radius=int(10 * S), outline="black", width=lw, fill="white")
        else:
            d.rectangle([x0, y0, x1, y1], fill="white", outline="black", width=lw)

    # edge labels at polyline midpoint
    for idx, pts in enumerate(polys):
        lab = edges[idx]["label"]
        if not lab:
            continue
        lab = lab.replace("&#10;", " ")
        xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
        mx = (min(xs) + max(xs)) / 2
        my = (min(ys) + max(ys)) / 2
        font = _F.get(int(10 * S), False)
        tw = font.getlength(lab)
        d.text((mx - tw / 2, my - font.size - 2), lab, font=font, fill="black")

    for v in verts:
        label = v["label"].replace("&#10;", "\n")
        fs = v["size"]
        x0, y0 = X(v["x"]), Y(v["y"])
        wpx, hpx = v["w"] * S, v["h"] * S
        if v["lifeline"]:
            continue
        if v["actor"]:
            # stick figure: head circle, body, arms, legs; label beneath
            cx = x0 + wpx / 2
            head_r = min(10 * S, wpx * 0.18, hpx * 0.12)
            hy = y0 + hpx * 0.18
            d.ellipse([cx - head_r, hy - head_r, cx + head_r, hy + head_r], outline="black", width=lw)
            body_top = hy + head_r
            body_bot = y0 + hpx * 0.62
            d.line([cx, body_top, cx, body_bot], fill="black", width=lw)
            d.line([cx - head_r * 1.6, hy + head_r * 0.6, cx + head_r * 1.6, hy + head_r * 0.6], fill="black", width=lw)
            d.line([x0 + wpx * 0.12, y0 + hpx * 0.88, cx, body_bot], fill="black", width=lw)
            d.line([x0 + wpx * 0.88, y0 + hpx * 0.88, cx, body_bot], fill="black", width=lw)
            font = _F.get(int(11 * S), False)
            if label.strip():
                tw = font.getlength(label)
                d.text((x0 + (wpx - tw) / 2, y0 + hpx * 0.72), label, font=font, fill="black")
            continue
        if not label.strip():
            continue
        if v["fill_none"] and not v["ellipse"]:
            font = _F.get(int(fs * S), True)
            if v.get("align_center"):
                tw = font.getlength(label.replace("\n", " "))
                d.text((x0 + (wpx - tw) / 2, y0 + 6), label.replace("\n", " "), font=font, fill="black")
            else:
                d.text((x0 + 6, y0 + 6), label.replace("\n", " "), font=font, fill="black")
        else:
            font = _F.get(int(fs * S), v["bold"])
            max_w = wpx - 12
            lines = wrap(label, font, max_w)
            lh = int(font.size * 1.25)
            ty = y0 + (hpx - lh * len(lines)) / 2
            for ln in lines:
                tw = font.getlength(ln)
                d.text((x0 + (wpx - tw) / 2, ty), ln, font=font, fill="black")
                ty += lh

    img.save(dst)
    print("saved", dst, img.size)

if __name__ == "__main__":
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + ".png"
    render(src, dst)
