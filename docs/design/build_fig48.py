# -*- coding: utf-8 -*-
"""Build Fig4.8 Use Case Diagram .drawio (monochrome, orthogonal)."""
import os

V = []  # vertices
E = []  # edges
OUT = r"c:\FYP\VulnScan\docs\design\Fig4.8_Use_Case_Diagram.drawio"

def vx(_id, x, y, w, h, label, style):
    V.append((_id, x, y, w, h, label, style))

def edge(_id, src, tgt, pts):
    E.append((_id, src, tgt, pts))

# Actors (stick figures)
vx("aAdmin", 40, 300, 120, 130, "Administrator", "shape=actor;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;")
vx("aDev", 1120, 300, 120, 130, "Developer", "shape=actor;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;")

# System boundary
vx("boundary", 260, 60, 780, 680, "VulnScan", "rounded=0;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#000000;verticalAlign=top;align=center;fontStyle=1;fontSize=12;")

def uc(_id, x, y, label):
    vx(_id, x, y, 170, 58, label, "ellipse;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;")

# Shared
uc("uSign", 565, 100, "Sign In")
uc("uKB", 565, 645, "View Vulnerability Knowledge Base")
# Administrator
uc("uUsers", 300, 175, "Manage User Accounts")
uc("uProfiles", 300, 265, "Manage Scan Profiles")
uc("uVulnDef", 300, 355, "Manage Vulnerability Definitions")
uc("uAudit", 300, 445, "View Audit Logs")
# Developer
uc("uScan", 830, 175, "Start Vulnerability Scan")
uc("uResults", 830, 265, "View Scan Results")
uc("uReport", 830, 355, "Generate / Export Scan Report")

# central row of each oval (y + h/2) so horizontal lines hit the oval's left/right extremes
center = {"uSign": 129, "uKB": 674, "uUsers": 204, "uProfiles": 294,
          "uVulnDef": 384, "uAudit": 474, "uScan": 204, "uResults": 294, "uReport": 384}
left  = {"uSign": 565, "uKB": 565, "uUsers": 300, "uProfiles": 300, "uVulnDef": 300, "uAudit": 300}
right = {"uScan": 1000, "uResults": 1000, "uReport": 1000, "uSign": 735, "uKB": 735}

# Association style
AST = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;endArrow=none;"

# --- Administrator routes (bus x=278) ---
ax = 160          # actor right
busA = 278
a_center_y = 360
def admin_route(row, target_left):
    return [(ax, a_center_y), (busA, a_center_y), (busA, row), (target_left, row)]

edge("eA1", "aAdmin", "uUsers", admin_route(center["uUsers"], left["uUsers"]))
edge("eA2", "aAdmin", "uProfiles", admin_route(center["uProfiles"], left["uProfiles"]))
edge("eA3", "aAdmin", "uVulnDef", admin_route(center["uVulnDef"], left["uVulnDef"]))
edge("eA4", "aAdmin", "uAudit", admin_route(center["uAudit"], left["uAudit"]))
edge("eA5", "aAdmin", "uSign", admin_route(center["uSign"], left["uSign"]))
edge("eA6", "aAdmin", "uKB", admin_route(center["uKB"], left["uKB"]))

# --- Developer routes (bus x=1015) ---
dx = 1080         # actor left
busD = 1015
def dev_route(row, target_right):
    return [(dx, a_center_y), (busD, a_center_y), (busD, row), (target_right, row)]

edge("eD1", "aDev", "uScan", dev_route(center["uScan"], right["uScan"]))
edge("eD2", "aDev", "uResults", dev_route(center["uResults"], right["uResults"]))
edge("eD3", "aDev", "uReport", dev_route(center["uReport"], right["uReport"]))
edge("eD4", "aDev", "uSign", dev_route(center["uSign"], right["uSign"]))
edge("eD5", "aDev", "uKB", dev_route(center["uKB"], right["uKB"]))

# ---------------- XML ----------------
def xml_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

lines = []
lines.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
lines.append('  <diagram id="fig4-8-usecase" name="Fig4.8 System Use Case Diagram">')
lines.append('    <mxGraphModel dx="1100" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1280" pageHeight="820" math="0" shadow="0">')
lines.append('      <root>')
lines.append('        <mxCell id="0" />')
lines.append('        <mxCell id="1" parent="0" />')
for (_id, x, y, w, h, label, style) in V:
    lines.append(f'        <mxCell id="{_id}" value="{xml_escape(label)}" style="{style}" vertex="1" parent="1">')
    lines.append(f'          <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />')
    lines.append('        </mxCell>')
for (_id, src, tgt, pts) in E:
    lines.append(f'        <mxCell id="{_id}" style="{AST}" edge="1" parent="1" source="{src}" target="{tgt}">')
    lines.append('          <mxGeometry relative="1" as="geometry">')
    lines.append('            <Array as="points">')
    for (px, py) in pts:
        lines.append(f'              <mxPoint x="{px}" y="{py}" />')
    lines.append('            </Array>')
    lines.append('          </mxGeometry>')
    lines.append('        </mxCell>')
lines.append('      </root>')
lines.append('    </mxGraphModel>')
lines.append('  </diagram>')
lines.append('</mxfile>')

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print("wrote", OUT, len(V), "vertices", len(E), "edges")
