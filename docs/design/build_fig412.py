# -*- coding: utf-8 -*-
"""Build Fig4.12 Security Audit Logging Activity Diagram .drawio (vertical swimlanes, monochrome)."""
OUT = r"c:\FYP\VulnScan\docs\design\Fig4.12_Audit_Activity_Diagram.drawio"

V, E = [], []
def vx(_id, x, y, w, h, label, style):
    V.append((_id, x, y, w, h, label, style))
def edge(_id, src, tgt, pts, label="", arrow=True):
    E.append((_id, src, tgt, pts, label, arrow))

ACT = "rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"
DIA = "rhombus;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"

# ---- vertical swimlane partitions ----
vx("laneSys", 40, 50, 420, 720, "VulnScan System (Business Logic)",
   "rounded=0;fillColor=none;strokeColor=#000000;align=center;fontStyle=1;fontSize=12;")
vx("laneDb", 470, 50, 400, 720, "SecurityAuditLog (Database)",
   "rounded=0;fillColor=none;strokeColor=#000000;align=center;fontStyle=1;fontSize=12;")

# ---- nodes ----
vx("start", 230, 110, 40, 40, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")
vx("a1", 120, 180, 260, 60, "Significant action occurs (authentication, scan, administrative operation)", ACT)
vx("a2", 120, 290, 260, 60, "Capture event context (user, IP address, entity, timestamp)", ACT)
vx("d1", 215, 400, 70, 70, "Significant event?", DIA)
vx("a3", 110, 560, 220, 60, "Discard event (no record)", ACT)
vx("a4", 260, 560, 190, 60, "Compose audit record (category, action, description)", ACT)
vx("a5", 520, 560, 300, 60, "Insert audit record into SecurityAuditLog", ACT)
vx("fin1", 210, 690, 40, 40, "", "ellipse;ringNode;fillColor=#FFFFFF;strokeColor=#000000;")
vx("fin1i", 224, 704, 12, 12, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")
vx("fin2", 650, 690, 40, 40, "", "ellipse;ringNode;fillColor=#FFFFFF;strokeColor=#000000;")
vx("fin2i", 664, 704, 12, 12, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")

def _e(_id, src, tgt, pts, label="", arrow=True):
    edge(_id, src, tgt, pts, label, arrow)

_e("e1", "start", "a1", [(250, 150), (250, 180)])
_e("e2", "a1", "a2", [(250, 240), (250, 290)])
_e("e3", "a2", "d1", [(250, 350), (250, 400)])
_e("e4", "d1", "a3", [(215, 435), (215, 560)], "No")
_e("e5", "d1", "a4", [(250, 470), (250, 560)], "Yes")
_e("e6", "a3", "fin1", [(220, 620), (220, 690)])
_e("e7", "a4", "a5", [(450, 590), (520, 590)])
_e("e8", "a5", "fin2", [(670, 620), (670, 690)])

lines = []
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
lines.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
lines.append('  <diagram id="fig4-12-audit-activity" name="Fig4.12 Security Audit Logging Activity Diagram">')
lines.append('    <mxGraphModel dx="800" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="920" pageHeight="840" math="0" shadow="0">')
lines.append('      <root>')
lines.append('        <mxCell id="0" />')
lines.append('        <mxCell id="1" parent="0" />')
for (_id, x, y, w, h, label, style) in V:
    lines.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{style}" vertex="1" parent="1">')
    lines.append(f'          <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />')
    lines.append('        </mxCell>')
for (_id, src, tgt, pts, label, arrow) in E:
    style = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;"
    style += "targetArrow=classic;" if arrow else "endArrow=none;"
    lines.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{style}" edge="1" parent="1" source="{src}" target="{tgt}">')
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
open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("wrote", OUT, len(V), "vertices", len(E), "edges")
