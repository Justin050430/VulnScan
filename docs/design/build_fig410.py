# -*- coding: utf-8 -*-
"""Build Fig4.10 Vulnerability Scanning Activity Diagram .drawio (monochrome UML activity)."""
OUT = r"c:\FYP\VulnScan\docs\design\Fig4.10_Scan_Activity_Diagram.drawio"

V, E = [], []
def vx(_id, x, y, w, h, label, style):
    V.append((_id, x, y, w, h, label, style))
def edge(_id, src, tgt, pts, label=""):
    E.append((_id, src, tgt, pts, label))

ACT = "rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"
DIA = "rhombus;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"

vx("start", 360, 20, 40, 40, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")
vx("a1", 230, 90, 300, 64, "Developer provides a target URL and selects a scan profile", ACT)
vx("a2", 230, 190, 300, 64, "System validates target URL and scan profile", ACT)
vx("d1", 345, 300, 70, 70, "Valid?", DIA)
vx("err", 560, 150, 180, 64, "Display validation error", ACT)
vx("a3", 230, 470, 300, 64, "Web crawler discovers pages (stored as DiscoveredPage)", ACT)
vx("d2", 345, 590, 70, 70, "More pages?", DIA)
vx("a4", 230, 760, 300, 72, "Run enabled detection modules and record Findings (severity, risk, evidence)", ACT)
vx("a5", 560, 760, 180, 64, "Update scan status to Completed", ACT)
vx("a6", 560, 870, 180, 64, "Present scan results to Developer", ACT)
vx("endOuter", 650, 990, 40, 40, "", "ellipse;ringNode;fillColor=#FFFFFF;strokeColor=#000000;")
vx("endInner", 664, 1004, 12, 12, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")

AST = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;targetArrow=classic;"
ASTN = AST + "endArrow=none;"

edge("e1", "start", "a1", [(380, 60), (380, 90)])
edge("e2", "a1", "a2", [(380, 154), (380, 190)])
edge("e3", "a2", "d1", [(380, 254), (380, 300)])
edge("e4", "d1", "err", [(415, 335), (500, 335), (500, 182), (560, 182)], "No")
edge("e5", "err", "a1", [(560, 182), (490, 182), (490, 120), (230, 120)])
edge("e6", "d1", "a3", [(380, 370), (380, 470)], "Yes")
edge("e7", "a3", "d2", [(380, 534), (380, 590)])
edge("e8", "d2", "a4", [(380, 660), (380, 760)], "Yes")
edge("e9", "a4", "d2", [(230, 796), (150, 796), (150, 625), (345, 625)])
edge("e10", "d2", "a5", [(415, 625), (500, 625), (500, 792), (560, 792)], "No")
edge("e11", "a5", "a6", [(650, 824), (650, 870)])
edge("e12", "a6", "endOuter", [(650, 934), (650, 990)])

lines = []
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
lines.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
lines.append('  <diagram id="fig4-10-scan-activity" name="Fig4.10 Vulnerability Scanning Activity Diagram">')
lines.append('    <mxGraphModel dx="700" dy="1000" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="780" pageHeight="1080" math="0" shadow="0">')
lines.append('      <root>')
lines.append('        <mxCell id="0" />')
lines.append('        <mxCell id="1" parent="0" />')
for (_id, x, y, w, h, label, style) in V:
    lines.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{style}" vertex="1" parent="1">')
    lines.append(f'          <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />')
    lines.append('        </mxCell>')
for (_id, src, tgt, pts, label) in E:
    style = AST if _id not in ("e4", "e10") else ASTN
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
