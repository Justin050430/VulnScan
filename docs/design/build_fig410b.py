# -*- coding: utf-8 -*-
"""Build Fig4.10 Vulnerability Scanning Activity Diagram .drawio with swimlanes (UML activity)."""
OUT = r"c:\FYP\VulnScan\docs\design\Fig4.10_Scan_Activity_Diagram.drawio"

V, E = [], []
def vx(_id, x, y, w, h, label, style):
    V.append((_id, x, y, w, h, label, style))
def edge(_id, src, tgt, pts, label="", arrow=True):
    E.append((_id, src, tgt, pts, label, arrow))

ACT = "rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"
DIA = "rhombus;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"

# ---- swimlane partitions (horizontal bands) ----
vx("bandDev", 60, 20, 700, 200, "Developer", "rounded=0;fillColor=none;strokeColor=#000000;align=center;fontStyle=1;fontSize=12;")
vx("bandSys", 60, 240, 700, 900, "VulnScan System", "rounded=0;fillColor=none;strokeColor=#000000;align=center;fontStyle=1;fontSize=12;")

# ---- nodes (top-level absolute coords inside correct bands) ----
vx("start", 390, 30, 40, 40, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")          # Developer band
vx("a1", 270, 90, 280, 60, "Developer provides a target URL and selects a scan profile", ACT)       # Developer band

vx("a2", 270, 270, 280, 60, "System validates target URL and scan profile", ACT)                    # System band
vx("d1", 375, 370, 70, 70, "Valid?", DIA)
vx("err", 560, 330, 180, 60, "Display validation error", ACT)
vx("a3", 270, 540, 280, 60, "Web crawler discovers pages (stored as DiscoveredPage)", ACT)
vx("d2", 375, 640, 70, 70, "More pages?", DIA)
vx("a4", 260, 800, 300, 70, "Run enabled detection modules and record Findings (severity, risk, evidence)", ACT)
vx("a5", 560, 650, 180, 60, "Update scan status to Completed", ACT)
vx("a6", 560, 740, 180, 60, "Present scan results to Developer", ACT)
vx("endOuter", 630, 820, 40, 40, "", "ellipse;ringNode;fillColor=#FFFFFF;strokeColor=#000000;")
vx("endInner", 644, 834, 12, 12, "", "ellipse;fillNode;fillColor=#000000;strokeColor=#000000;")

edge("e1", "start", "a1", [(410, 70), (410, 90)])
edge("e2", "a1", "a2", [(410, 150), (410, 270)])
edge("e3", "a2", "d1", [(410, 330), (410, 370)])
edge("e4", "d1", "err", [(445, 405), (500, 405), (500, 360), (560, 360)], "No", arrow=False)
edge("e5", "err", "a1", [(650, 330), (650, 120), (550, 120)])
edge("e6", "d1", "a3", [(410, 440), (410, 540)], "Yes")
edge("e7", "a3", "d2", [(410, 600), (410, 640)])
edge("e8", "d2", "a4", [(410, 710), (410, 800)], "Yes")
edge("e9", "a4", "d2", [(260, 835), (140, 835), (140, 675), (375, 675)])
edge("e10", "d2", "a5", [(445, 675), (445, 700), (560, 700)], "No", arrow=False)
edge("e11", "a5", "a6", [(650, 710), (650, 740)])
edge("e12", "a6", "endOuter", [(650, 800), (650, 820)])

lines = []
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
lines.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
lines.append('  <diagram id="fig4-10-scan-activity" name="Fig4.10 Vulnerability Scanning Activity Diagram">')
lines.append('    <mxGraphModel dx="700" dy="1000" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="820" pageHeight="1180" math="0" shadow="0">')
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
