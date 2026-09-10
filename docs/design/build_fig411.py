# -*- coding: utf-8 -*-
"""Build Fig4.11 SQL Injection Detection Flowchart .drawio (monochrome)."""
OUT = r"c:\FYP\VulnScan\docs\design\Fig4.11_SQLi_Flowchart.drawio"

V, E = [], []
def vx(_id, x, y, w, h, label, style):
    V.append((_id, x, y, w, h, label, style))
def edge(_id, src, tgt, pts, label=""):
    E.append((_id, src, tgt, pts, label))

TERM = "rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"
PROC = "rounded=0;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"
DIA  = "rhombus;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"

vx("start", 360, 20, 100, 40, "Start", TERM)
vx("a2", 260, 100, 300, 50, "Select an input parameter of the page", PROC)
vx("d1", 345, 190, 70, 70, "Unprocessed parameter?", DIA)
vx("a3", 260, 320, 300, 50, "Send baseline request and record normal response", PROC)
vx("a4", 260, 410, 300, 50, "Inject SQL injection payload into the parameter", PROC)
vx("a5", 260, 500, 300, 50, "Send request and capture the response", PROC)
vx("d2", 345, 600, 70, 70, "SQL error or anomalous response?", DIA)
vx("a6", 240, 730, 340, 50, "Record SQL Injection finding (severity, risk score, evidence)", PROC)
vx("end", 620, 860, 120, 40, "End", TERM)

AST = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;targetArrow=classic;"
edge("e1", "start", "a2", [(410, 60), (410, 100)])
edge("e2", "a2", "d1", [(410, 150), (410, 190)])
edge("e3", "d1", "a3", [(410, 260), (410, 320)], "Yes")
edge("e4", "a3", "a4", [(410, 370), (410, 410)])
edge("e5", "a4", "a5", [(410, 460), (410, 500)])
edge("e6", "a5", "d2", [(410, 550), (410, 600)])
edge("e7", "d2", "a6", [(410, 670), (410, 730)], "Yes")
edge("e8", "a6", "d1", [(240, 755), (140, 755), (140, 230), (345, 230)])
edge("e9", "d2", "d1", [(345, 635), (140, 635), (140, 230), (345, 230)], "No")
edge("e10", "d1", "end", [(445, 230), (720, 230), (720, 880), (620, 880)], "No")

lines = []
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
lines.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
lines.append('  <diagram id="fig4-11-sqli-flowchart" name="Fig4.11 SQL Injection Detection Flowchart">')
lines.append('    <mxGraphModel dx="700" dy="850" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="820" pageHeight="980" math="0" shadow="0">')
lines.append('      <root>')
lines.append('        <mxCell id="0" />')
lines.append('        <mxCell id="1" parent="0" />')
for (_id, x, y, w, h, label, style) in V:
    lines.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{style}" vertex="1" parent="1">')
    lines.append(f'          <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />')
    lines.append('        </mxCell>')
for (_id, src, tgt, pts, label) in E:
    lines.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{AST}" edge="1" parent="1" source="{src}" target="{tgt}">')
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
