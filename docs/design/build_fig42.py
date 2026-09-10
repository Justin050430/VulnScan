# -*- coding: utf-8 -*-
"""
Build Fig4.2 Deployment Diagram (Azure + GitHub Actions) .drawio
Monochrome UML-deployment style, same box/cube convention as the original file:
  - node "boxes" are draw.io 'cube' containers (they render as white boxes)
  - '«artifact»' sub-boxes are nested inside the Azure App Service / Azure SQL Database boxes
Run from the repo venv:  python docs/design/build_fig42.py
"""
import os

OUT = r"c:\FYP\VulnScan\docs\design\Fig4.2_Deployment_Diagram.drawio"

# ----- drawing geometry (page 1200 x 880) -----
# canvas extents used below
W_PAGE, H_PAGE = 1200, 880

# node styles (same conventions as the original file)
CUBE  = "shape=cube;size=10;direction=south;html=1;whiteSpace=wrap;fontStyle=4;"   # bold node box
CUBE_T = ("verticalAlign=top;align=center;spacingTop=8;spacingLeft=2;spacingRight=12;"
          "shape=cube;size=10;direction=south;fontStyle=4;html=1;whiteSpace=wrap;")  # container box, title at top
ART   = "html=1;whiteSpace=wrap;"                                                   # artifact sub-box

EDGE  = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;endArrow=block;endFill=1;"

V = []   # (id, x, y, w, h, label, style, parent)
E = []   # (id, src, tgt, pts, label)

def vx(_id, x, y, w, h, label, style, parent="1"):
    V.append((_id, x, y, w, h, label, style, parent))

def edge(_id, src, tgt, pts, label):
    E.append((_id, src, tgt, pts, label))

# ============================ nodes ============================
# --- left column: Client (top) and GitHub (below) ---
vx("client",   60,  70, 190, 150, "«device»<br>Client<br>(Web Browser)", CUBE)
vx("github",   60, 260, 190, 150, "«external»<br>GitHub<br>(GitHub Actions CI/CD)", CUBE)

# --- centre: Azure App Service (container) ---
vx("appSvc", 360,  90, 560, 380,
   "<b>«server»<br>Azure App Service</b>", CUBE_T)
# children of appSvc (relative geometry)
vx("appArt", 30,  95, 500, 120,
   "«artifact» VulnScan Web Application (Flask)<br>"
   "Frontend (UI) + Backend (REST API · Business Logic Layers)", ART, "appSvc")
vx("scanArt", 30, 240, 500, 120,
   "«artifact» Scanner Engine<br>"
   "Web Crawler · SQL Injection · XSS · HTTP Security Header Modules", ART, "appSvc")

# --- centre-left bottom: Azure SQL Database (container) ---
vx("sqlSvc", 60, 520, 500, 320,
   "<b>«server»<br>Azure SQL Database</b>", CUBE_T)
vx("sqlArt", 30,  75, 440, 215,
   "«artifact» Microsoft SQL Server (managed)<br>"
   "User · Scan · ScanProfile · ProfileModule<br>"
   "Vulnerability · DiscoveredPage · Finding · SecurityAuditLog", ART, "sqlSvc")

# --- right column: Google OAuth (top) and Target (bottom-right) ---
vx("oauth",  980,  70, 190, 150, "«external»<br>Google OAuth 2.0<br>(Identity Provider)", CUBE)
vx("target", 640, 610, 500, 160, "«external»<br>Target Web Application<br>(subject of vulnerability assessment)", CUBE)

# ============================ edges ============================
edge("eClient", "client", "appSvc", [(250, 145), (360, 145)], "HTTPS")
edge("eGitHub", "github", "appSvc", [(155, 410), (155, 455), (360, 455)],
     "HTTPS (git push · auto-deploy)")
edge("eDb",     "appSvc", "sqlSvc", [(520, 470), (520, 520)], "TCP (SQL Server)")
edge("eTarget", "appSvc", "target", [(880, 470), (880, 610)], "HTTP / HTTPS (scan requests)")
edge("eOauth",  "oauth",  "appSvc", [(1095, 220), (1095, 250), (920, 250)], "HTTPS (OAuth 2.0)")

# ============================ emit ============================
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

L = []
L.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
L.append('  <diagram id="fig4-2-deployment" name="Fig4.2 Deployment Diagram">')
L.append(f'    <mxGraphModel dx="1527" dy="757" grid="1" gridSize="10" guides="1" tooltips="1" '
         f'connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="{W_PAGE}" '
         f'pageHeight="{H_PAGE}" math="0" shadow="0">')
L.append('      <root>')
L.append('        <mxCell id="0" />')
L.append('        <mxCell id="1" parent="0" />')
for (_id, x, y, w, h, label, style, parent) in V:
    L.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{style}" vertex="1" parent="{parent}">')
    L.append(f'          <mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry" />')
    L.append('        </mxCell>')
for (_id, src, tgt, pts, label) in E:
    L.append(f'        <mxCell id="{_id}" value="{esc(label)}" style="{EDGE}" edge="1" '
             f'parent="1" source="{src}" target="{tgt}">')
    L.append('          <mxGeometry relative="1" as="geometry">')
    L.append('            <Array as="points">')
    for (px, py) in pts:
        L.append(f'              <mxPoint x="{px}" y="{py}" />')
    L.append('            </Array>')
    L.append('          </mxGeometry>')
    L.append('        </mxCell>')
L.append('      </root>')
L.append('    </mxGraphModel>')
L.append('  </diagram>')
L.append('</mxfile>')

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(L))
print("wrote", OUT, "|", len(V), "vertices |", len(E), "edges")
