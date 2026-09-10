# -*- coding: utf-8 -*-
"""Build Fig4.9 User Authentication Sequence Diagram .drawio (monochrome)."""
OUT = r"c:\FYP\VulnScan\docs\design\Fig4.9_Auth_Sequence_Diagram.drawio"

# participant centres and header boxes
parts = [("User", 120), ("Web UI (Presentation)", 310), ("API (Flask)", 520),
         ("Auth Service (Business Logic)", 740), ("Database (SQL Server)", 950),
         ("Google OAuth", 1150)]
HEAD_Y = 40
HEAD_H = 46
LIFE_TOP = 100
LIFE_BOT = 900

# messages: (src_cx, dst_cx, y, label, kind) kind: call | ret
M = []
def call(a, b, y, label):
    M.append((a, b, y, label, "call"))
def ret(a, b, y, label):
    M.append((a, b, y, label, "ret"))  # drawn from a (right) to b (left)

# ---- main local flow ----
call(120, 310, 150, "1: Email & password (Sign In)")
call(310, 520, 190, "2: POST /api/auth/login")
call(520, 740, 230, "3: Forward login request")
call(740, 950, 270, "4: Retrieve user by email")
ret(950, 740, 305, "5: User (password hash, role, is_active)")
ret(740, 520, 350, "6: Auth result + JWT (or failure)")
ret(520, 310, 390, "7: HTTP 200 + JWT (or 401)")
ret(310, 120, 430, "8: Dashboard by role (or error)")

# ---- optional Google SSO fragment ----
OPT_Y0 = 480
OPT_Y1 = 820
call(120, 310, OPT_Y0 + 20, "Sign in with Google")
call(310, 1150, OPT_Y0 + 60, "OAuth 2.0 authorisation request")
ret(1150, 310, OPT_Y0 + 95, "Authorisation code")
call(310, 520, OPT_Y0 + 135, "POST /api/auth/google (code)")
call(520, 1150, OPT_Y0 + 175, "Exchange code / fetch profile")
ret(1150, 520, OPT_Y0 + 210, "Verified email")
call(520, 740, OPT_Y0 + 250, "Match email against user")
call(740, 950, OPT_Y0 + 290, "Retrieve user by verified email")
ret(950, 740, OPT_Y0 + 325, "User record")

lines = []
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

lines.append('<mxfile host="app.diagrams.net" agent="5.0" version="24.0.0">')
lines.append('  <diagram id="fig4-9-auth-seq" name="Fig4.9 User Authentication Sequence Diagram">')
lines.append('    <mxGraphModel dx="1200" dy="850" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1400" pageHeight="960" math="0" shadow="0">')
lines.append('      <root>')
lines.append('        <mxCell id="0" />')
lines.append('        <mxCell id="1" parent="0" />')

# opt frame
lines.append('        <mxCell id="optFrame" value="opt [Google Sign-In]" style="rounded=0;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#000000;verticalAlign=top;align=left;fontStyle=1;fontSize=11;" vertex="1" parent="1">')
lines.append(f'          <mxGeometry x="60" y="{OPT_Y0}" width="1240" height="{OPT_Y1-OPT_Y0}" as="geometry" />')
lines.append('        </mxCell>')

# headers + lifelines
for i, (name, cx) in enumerate(parts):
    hx = cx - 90
    lines.append(f'        <mxCell id="h{i}" value="{esc(name)}" style="rounded=0;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;fontColor=#000000;fontStyle=1;" vertex="1" parent="1">')
    lines.append(f'          <mxGeometry x="{hx}" y="{HEAD_Y}" width="180" height="{HEAD_H}" as="geometry" />')
    lines.append('        </mxCell>')
    lines.append(f'        <mxCell id="l{i}" value="" style="lifeline;" vertex="1" parent="1">')
    lines.append(f'          <mxGeometry x="{cx}" y="{LIFE_TOP}" width="1" height="{LIFE_BOT-LIFE_TOP}" as="geometry" />')
    lines.append('        </mxCell>')

# messages
for idx, (a, b, y, label, kind) in enumerate(M):
    if kind == "call":
        # solid filled arrow, from a -> b (b > a normally)
        style = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;endArrow=classic;"
        pts = [(a, y), (b, y)]
    else:
        style = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#000000;dashed=1;endArrow=open;"
        pts = [(b, y), (a, y)]  # draw from right to left (arrow at left end)
    src_i = min(range(len(parts)), key=lambda k: abs(parts[k][1] - a))
    tgt_i = min(range(len(parts)), key=lambda k: abs(parts[k][1] - b))
    lines.append(f'        <mxCell id="m{idx}" value="{esc(label)}" style="{style}" edge="1" parent="1" source="l{src_i}" target="l{tgt_i}">')
    lines.append('          <mxGeometry relative="1" as="geometry">')
    lines.append('            <Array as="points">')
    for (px, py) in pts:
        lines.append(f'              <mxPoint x="{px}" y="{py}" />')
    lines.append('            </Array>')
    lines.append('          </mxGeometry>')
    lines.append('        </mxCell>')

# closing note
lines.append('        <mxCell id="note" value="JWT generation and response follow the same steps (6-8) after account matching." style="text;html=1;align=left;verticalAlign=top;fontSize=11;" vertex="1" parent="1">')
lines.append(f'          <mxGeometry x="620" y="{OPT_Y1+15}" width="700" height="40" as="geometry" />')
lines.append('        </mxCell>')

lines.append('      </root>')
lines.append('    </mxGraphModel>')
lines.append('  </diagram>')
lines.append('</mxfile>')

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print("wrote", OUT, "messages", len(M))
