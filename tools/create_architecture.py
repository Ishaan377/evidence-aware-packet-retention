"""Draw the project architecture as a reproducible PNG and editable SVG."""
from pathlib import Path
from html import escape
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/assets"
OUT.mkdir(parents=True, exist_ok=True)
W,H = 2200,1560
im = Image.new("RGB",(W,H),"white")
draw = ImageDraw.Draw(im)
FONT = Path("C:/Windows/Fonts/arial.ttf")
BOLD = Path("C:/Windows/Fonts/arialbd.ttf")
svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
       '<rect width="2200" height="1560" fill="white"/>',
       '<defs><marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth"><path d="M0 0 L12 6 L0 12 Z" fill="#374151"/></marker></defs>']

def box(x0,y0,x1,y1,lines,fill="#eef2f6",size=43):
    draw.rounded_rectangle((x0,y0,x1,y1),radius=14,fill=fill,outline="#374151",width=4)
    svg.append(f'<rect x="{x0}" y="{y0}" width="{x1-x0}" height="{y1-y0}" rx="14" fill="{fill}" stroke="#374151" stroke-width="4"/>')
    font=ImageFont.truetype(str(FONT),size)
    lineheight=size+13
    first=(y0+y1)/2-(len(lines)-1)*lineheight/2
    for i,line in enumerate(lines):
        cy=first+i*lineheight
        draw.text(((x0+x1)/2,cy),line,font=font,fill="#111827",anchor="mm")
        svg.append(f'<text x="{(x0+x1)/2}" y="{cy}" dominant-baseline="middle" text-anchor="middle" font-family="Arial,sans-serif" font-size="{size}" fill="#111827">{escape(line)}</text>')

def line(points,arrow=False,dashed=False):
    color="#374151"
    width=5
    if dashed:
        for a,b in zip(points,points[1:]):
            dx,dy=b[0]-a[0],b[1]-a[1]
            length=(dx*dx+dy*dy)**.5
            for offset in range(0,int(length),24):
                t1,t2=offset/length,min(offset+13,length)/length
                draw.line([(a[0]+dx*t1,a[1]+dy*t1),(a[0]+dx*t2,a[1]+dy*t2)],fill=color,width=width)
    else:
        draw.line(points,fill=color,width=width)
    if arrow:
        a,b=points[-2],points[-1]
        dx,dy=b[0]-a[0],b[1]-a[1]
        mag=(dx*dx+dy*dy)**.5
        ux,uy=dx/mag,dy/mag
        draw.polygon([b,(b[0]-22*ux+11*uy,b[1]-22*uy-11*ux),
                      (b[0]-22*ux-11*uy,b[1]-22*uy+11*ux)],fill=color)
    d="M "+" L ".join(f"{a},{b}" for a,b in points)
    svg.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"'
               +(' stroke-dasharray="13 11"' if dashed else '')
               +(' marker-end="url(#arrow)"' if arrow else '')+'/>')

box(560,45,1560,155,["Input classic PCAP","Original captured packet records"])
line([(1060,155),(1060,210)],True)
box(560,210,1560,320,["Validate and parse packets","Preserve bytes and timestamps"])
line([(1060,320),(1060,375)],True)
box(560,375,1560,485,["Extract observable features","Flows and supported protocol sequences"])
line([(1060,485),(1060,550)])
line([(280,550),(1750,550)])
centers=[280,770,1260,1750]
for x in centers:
    line([(x,550),(x,605)],True)
labels=[["Random","packet packing"],["Alerted flows","chronological packing"],
        ["Evidence bundles","gain per added byte"],["Flow prefixes","whole packet cutoff"]]
for x,labels_here in zip(centers,labels):
    box(x-205,605,x+205,735,labels_here,fill="#e5edf4",size=38)
    line([(x,735),(x,795)])
line([(280,795),(1750,795)])
line([(1060,795),(1060,845)],True)
box(560,845,1560,955,["Apply the same PCAP byte cap","Keep whole original records only"])
line([(1060,955),(1060,1010)],True)
box(560,1010,1560,1120,["Write retained PCAP","Copy selected records in capture order"])
line([(1060,1120),(1060,1175)],True)
box(560,1175,1560,1285,["Reparse and evaluate eight criteria","Answers use retained packets only"],size=42)
line([(1060,1285),(1060,1340)],True)
box(560,1340,1560,1450,["Metrics plots and report","CSV and JSON results with hashes"])
box(1710,45,2170,195,["Separate ground truth","Reference answers","Evaluator only"],fill="#f5f5f5",size=36)
line([(1940,195),(2090,195),(2090,1230),(1570,1230)],True,True)
font=ImageFont.truetype(str(FONT),36)
draw.text((1060,1505),"No truth labels or oracle packet IDs enter selection",font=font,fill="#374151",anchor="mm")
svg.append('<text x="1060" y="1505" dominant-baseline="middle" text-anchor="middle" font-family="Arial,sans-serif" font-size="36" fill="#374151">No truth labels or oracle packet IDs enter selection</text>')
svg.append("</svg>")
im.save(OUT/"architecture_flowchart.png",dpi=(300,300))
(OUT/"architecture_flowchart.svg").write_text("\n".join(svg),encoding="utf-8")
print("Saved PNG and SVG architecture in",OUT)
