"""Patch authorized content/image parts while preserving the reference package."""
import copy
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile
from io import BytesIO
from docx import Document
from docx.shared import Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from lxml import etree

ROOT = Path(__file__).resolve().parents[1]
reference = ROOT / "Network_Traffic_Forensics_Synopsis_FINAL.docx"
expected = "2a9000836d4bbac7e5db0347597bd17e8a10f8b6acd5157fda2e638452659800"
assert hashlib.sha256(reference.read_bytes()).hexdigest() == expected
content = json.loads((ROOT / "docs/synopsis_content.json").read_text(encoding="utf-8"))
sources = json.loads((ROOT / "docs/sources.json").read_text(encoding="utf-8"))
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}
tag = lambda name: "{" + W + "}" + name

def replace_text(element, text):
    first = element.find("w:r", NS)
    props = copy.deepcopy(first.find("w:rPr", NS)) if first is not None and first.find("w:rPr",NS) is not None else None
    for child in list(element):
        if child.tag != tag("pPr"):
            element.remove(child)
    run = etree.SubElement(element, tag("r"))
    if props is not None:
        run.append(props)
    for i,line in enumerate(text.split("\n")):
        if i:
            etree.SubElement(run, tag("br"))
        if line:
            t = etree.SubElement(run, tag("t"))
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            t.text = line

with ZipFile(reference) as z:
    infos = z.infolist()
    original = {info.filename: z.read(info.filename) for info in infos}
root = etree.fromstring(original["word/document.xml"])
body = root.find("w:body", NS)
paragraphs = body.findall("w:p", NS)
tables = body.findall("w:tbl", NS)
replace_text(paragraphs[7], content["title"])
for index, text in content["paragraphs"].items():
    replace_text(paragraphs[int(index)], text)
for row,text in zip(tables[1].findall("w:tr",NS)[1:],content["team"]):
    replace_text(row.findall("w:tc",NS)[3].find("w:p",NS),text)
for table_index,key in ((2,"tools"),(3,"timeline")):
    rows = tables[table_index].findall("w:tr",NS)[1:]
    assert len(rows) == len(content[key])
    for row,values in zip(rows,content[key]):
        for cell,text in zip(row.findall("w:tc",NS),values):
            replace_text(cell.find("w:p",NS),text)
reference_elements = paragraphs[45:49]
anchor = paragraphs[49]
for element in reference_elements:
    body.remove(element)
for source in sources:
    p = copy.deepcopy(reference_elements[0])
    label = f'[{source["id"]}] {source["authors"]}. {source["title"]}. '
    label += str(source["year"]) if source["year"] else "Undated documentation"
    if source.get("version"):
        label += "; " + source["version"]
    if source.get("doi"):
        label += ". DOI: " + source["doi"]
    label += ". " + source["url"]
    if source["id"] in (2,4,14):
        label += " (Reviewed preprint)"
    elif source["id"] == 5:
        label += " (Official abstract reviewed)"
    elif source["id"] == 13:
        label += " (Internet-Draft; work in progress)"
    replace_text(p,label)
    body.insert(body.index(anchor),p)
headings = {"".join(p.xpath(".//w:t/text()",namespaces=NS)) for p in paragraphs
            if p.find("w:r/w:rPr/w:sz",NS) is not None
            and p.find("w:r/w:rPr/w:sz",NS).get(tag("val"))=="28"}
for p in body.findall("w:p",NS):
    text = "".join(p.xpath(".//w:t/text()",namespaces=NS))
    if text in headings:
        props = p.find("w:pPr",NS)
        if props is None:
            props = etree.Element(tag("pPr"))
            p.insert(0,props)
        if props.find("w:keepNext",NS) is None:
            etree.SubElement(props,tag("keepNext"))
for table in tables[1:]:
    for i,row in enumerate(table.findall("w:tr",NS)):
        props = row.find("w:trPr",NS)
        if props is None:
            props = etree.Element(tag("trPr"))
            row.insert(0,props)
        if props.find("w:cantSplit",NS) is None:
            etree.SubElement(props,tag("cantSplit"))
        if i==0 and props.find("w:tblHeader",NS) is None:
            etree.SubElement(props,tag("tblHeader"))
# The requested architecture adds one image relationship and a PNG content type.
donor=Document()
picture=donor.add_picture(str(ROOT/"docs/assets/architecture_flowchart.png"),width=Inches(6.6))
picture._inline.docPr.set("descr","PCAP input through four retention policies to retained-file evaluation; truth enters evaluation only.")
picture._inline.xpath(".//a:blip")[0].set("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed","rIdArchitectureFlowchart")
image_p=copy.deepcopy(donor.paragraphs[-1]._p)
props=image_p.find("w:pPr",NS)
if props is None:
    props=etree.Element(tag("pPr"))
    image_p.insert(0,props)
jc=etree.SubElement(props,tag("jc"))
jc.set(tag("val"),"center")
etree.SubElement(props,tag("keepNext"))
body.insert(body.index(paragraphs[28]),image_p)
note=copy.deepcopy(paragraphs[28])
replace_text(note,content["timeline_note"])
body.insert(body.index(tables[3])+1,note)
rels=etree.fromstring(original["word/_rels/document.xml.rels"])
rns="http://schemas.openxmlformats.org/package/2006/relationships"
relationship=etree.SubElement(rels,"{"+rns+"}Relationship")
relationship.set("Id","rIdArchitectureFlowchart")
relationship.set("Type","http://schemas.openxmlformats.org/officeDocument/2006/relationships/image")
relationship.set("Target","media/architecture_flowchart.png")
types=etree.fromstring(original["[Content_Types].xml"])
cns="http://schemas.openxmlformats.org/package/2006/content-types"
if not any(e.get("Extension")=="png" for e in types):
    default=etree.SubElement(types,"{"+cns+"}Default")
    default.set("Extension","png")
    default.set("ContentType","image/png")
modified={
    "word/_rels/document.xml.rels":etree.tostring(rels,encoding="UTF-8",xml_declaration=True,standalone=True),
    "[Content_Types].xml":etree.tostring(types,encoding="UTF-8",xml_declaration=True,standalone=True),
}
editable_parts={"word/document.xml",*modified}

updated = etree.tostring(root, encoding="UTF-8", xml_declaration=True, standalone=True)
output = ROOT / "docs/synopsis.docx"
with ZipFile(output,"w") as z:
    for info in infos:
        z.writestr(info, updated if info.filename=="word/document.xml" else modified.get(info.filename,original[info.filename]))
    z.writestr("word/media/architecture_flowchart.png",(ROOT/"docs/assets/architecture_flowchart.png").read_bytes())
with ZipFile(output) as z:
    for name,data in original.items():
        if name not in editable_parts:
            assert z.read(name)==data, "Preserve-only part changed: "+name
assert hashlib.sha256(reference.read_bytes()).hexdigest()==expected
evidence = {
    "reference_sha256": expected, "final_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    "section_geometry_unchanged": etree.tostring(etree.fromstring(original["word/document.xml"]).find("w:body/w:sectPr",NS))
                                  == etree.tostring(root.find("w:body/w:sectPr",NS)),
    "preserve_only_parts_verified": len(original)-len(editable_parts),
    "added_parts": ["word/media/architecture_flowchart.png"],
    "editable_parts": sorted(editable_parts),
    "baseline_parts": {name:{"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()} for name,data in original.items()},
    "intentional_changes": ["Project content and planned roles","Reference-matched planned-completion labels explicitly distinguished from completed work","18 verified references",
                           "Keep section headings with next content","Repeating headers and intact table rows","Requested visual architecture and its image relationship/content type"],
}
(ROOT / "docs/qa/template_evidence.json").write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
print("Created",output)
print("Preserved",len(original)-len(editable_parts),"non-editable package parts; source reference unchanged.")
