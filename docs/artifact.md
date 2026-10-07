# Synopsis template execution contract

Reference: C:\Users\Ishaan SM\Desktop\IS project\Network_Traffic_Forensics_Synopsis_FINAL.docx
SHA-256: 2a9000836d4bbac7e5db0347597bd17e8a10f8b6acd5157fda2e638452659800
Reference rendering: docs/qa/reference/reference.pdf and page-1.png through page-8.png. Eight pages inspected.
Renderer: packaged render_docx.py attempted, but no bundled LibreOffice is available on Windows. Hidden Word read-only PDF export plus bundled Poppler is the verified alternate path.

## Page and typography
One section, portrait US Letter, 12240 x 15840 twips. Top/bottom 1152 twips; left/right 1296 twips. Header/footer distances 720 twips. One column. No source headers, footers, fields, images, text boxes, controls, bookmarks or footnotes.
Normal: Arial 11pt. Body runs inherit it. Section headings: direct bold 14pt. Cover title: bold 18pt centred after three line breaks; subtitle: bold 13pt centred. Year: bold 11pt centred. Default black. Preserve paragraph rhythm and cover breaks.
Lists use numbered text paragraphs. Four tables use source border/style and four equal 2412-twip columns except cover two equal 4824-twip columns. Table runs inherit Arial 11pt. No fixed row heights.

## Content flow and slots
word/document.xml body: 55 top-level paragraphs and four tables. Preserve order, cover metadata, single cover page break, declaration, signatures, remarks and approval checkboxes.
Paragraph 7 title. Paragraphs 10,13,16 background/problem/motivation. Paragraphs 19–23 objectives, with research questions and hypothesis appended through the source line-break pattern. Paragraphs 25,28,31,35,38,42 system/architecture/methodology/outcomes/metrics/review. Paragraphs 45–48 references; clone that pattern for 18 verified entries before paragraph 49.
Table 0 cover metadata preserved exactly. Table 1 names/roll numbers preserved; contribution column states planned roles. Tables 2/3 tools and timeline updated in place. All 16 source section headings preserved verbatim.

## Preservation and visual gates
The initial version patched only word/document.xml. The user's 7 October 2026 follow-up explicitly requests a visual architecture. The current contract therefore permits edits to word/document.xml, word/_rels/document.xml.rels and [Content_Types].xml, plus one new word/media/architecture_flowchart.png. Preserve all 14 other original parts byte-for-byte, including styles, numbering, theme, settings, customXml, document properties and thumbnail. Save package hash inventory in docs/qa/template_evidence.json; verify preserve-only members and original file unchanged.
No generic preset or font shrinking. Shorter table prose and extra verified references are intentional. Heading keepNext, repeating table headers and cantSplit rows are permitted pagination repairs within the source visual system.
The updated synopsis has 10 rendered pages; the former nine-page version is archived at docs/archive/synopsis_before_flowchart.docx. Final page count can change with content, but must remain close in density and source appearance. Inspect every rendered final PNG and check table continuation, heading placement, margins, signatures and clipping.

## Requested schedule update
Copy the reference's ten Planned Completion week/month strings exactly into the current timeline. They are proposed academic-schedule labels, not fabricated records of completed milestones. Keep the explicit schedule note: actual prototype checkpoint 7 October 2026; independent validation and final-project stages remain prospective.
