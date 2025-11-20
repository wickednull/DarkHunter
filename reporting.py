
import json, os, time, html, zipfile
from colorama import Fore, Style

def print_findings(findings):
    if not findings:
        print("%s✅ No findings.%s" % (Fore.GREEN, Style.RESET_ALL)); return
    print("\n%s--- Scan Report ---%s" % (Fore.CYAN, Style.RESET_ALL))
    for f in findings:
        sev=getattr(f,"severity","Info"); ttl=getattr(f,"title","Untitled"); desc=getattr(f,"description","")
        print("[%s] %s -> %s" % (sev, ttl, desc))
        if getattr(f,"evidence",None): print("  Evidence:", json.dumps(f.evidence))

def export_html(findings, out_dir="reports", title="DarkHunter Report"):
    os.makedirs(out_dir, exist_ok=True); ts=int(time.time())
    path=os.path.join(out_dir, "report_%d.html" % ts); rows=[]
    for f in findings:
        sev=html.escape(getattr(f,"severity","")); ttl=html.escape(getattr(f,"title","")); desc=html.escape(getattr(f,"description",""))
        ev=html.escape(json.dumps(getattr(f,"evidence",{}), indent=2))
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>" % (sev,ttl,desc,ev))
    css="body{font-family:system-ui; background:#0b0f14; color:#d9e1ee; padding:20px} table{width:100%; border-collapse:collapse} th,td{border:1px solid #233; padding:8px}"
    body="<!doctype html><html><head><meta charset='utf-8'><title>%s</title><style>%s</style></head><body><h1>%s</h1><table><thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Evidence</th></tr></thead><tbody>%s</tbody></table></body></html>" % (html.escape(title),css,html.escape(title),"".join(rows))
    open(path,"w",encoding="utf-8").write(body); return path

_DOCX_CT="<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'><Default Extension='rels' ContentType='application/vnd.openxmlformats-package.relationships+xml'/><Default Extension='xml' ContentType='application/xml'/><Override PartName='/word/document.xml' ContentType='application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'/></Types>"
_RELS="<?xml version='1.0' encoding='UTF-8' standalone='yes'?><Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'></Relationships>"
def _p(text): return "<w:p><w:r><w:t>%s</w:t></w:r></w:p>" % html.escape(text)

def export_docx(findings, out_dir="reports", title="DarkHunter Report"):
    os.makedirs(out_dir, exist_ok=True); ts=int(time.time())
    path=os.path.join(out_dir, "report_%d.docx" % ts); parts=[_p(title)]
    for f in findings:
        parts += [_p("[%s] %s" % (getattr(f,"severity",""), getattr(f,"title",""))), _p(getattr(f,"description","")), _p(json.dumps(getattr(f,"evidence",{}))), _p("")]
    doc="<?xml version='1.0' encoding='UTF-8' standalone='yes'?><w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body>%s</w:body></w:document>" % "".join(parts)
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _DOCX_CT); z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", doc); z.writestr("word/_rels/document.xml.rels", _RELS)
    return path

def _pdf_from_lines(lines, out_path):
    def esc(s): return s.replace("\\","\\\\").replace("(","\(").replace(")","\)")
    content_lines=["BT /F1 12 Tf 50 %d Td (%s) Tj ET" % (770-i*14, esc(l)) for i,l in enumerate(lines[:50])]
    content="\n".join(content_lines).encode("latin-1","ignore")
    objs=[]; xref=[]
    def add(b): xref.append(sum(len(x) for x in objs)); objs.append(b)
    add(b"%PDF-1.4\n"); add(b"1 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")
    add(b"2 0 obj<< /Type /Page /Parent 3 0 R /Resources<< /Font<< /F1 1 0 R>> >> /MediaBox[0 0 595 842] /Contents 4 0 R>>endobj\n")
    add(b"3 0 obj<< /Type /Pages /Kids[2 0 R] /Count 1>>endobj\n")
    add(("4 0 obj<< /Length %d >>stream\n" % len(content)).encode()); add(content); add(b"\nendstream endobj\n")
    add(b"5 0 obj<< /Type /Catalog /Pages 3 0 R>>endobj\n")
    xref_pos=sum(len(x) for x in objs); pdf=b"".join(objs)
    xreft=[b"xref\n0 6\n0000000000 65535 f \n"]+[("%010d 00000 n \n" % off).encode() for off in xref]
    trailer=b"trailer<< /Size 6 /Root 5 0 R >>\nstartxref\n"+str(xref_pos).encode()+b"\n%%EOF"
    open(out_path,"wb").write(pdf+b"".join(xreft)+trailer)

def export_pdf(findings, out_dir="reports", title="DarkHunter Report"):
    os.makedirs(out_dir, exist_ok=True); ts=int(time.time())
    path=os.path.join(out_dir, "report_%d.pdf" % ts)
    lines=[title]
    for f in findings:
        lines += ["[%s] %s" % (getattr(f,"severity",""), getattr(f,"title","")), getattr(f,"description",""), json.dumps(getattr(f,"evidence",{})), ""]
    _pdf_from_lines(lines, path); return path

def export_bug_pdf(finding, out_dir="reports", program_name="HackerOne/Bugcrowd", title="Bug Bounty Submission"):
    os.makedirs(out_dir, exist_ok=True); ts=int(time.time())
    path=os.path.join(out_dir, "submission_%d.pdf" % ts)
    sev=getattr(finding,"severity","Info")
    lines=[title, "Program: %s" % program_name, "Severity: %s" % sev,
           "Title: %s" % getattr(finding,"title","Untitled"), "Description: %s" % getattr(finding,"description",""),
           "Evidence: %s" % json.dumps(getattr(finding,"evidence",{})), "", "Steps to Reproduce:", "1) ...","2) ...","3) ...", "", "Impact:", "", "Scope:"]
    _pdf_from_lines(lines, path); return path
