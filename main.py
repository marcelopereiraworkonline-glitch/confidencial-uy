import hashlib, io
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, Response
from PIL import Image
from pypdf import PdfReader
from forensics import analyze as forensic_analyze
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from xml.sax.saxutils import escape
from datetime import datetime, timezone
import json
app = FastAPI(title="Confidencial UY", docs_url=None, redoc_url=None)
MAX=10*1024*1024
@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confidencial UY</title><style>body{background:#0b111b;color:#e7eef5;font:16px system-ui;margin:0}main{max-width:740px;margin:12vh auto;padding:24px}h1{font-size:48px;letter-spacing:-2px}em{color:#5ee4c0;font-style:normal}.drop{border:1px dashed #607080;border-radius:16px;padding:35px;margin-top:35px}button{background:#5ee4c0;border:0;border-radius:9px;padding:13px 22px;font-weight:700;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#172234;padding:20px;border-radius:12px}small{color:#a6b2c3}</style><main><small>LABORATORIO FORENSE DIGITAL</small><h1>Confidencial <em>UY</em></h1><p>Cada archivo cuenta una historia. Explorá sus metadatos con una lectura clara y verificable.</p><div class="drop"><form id="f"><input name="file" type="file" required><p><button>Analizar archivo</button></p></form><small>Prueba técnica · Máximo 10 MB · No subas información sensible</small></div><pre id="out">Esperando archivo…</pre><small>Desarrollada por Marcelo Pereira</small></main><script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const o=document.getElementById('out');o.textContent='Analizando…';try{let r=await fetch('/api/analyze',{method:'POST',body:new FormData(e.target)});const d=await r.json();o.textContent=JSON.stringify(d,null,2);if(r.ok){const b=document.createElement('button');b.textContent='Exportar JSON';b.onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(d,null,2)],{type:'application/json'}));a.download='confidencial-uy-informe.json';a.click();URL.revokeObjectURL(a.href)};o.after(b);const p=document.createElement('button');p.textContent='Descargar informe PDF';p.style.marginLeft='8px';p.onclick=async()=>{p.disabled=true;try{const rr=await fetch('/api/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});if(!rr.ok)throw Error('No se pudo generar el PDF');const a=document.createElement('a');const u=URL.createObjectURL(await rr.blob());a.href=u;a.download='Confidencial_UY_Informe.pdf';a.click();setTimeout(()=>URL.revokeObjectURL(u),30000)}catch(e){alert(e.message)}finally{p.disabled=false}};b.after(p)}}catch(err){o.textContent='Error: '+err.message}}</script></html>"""
@app.post("/api/analyze")
async def analyze(file: UploadFile=File(...)):
    data=await file.read(MAX+1)
    if len(data)>MAX: raise HTTPException(413,"Máximo 10 MB")
    if not data: raise HTTPException(400,"Archivo vacío")
    name=Path((file.filename or "archivo").replace("\\","/")).name[:120]
    return forensic_analyze(data,name)

@app.post("/api/report")
async def report(result: dict):
    if len(json.dumps(result,ensure_ascii=False))>250000:
        raise HTTPException(413,"Informe demasiado extenso")
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=50,bottomMargin=45)
    styles=getSampleStyleSheet()
    story=[Paragraph("CONFIDENCIAL UY",styles["Title"]),Paragraph("INFORME DE METADATOS Y ANALISIS DIGITAL",styles["Heading2"]),Paragraph("Emitido UTC: "+datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),styles["Normal"]),Spacer(1,18)]
    sections=[("archivo","01. IDENTIFICACION DEL ARCHIVO"),("hashes","02. HASHES E INTEGRIDAD"),("identidad","03. IDENTIDAD Y PROPIEDAD"),("fechas","04. FECHAS"),("dispositivo","05. EXIF Y DATOS TECNICOS"),("geolocalizacion","06. GEOLOCALIZACION"),("estructura","07. ESTRUCTURA"),("contenido","08. CONTENIDO"),("hallazgos","09. HALLAZGOS"),("limitaciones","10. LIMITACIONES")]
    for key,title in sections:
        story.append(Paragraph(title,styles["Heading3"]))
        block=result.get(key)
        if isinstance(block,dict):
            pairs=list(block.items())[:150]
        elif isinstance(block,list):
            pairs=[(str(i+1),v) for i,v in enumerate(block[:150])]
        else:
            pairs=[("Resultado",block)] if block else []
        if not pairs: story.append(Paragraph("Sin datos registrados.",styles["Normal"]))
        for k,v in pairs:
            value=json.dumps(v,ensure_ascii=False,default=str) if isinstance(v,(dict,list)) else str(v)
            value=escape(value[:1800])
            story.append(Paragraph("<b>"+escape(str(k)[:100])+":</b> "+value,styles["Normal"]))
            story.append(Spacer(1,5))
        story.append(Spacer(1,12))
    story.append(Paragraph("Advertencia: los metadatos pueden ser modificados. Este reporte automatizado no certifica autenticidad ni autoria.",styles["Normal"]))
    def footer(canvas,document):
        canvas.setFont("Helvetica",8)
        canvas.drawString(42,25,"Confidencial UY - Desarrollada por Marcelo Pereira")
        canvas.drawRightString(A4[0]-42,25,"Pagina "+str(document.page))
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return Response(content=buf.getvalue(),media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=Confidencial_UY_Informe.pdf","Cache-Control":"no-store"})
