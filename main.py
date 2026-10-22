import hashlib, io
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from PIL import Image
from pypdf import PdfReader
from forensics import analyze as forensic_analyze
app = FastAPI(title="Confidencial UY", docs_url=None, redoc_url=None)
MAX=10*1024*1024
@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confidencial UY</title><style>body{background:#0b111b;color:#e7eef5;font:16px system-ui;margin:0}main{max-width:740px;margin:12vh auto;padding:24px}h1{font-size:48px;letter-spacing:-2px}em{color:#5ee4c0;font-style:normal}.drop{border:1px dashed #607080;border-radius:16px;padding:35px;margin-top:35px}button{background:#5ee4c0;border:0;border-radius:9px;padding:13px 22px;font-weight:700;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#172234;padding:20px;border-radius:12px}small{color:#a6b2c3}</style><main><small>LABORATORIO FORENSE DIGITAL</small><h1>Confidencial <em>UY</em></h1><p>Cada archivo cuenta una historia. Explorá sus metadatos con una lectura clara y verificable.</p><div class="drop"><form id="f"><input name="file" type="file" required><p><button>Analizar archivo</button></p></form><small>Prueba técnica · Máximo 10 MB · No subas información sensible</small></div><pre id="out">Esperando archivo…</pre><small>Desarrollada por Marcelo Pereira</small></main><script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();const o=document.getElementById('out');o.textContent='Analizando…';try{let r=await fetch('/api/analyze',{method:'POST',body:new FormData(e.target)});const d=await r.json();o.textContent=JSON.stringify(d,null,2);if(r.ok){const b=document.createElement('button');b.textContent='Exportar JSON';b.onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(d,null,2)],{type:'application/json'}));a.download='confidencial-uy-informe.json';a.click();URL.revokeObjectURL(a.href)};o.after(b)}}catch(err){o.textContent='Error: '+err.message}}</script></html>"""
@app.post("/api/analyze")
async def analyze(file: UploadFile=File(...)):
    data=await file.read(MAX+1)
    if len(data)>MAX: raise HTTPException(413,"Máximo 10 MB")
    if not data: raise HTTPException(400,"Archivo vacío")
    name=Path((file.filename or "archivo").replace("\\","/")).name[:120]
    return forensic_analyze(data,name)
