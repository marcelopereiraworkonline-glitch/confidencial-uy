import io, os, re, json, hashlib, zipfile, mimetypes
from pathlib import Path
from xml.etree import ElementTree as ET
from PIL import Image, ExifTags
from pypdf import PdfReader

def safe(v, limit=400):
    if isinstance(v, bytes): return {"tipo":"binario","bytes":len(v),"muestra_hex":v[:32].hex()}
    if isinstance(v, (list,tuple)): return [safe(x) for x in v[:100]]
    if isinstance(v,dict): return {str(k):safe(x) for k,x in list(v.items())[:300]}
    return str(v)[:limit] if not isinstance(v,(int,float,bool,type(None))) else v

def analyze(data, name):
    result={"archivo":{"nombre":Path(name).name[:120],"tamano_bytes":len(data),"extension":Path(name).suffix.lower(),"mime_declarado":mimetypes.guess_type(name)[0]},"hashes":{"sha256":hashlib.sha256(data).hexdigest(),"md5":hashlib.md5(data).hexdigest()},"identidad":{},"fechas":{},"dispositivo":{},"geolocalizacion":{},"estructura":{},"contenido":{},"hallazgos":[],"limitaciones":[]}
    h=result["hallazgos"]; lim=result["limitaciones"]
    if data.startswith(b"%PDF"):
        result["archivo"]["tipo_detectado"]="PDF"
        try:
            pdf=PdfReader(io.BytesIO(data),strict=False)
            result["estructura"]["paginas"]=len(pdf.pages)
            result["estructura"]["cifrado"]=pdf.is_encrypted
            if not pdf.is_encrypted:
                meta={str(k):safe(v) for k,v in (pdf.metadata or {}).items()}
                result["identidad"]["propiedades_pdf"]=meta
                for k,v in meta.items():
                    if any(x in k.lower() for x in ("date","fecha")): result["fechas"][k]=v
                links=[]; annotations=[]
                for i,page in enumerate(pdf.pages[:100]):
                    try:
                        for a in page.get("/Annots",[])[:100]:
                            obj=a.get_object()
                            annotations.append({"pagina":i+1,"tipo":str(obj.get("/Subtype","")),"contenido":safe(obj.get("/Contents",""))})
                            action=obj.get("/A")
                            if action and action.get("/URI"): links.append(safe(action.get("/URI")))
                    except Exception: continue
                result["contenido"]["anotaciones"]=annotations[:200]
                result["contenido"]["enlaces"]=links[:200]
                if annotations: h.append("El PDF contiene anotaciones incrustadas.")
            else: lim.append("PDF cifrado: no se inspeccionó su contenido.")
        except Exception as e: lim.append("No se pudo interpretar el PDF: "+type(e).__name__)
    elif data.startswith((b"\xff\xd8\xff",b"\x89PNG\r\n\x1a\n",b"GIF8",b"RIFF",b"II*\x00",b"MM\x00*")):
        try:
            with Image.open(io.BytesIO(data)) as im:
                result["archivo"].update(tipo_detectado=im.format,dimensiones=[im.width,im.height],modo_color=im.mode)
                result["estructura"]["fotogramas"]=getattr(im,"n_frames",1)
                result["estructura"]["informacion_contenedor"]={str(k):safe(v) for k,v in im.info.items()}
                exif=im.getexif()
                tags={ExifTags.TAGS.get(k,str(k)):safe(v) for k,v in exif.items()}
                result["dispositivo"]["exif"]=tags
                for k in ("Make","Model","LensModel","ISOSpeedRatings","FNumber","ExposureTime","FocalLength","Software"):
                    if k in tags: result["dispositivo"][k]=tags[k]
                for k in ("DateTime","DateTimeOriginal","DateTimeDigitized"):
                    if k in tags: result["fechas"][k]=tags[k]
                for k in ("Artist","Copyright","Software","ImageDescription"):
                    if k in tags: result["identidad"][k]=tags[k]
                try:
                    gps=exif.get_ifd(0x8825)
                    result["geolocalizacion"]["gps_exif"]={ExifTags.GPSTAGS.get(k,str(k)):safe(v) for k,v in gps.items()}
                    if gps: h.append("La imagen contiene información GPS; revisá su exposición antes de compartir.")
                except Exception: pass
                if any(k in im.info for k in ("xmp","XML:com.adobe.xmp","icc_profile","exif")): h.append("La imagen contiene bloques adicionales de metadatos.")
        except Exception as e: lim.append("No se pudo interpretar la imagen: "+type(e).__name__)
    elif zipfile.is_zipfile(io.BytesIO(data)):
        result["archivo"]["tipo_detectado"]="Contenedor ZIP/Office"
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names=z.namelist()
                result["estructura"]["entradas"]=[{"ruta":n[:200],"tamano":z.getinfo(n).file_size} for n in names[:250]]
                result["estructura"]["cantidad_entradas"]=len(names)
                result["contenido"]["objetos_incrustados"]=[n for n in names if "/embeddings/" in n.lower()][:100]
                result["contenido"]["comentarios_archivos"]=[n for n in names if "comment" in n.lower()][:100]
                result["contenido"]["revisiones_archivos"]=[n for n in names if "revision" in n.lower()][:100]
                for part in ("docProps/core.xml","docProps/app.xml","docProps/custom.xml"):
                    if part in names and z.getinfo(part).file_size<1024*1024:
                        root=ET.fromstring(z.read(part))
                        vals={node.tag.split("}")[-1]:safe(node.text) for node in root.iter() if node.text and node.text.strip()}
                        result["identidad"][part]=vals
                        for k,v in vals.items():
                            if any(x in k.lower() for x in ("created","modified","printed")): result["fechas"][k]=v
                if result["contenido"]["objetos_incrustados"]: h.append("El documento contiene objetos incrustados.")
                if result["contenido"]["comentarios_archivos"]: h.append("Se detectaron partes relacionadas con comentarios.")
                if any(n.lower().endswith("vbaproject.bin") for n in names): h.append("El documento contiene un proyecto de macros VBA; no se ejecutó.")
        except Exception as e: lim.append("No se pudo inspeccionar el contenedor: "+type(e).__name__)
    else: lim.append("El formato no dispone aún de un analizador especializado.")
    lim.extend(["Las fechas del sistema de archivos original no se conservan necesariamente al subir un archivo.","Los metadatos pueden editarse; no prueban por sí solos autoría, ubicación ni autenticidad.","No se ejecutan macros, archivos adjuntos ni contenido activo."])
    return result
