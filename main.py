from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import socket
import concurrent.futures
from analyzer import obtener_consejos_seguridad
from security_web import analizar_cabeceras_http

app = FastAPI()
templates = Jinja2Templates(directory="templates")

PUERTOS_COMUNES = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}

def escanear_un_puerto(host, puerto, servicio):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        if sock.connect_ex((host, puerto)) == 0:
            analisis = obtener_consejos_seguridad(puerto)
            return {
                "puerto": f"#{puerto}",
                "servicio": servicio,
                "vector": analisis["vector"],
                "nivel_riesgo": analisis["nivel_riesgo"],
                "tip": analisis["tip"],
                "peligroso": analisis["nivel_riesgo"] in ["Alto", "Crítico"]
            }
        sock.close()
    except: return None

@app.get("/", response_class=HTMLResponse)
async def leer_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def ejecutar_escaneo(request: Request, target: str):
    hallazgos = []
    # Escaneo de Puertos
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PUERTOS_COMUNES)) as executor:
        futuros = [executor.submit(escanear_un_puerto, target, p, s) for p, s in PUERTOS_COMUNES.items()]
        for f in concurrent.futures.as_completed(futuros):
            if f.result(): hallazgos.append(f.result())

    # Auditoría Ofensiva Web
    try:
        analisis_web = analizar_cabeceras_http(target)
        hallazgos.extend(analisis_web)
    except: pass

    return templates.TemplateResponse("index.html", {
        "request": request,
        "target": target,
        "puertos": hallazgos,
        "estado": "Online" if hallazgos else "Offline",
        "alerta_seguridad": any(h.get('nivel_riesgo') in ["Alto", "Crítico"] for h in hallazgos)
    })