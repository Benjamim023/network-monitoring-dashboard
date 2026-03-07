from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import socket
import concurrent.futures
from analyzer import obtener_consejos_seguridad
from security_web import analizar_cabeceras_http

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# LISTA AGRESIVA: Puertos de administración, DBs y Proxies
PUERTOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP", 
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 
    5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "Plesk", 
    2082: "cPanel", 2083: "cPanel/SSL", 27017: "MongoDB", 6379: "Redis"
}

def escanear_un_puerto(host, puerto, servicio):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        if sock.connect_ex((host, puerto)) == 0:
            analisis = obtener_consejos_seguridad(puerto)
            return {
                "puerto": f"#{puerto}",
                "servicio": servicio,
                "vector": analisis["vector"],
                "nivel_riesgo": analisis["nivel_riesgo"],
                "tip": analisis["tip"]
            }
        sock.close()
    except: return None

@app.get("/", response_class=HTMLResponse)
async def leer_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def ejecutar_escaneo(request: Request, target: str):
    hallazgos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futuros = [executor.submit(escanear_un_puerto, target, p, s) for p, s in PUERTOS_COMUNES.items()]
        for f in concurrent.futures.as_completed(futuros):
            if f.result(): hallazgos.append(f.result())

    # Auditoría Ofensiva Web (Fuzzer + Regex + SQLi)
    analisis_web = analizar_cabeceras_http(target)
    hallazgos.extend(analisis_web)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "target": target,
        "puertos": hallazgos,
        "estado": "Online" if hallazgos else "Offline"
    })