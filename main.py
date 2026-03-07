from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from analyzer import obtener_consejos_seguridad # Importamos tu motor de análisis
import socket
import concurrent.futures

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Lista de puertos para auditar
PUERTOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC"
}

def escanear_un_puerto(host, puerto, servicio):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        resultado = sock.connect_ex((host, puerto))
        
        datos = None
        if resultado == 0:
            banner = "No identificado"
            try:
                if puerto in {21, 22}:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif puerto == 80:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    res = sock.recv(1024).decode('utf-8', errors='ignore')
                    for line in res.split('\n'):
                        if "Server:" in line:
                            banner = line.replace("Server:", "").strip()
                            break
            except: pass

            # INTEGRACIÓN: Usamos el motor de analyzer.py
            analisis = obtener_consejos_seguridad(puerto, banner)

            datos = {
                "puerto": puerto,
                "servicio": servicio,
                "version": banner,
                "vector": analisis["vector"],
                "nivel_riesgo": analisis["nivel_riesgo"],
                "tip": analisis["consejo"],
                "peligroso": analisis["nivel_riesgo"] in ["Alto", "Crítico"]
            }
        sock.close()
        return datos
    except: return None

def escanear_puertos_paralelo(host):
    puertos_encontrados = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PUERTOS_COMUNES)) as executor:
        futuros = [executor.submit(escanear_un_puerto, host, p, s) for p, s in PUERTOS_COMUNES.items()]
        for futuro in concurrent.futures.as_completed(futuros):
            res = futuro.result()
            if res: puertos_encontrados.append(res)
    return sorted(puertos_encontrados, key=lambda x: x['puerto'])

@app.get("/", response_class=HTMLResponse)
async def leer_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def ejecutar_escaneo(request: Request, target: str):
    puertos = escanear_puertos_paralelo(target)
    host_online = len(puertos) > 0
    hay_amenazas = any(p['peligroso'] for p in puertos)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "target": target,
        "estado": "Online" if host_online else "Offline / Protegido",
        "puertos": puertos,
        "alerta_seguridad": hay_amenazas
    })