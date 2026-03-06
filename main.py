from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import socket

app = FastAPI()

# Configuración de plantillas HTML
templates = Jinja2Templates(directory="templates")

# Definición de parámetros de seguridad
PUERTOS_CRITICOS = {21, 23, 3389}  # FTP, Telnet, RDP
PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP"
}

def escanear_puertos(host):
    """Escanea los puertos y realiza Banner Grabbing para identificar el servicio."""
    puertos_encontrados = []
    for puerto, servicio in PUERTOS_COMUNES.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0) 
            resultado = sock.connect_ex((host, puerto))
            
            if resultado == 0:
                banner = "No identificado"
                try:
                    # Lógica de Banner Grabbing por protocolo
                    if puerto in {21, 22}:
                        banner_raw = sock.recv(1024)
                        banner = banner_raw.decode('utf-8', errors='ignore').strip()
                    elif puerto == 80:
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n")
                        banner_raw = sock.recv(1024)
                        for line in banner_raw.decode('utf-8', errors='ignore').split('\n'):
                            if "Server:" in line:
                                banner = line.replace("Server:", "").strip()
                                break
                except:
                    pass 

                puertos_encontrados.append({
                    "puerto": puerto,
                    "servicio": servicio,
                    "version": banner,
                    "peligroso": puerto in PUERTOS_CRITICOS
                })
            sock.close()
        except Exception:
            continue
    return puertos_encontrados

@app.get("/", response_class=HTMLResponse)
async def leer_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def ejecutar_escaneo(request: Request, target: str):
    puertos_encontrados = escanear_puertos(target)
    host_online = len(puertos_encontrados) > 0
    hay_amenazas = any(p['peligroso'] for p in puertos_encontrados)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "target": target,
        "estado": "Online" if host_online else "Offline (o Protegido)",
        "puertos": puertos_encontrados,
        "alerta_seguridad": hay_amenazas
    })