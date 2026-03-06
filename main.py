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
            sock.settimeout(1.0) # Aumentamos un poco el timeout para leer el banner
            resultado = sock.connect_ex((host, puerto))
            
            if resultado == 0:
                # Intentamos leer el Banner (la "firma" del software)
                banner = "No identificado"
                try:
                    # Enviamos una solicitud vacía para forzar una respuesta
                    # (Esto funciona bien en SSH y FTP, a veces en HTTP)
                    if puerto in {21, 22}:
                        # Esperamos a que el servidor envíe su banner inicial
                        banner_raw = sock.recv(1024)
                        banner = banner_raw.decode('utf-8', errors='ignore').strip()
                    elif puerto == 80:
                        # Para HTTP, enviamos una solicitud GET simple
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n")
                        banner_raw = sock.recv(1024)
                        # Buscamos la línea "Server:"
                        for line in banner_raw.decode('utf-8', errors='ignore').split('\n'):
                            if "Server:" in line:
                                banner = line.replace("Server:", "").strip()
                                break
                except:
                    pass # Si no responde el banner, seguimos

                puertos_encontrados.append({
                    "puerto": puerto,
                    "servicio": servicio,
                    "version": banner, # <--- NUEVO DATO
                    "peligroso": puerto in PUERTOS_CRITICOS
                })
            sock.close()
        except Exception:
            continue
    return puertos_encontrados

@app.get("/", response_class=HTMLResponse)
async def leer_index(request: Request):
    """Carga la página principal del dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def ejecutar_escaneo(request: Request, target: str):
    """Procesa el escaneo solicitado por el usuario."""
    # Realizamos el escaneo directo
    puertos_encontrados = escanear_puertos(target)
    
    # Determinamos el estado: si hay puertos abiertos, el host responde (Online)
    host_online = len(puertos_encontrados) > 0
    
    # Verificamos si existe alguna amenaza en los puertos detectados
    hay_amenazas = any(p['peligroso'] for p in puertos_encontrados)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "target": target,
        "estado": "Online" if host_online else "Offline (o Protegido)",
        "puertos": puertos_encontrados,
        "alerta_seguridad": hay_amenazas
    })

# Ruta adicional para API (opcional para tu portafolio)
@app.get("/api/escanear/{objetivo}")
async def api_escanear(objetivo: str):
    puertos = escanear_puertos(objetivo)
    return {
        "host": objetivo,
        "online": len(puertos) > 0,
        "puertos": puertos
    }