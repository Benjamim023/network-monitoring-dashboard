from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import socket
import concurrent.futures

app = FastAPI()
templates = Jinja2Templates(directory="templates")

PUERTOS_CRITICOS = {21, 23, 3389}
PUERTOS_COMUNES = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}

def escanear_un_puerto(host, puerto, servicio):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        resultado = sock.connect_ex((host, puerto))
        datos = None
        if resultado == 0:
            banner = "No identificado"
            try:
                if puerto in {21, 22}:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif puerto == 80:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n")
                    res = sock.recv(1024).decode('utf-8', errors='ignore')
                    for line in res.split('\n'):
                        if "Server:" in line:
                            banner = line.replace("Server:", "").strip()
                            break
            except: pass
            datos = {"puerto": puerto, "servicio": servicio, "version": banner, "peligroso": puerto in PUERTOS_CRITICOS}
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
    return templates.TemplateResponse("index.html", {
        "request": request, "target": target, "estado": "Online" if puertos else "Offline",
        "puertos": puertos, "alerta_seguridad": any(p['peligroso'] for p in puertos)
    })