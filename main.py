from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import subprocess
import platform
import socket

app = FastAPI()

# Configuramos la carpeta donde irán nuestros archivos HTML
templates = Jinja2Templates(directory="templates")

# ... (Mantené aquí tus funciones realizar_ping y escanear_puertos)

# Puertos que suelen ser interesantes en Ciberseguridad
PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP"
}

def realizar_ping(host):
    parametro = "-n" if platform.system().lower() == "windows" else "-c"
    comando = ["ping", parametro, "1", host]
    try:
        resultado = subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        return resultado.returncode == 0
    except:
        return False

def escanear_puertos(host):
    puertos_abiertos = []
    for puerto, servicio in PUERTOS_COMUNES.items():
        # Creamos un socket para intentar la conexión
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Tiempo máximo de espera por puerto
        resultado = sock.connect_ex((host, puerto))
        if resultado == 0:
            puertos_abiertos.append({"puerto": puerto, "servicio": servicio})
        sock.close()
    return puertos_abiertos

@app.get("/escanear/{objetivo}")
def escanear_completo(objetivo: str):
    online = realizar_ping(objetivo)
    puertos = []
    
    if online:
        puertos = escanear_puertos(objetivo)
        
    return {
        "host": objetivo,
        "estado": "Online" if online else "Offline",
        "puertos_abiertos": puertos,
        "alerta_seguridad": len(puertos) > 2 # Un ejemplo de lógica de seguridad
    }

@app.get("/", response_class=HTMLResponse)
async def leer_index(request: Request):
    # Esta función ahora es la dueña de la página principal
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/scan")
async def ejecutar_escaneo(request: Request, target: str):
    # Esta función procesará los datos cuando toques el botón "Escanear"
    online = realizar_ping(target)
    puertos = []
    if online:
        puertos = escanear_puertos(target)
    
    # Por ahora, devolvemos los datos a una nueva página de resultados
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "target": target, 
        "estado": "Online" if online else "Offline",
        "puertos": puertos
    })