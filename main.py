from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import socket
import concurrent.futures

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Diccionario extendido de puertos y servicios
PUERTOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-Proxy"
}

# Puertos que disparan alertas de riesgo
PUERTOS_CRITICOS = {21, 23, 25, 445, 1433, 3306, 3389, 5900}

# Base de datos de recomendaciones de seguridad
CONSEJOS_SEGURIDAD = {
    21: "Riesgo alto. FTP envía datos en texto plano. Se recomienda usar SFTP/SSH.",
    22: "Servicio seguro, pero asegúrese de usar llaves SSH en lugar de contraseñas.",
    23: "CRÍTICO. Telnet no tiene cifrado. Reemplazar inmediatamente por SSH.",
    25: "Servidor de correo. Verificar que no permita 'Open Relay' para evitar spam.",
    445: "PELIGRO. SMB expuesto es vulnerable a Ransomware (WannaCry). Cerrar o usar VPN.",
    3306: "Base de datos expuesta. Riesgo de filtración. No exponer a Internet.",
    1433: "MSSQL detectado. Blanco frecuente de ataques de fuerza bruta.",
    3389: "RDP expuesto. Limitar acceso por IP o usar un Gateway de escritorio remoto.",
    5900: "VNC detectado. Asegurar con contraseñas robustas y túneles cifrados."
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
                # Intento de Banner Grabbing
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

            # Asignar consejo de seguridad
            consejo = CONSEJOS_SEGURIDAD.get(puerto, "Servicio estándar. Mantener software actualizado.")

            datos = {
                "puerto": puerto,
                "servicio": servicio,
                "version": banner,
                "peligroso": puerto in PUERTOS_CRITICOS,
                "tip": consejo
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
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "target": target, 
        "estado": "Online" if puertos else "Offline / Protegido",
        "puertos": puertos, 
        "alerta_seguridad": any(p['peligroso'] for p in puertos)
    })