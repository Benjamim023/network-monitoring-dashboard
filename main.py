from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
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

# Puertos que disparan la ALERTA ROJA
# He incluido el 80 para que pruebes con google.com y veas el rojo.
PUERTOS_CRITICOS = {21, 23, 25, 445, 1433, 3306, 3389, 5900, 80}

CONSEJOS_SEGURIDAD = {
    21: "Riesgo alto. FTP envía datos en texto plano. Se recomienda usar SFTP/SSH.",
    22: "Servicio seguro, pero asegúrese de usar llaves SSH en lugar de contraseñas.",
    23: "CRÍTICO. Telnet no tiene cifrado. Reemplazar inmediatamente por SSH.",
    25: "Servidor de correo. Verificar que no permita 'Open Relay'.",
    80: "Puerto HTTP estándar. Considere forzar el uso de HTTPS (443).",
    445: "PELIGRO. SMB expuesto es vulnerable a Ransomware. Cerrar o usar VPN.",
    3306: "Base de datos expuesta. Riesgo de filtración masiva.",
    3389: "RDP expuesto. Blanco frecuente de ataques de fuerza bruta.",
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

            # Aseguramos que la comparación sea entre el mismo tipo de dato
            es_peligroso = puerto in PUERTOS_CRITICOS

            datos = {
                "puerto": puerto,
                "servicio": servicio,
                "version": banner,
                "peligroso": es_peligroso,
                "tip": CONSEJOS_SEGURIDAD.get(puerto, "Servicio estándar detectado.")
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
    # Si hay puertos abiertos, el host está Online
    host_online = len(puertos) > 0
    hay_amenazas = any(p['peligroso'] for p in puertos)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "target": target,
        "estado": "Online" if host_online else "Offline / Protegido",
        "puertos": puertos,
        "alerta_seguridad": hay_amenazas
    })