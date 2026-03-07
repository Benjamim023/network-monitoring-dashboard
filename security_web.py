import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fuzzer_directorios(base_url):
    hallazgos = []
    # Diccionario de rutas que NUNCA deberían estar públicas
    rutas_sensibles = {
        "/.git/config": "Repositorio expuesto (fuga de código fuente).",
        "/.env": "Archivo de configuración con credenciales expuesto.",
        "/phpmyadmin/": "Panel de base de datos detectado.",
        "/wp-admin/": "Panel de administración de WordPress.",
        "/backup/": "Posibles copias de seguridad expuestas.",
        "/server-status": "Información del servidor Apache expuesta."
    }

    for ruta, desc in rutas_sensibles.items():
        try:
            url_test = f"{base_url.rstrip('/')}{ruta}"
            res = requests.get(url_test, timeout=2, verify=False, allow_redirects=False)
            if res.status_code == 200:
                hallazgos.append({
                    "puerto": "DIR", "servicio": "FUZZER",
                    "vector": f"Directorio Expuesto: {ruta}",
                    "nivel_riesgo": "Crítico",
                    "tip": f"⚠️ Hallazgo grave. {desc}"
                })
        except: pass
    return hallazgos

def analizar_cabeceras_http(url):
    target_url = url if url.startswith('http') else f"http://{url}"
    resultados = []
    
    try:
        response = requests.get(target_url, timeout=5, verify=False)
        html_content = response.text
        headers = response.headers

        # 1. Cabeceras
        headers_criticos = {"Content-Security-Policy": "XSS", "X-Frame-Options": "Clickjacking"}
        for h, desc in headers_criticos.items():
            if h not in headers:
                resultados.append({
                    "puerto": "WEB", "servicio": "HTTP", "vector": f"Falta {h}",
                    "nivel_riesgo": "Medio", "tip": f"Riesgo de {desc}."
                })

        # 2. Búsqueda de Secretos (Regex)
        patrones = {"Google API": r"AIza[0-9A-Za-z-_]{35}", "Firebase": r"firebaseio\.com"}
        for nombre, reg in patrones.items():
            if re.search(reg, html_content):
                resultados.append({
                    "puerto": "APP", "servicio": "REGEX", "vector": f"Key de {nombre}",
                    "nivel_riesgo": "Crítico", "tip": "Credencial expuesta en el HTML."
                })

        # 3. FUZZER DE DIRECTORIOS (NUEVO)
        resultados.extend(fuzzer_directorios(target_url))

    except: pass
    return resultados