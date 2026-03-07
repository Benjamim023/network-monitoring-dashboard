import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fuzzer_directorios(base_url):
    hallazgos = []
    # Rutas que NUNCA deberían estar públicas
    rutas_sensibles = {
        "/.git/config": "Repositorio expuesto (fuga de código fuente).",
        "/.env": "Archivo de configuración con credenciales expuesto.",
        "/phpmyadmin/": "Panel de base de datos detectado.",
        "/wp-admin/": "Panel de administración de WordPress.",
        "/backup/": "Posibles copias de seguridad expuestas."
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
        
        # 1. Búsqueda de Secretos (Regex)
        patrones = {"Google API": r"AIza[0-9A-Za-z-_]{35}", "Firebase": r"firebaseio\.com"}
        for nombre, reg in patrones.items():
            if re.search(reg, html_content):
                resultados.append({
                    "puerto": "APP", "servicio": "REGEX", "vector": f"Key de {nombre}",
                    "nivel_riesgo": "Crítico", "tip": "Credencial expuesta en el HTML."
                })

        # 2. FUZZER DE DIRECTORIOS
        resultados.extend(fuzzer_directorios(target_url))

        # 3. SQL Injection básico
        if "?" in target_url:
            res_sql = requests.get(f"{target_url}'", timeout=2, verify=False)
            if res_sql.status_code == 500 or "sql" in res_sql.text.lower():
                resultados.append({
                    "puerto": "DB", "servicio": "SQLi", "vector": "Posible Inyección SQL",
                    "nivel_riesgo": "Crítico", "tip": "El servidor falló al enviar una comilla simple."
                })

    except: pass
    return resultados