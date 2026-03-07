import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def buscar_secretos(html):
    hallazgos = []
    patrones = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Firebase URL": r"https://.*\.firebaseio\.com",
        "Posible Token/Secret": r"(?i)(key|secret|token|auth|pwd)\s*[:=]\s*['\"]([0-9a-zA-Z]{16,})['\"]"
    }
    for nombre, regex in patrones.items():
        if re.search(regex, html):
            hallazgos.append({
                "puerto": "APP", "servicio": "REGEX", "vector": f"Exposición de {nombre}",
                "nivel_riesgo": "Crítico", "tip": "Se detectó una credencial sensible en el código fuente HTML/JS."
            })
    return hallazgos

def probar_sql_injection(url):
    # Fuzzing básico: enviamos una comilla simple para ver si el servidor escupe un error de base de datos
    payloads = ["'", " OR 1=1", '"']
    errores_sql = ["sql syntax", "mysql_fetch", "sqlite3.OperationalError", "PostgreSQL query failed"]
    
    for p in payloads:
        try:
            test_url = f"{url}?id={p}"
            res = requests.get(test_url, timeout=3, verify=False)
            if any(error.lower() in res.text.lower() for error in errores_sql) or res.status_code == 500:
                return [{
                    "puerto": "DB", "servicio": "SQLi", "vector": "Posible Inyección SQL",
                    "nivel_riesgo": "Crítico", "tip": f"El endpoint respondió con error 500 o sintaxis SQL al enviar '{p}'. Revise la sanitización de inputs."
                }]
        except: pass
    return []

def analizar_cabeceras_http(url):
    target_url = url if url.startswith('http') else f"http://{url}"
    resultados = []
    
    try:
        response = requests.get(target_url, timeout=5, verify=False, allow_redirects=True)
        html_content = response.text
        headers = response.headers

        # 1. Auditoría de Cabeceras (Lo que ya teníamos)
        headers_criticos = {
            "Content-Security-Policy": "Riesgo de XSS.",
            "X-Frame-Options": "Riesgo de Clickjacking.",
            "Strict-Transport-Security": "Protocolo HTTPS no forzado."
        }
        for h, desc in headers_criticos.items():
            if h not in headers:
                resultados.append({
                    "puerto": "WEB", "servicio": "HTTP", "vector": f"Falta {h}",
                    "nivel_riesgo": "Medio", "tip": desc
                })

        # 2. Búsqueda de Secretos (NUEVO)
        resultados.extend(buscar_secretos(html_content))

        # 3. Probar SQLi (NUEVO)
        resultados.extend(probar_sql_injection(target_url))

        # 4. Análisis de Formularios (NUEVO)
        if "<form" in html_content.lower():
            if not target_url.startswith("https"):
                resultados.append({
                    "puerto": "WEB", "servicio": "FORM", "vector": "Formulario Inseguro",
                    "nivel_riesgo": "Alto", "tip": "El sitio captura datos en un formulario sin usar cifrado SSL (HTTPS)."
                })

    except Exception as e:
        print(f"Error en auditoría: {e}")
    
    return resultados