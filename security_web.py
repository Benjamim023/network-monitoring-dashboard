import requests

def analizar_cabeceras_http(url):
    """
    Analiza las cabeceras de respuesta de un servidor web para detectar 
    la falta de configuraciones de seguridad esenciales.
    """
    if not url.startswith('http'):
        url = f"http://{url}"
        
    resultados = []
    headers_criticos = {
        "Content-Security-Policy": "Previene ataques de XSS al restringir de dónde se carga el contenido.",
        "X-Frame-Options": "Protege contra Clickjacking al evitar que el sitio sea embebido en iframes ajenos.",
        "Strict-Transport-Security": "Fuerza el uso de HTTPS (HSTS) para evitar ataques de degradación de protocolo."
    }

    try:
        response = requests.get(url, timeout=3)
        headers = response.headers

        for header, descripcion in headers_criticos.items():
            if header not in headers:
                resultados.append({
                    "puerto": 80 if url.startswith('http://') else 443,
                    "vector": f"Falta cabecera {header}",
                    "nivel_riesgo": "Medio",
                    "tip": f"Riesgo de seguridad web. {descripcion}"
                })
    except:
        pass
    return resultados