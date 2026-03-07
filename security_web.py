import requests
import urllib3

# Desactivar advertencias de certificados inseguros (útil para escaneos de auditoría)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def analizar_cabeceras_http(url):
    """
    Analiza las cabeceras de respuesta de un servidor web para detectar 
    la falta de configuraciones de seguridad esenciales.
    """
    # Limpieza básica de la URL
    target_url = url if url.startswith('http') else f"http://{url}"
        
    resultados = []
    headers_criticos = {
        "Content-Security-Policy": "Previene ataques de XSS al restringir de dónde se carga el contenido.",
        "X-Frame-Options": "Protege contra Clickjacking al evitar que el sitio sea embebido en iframes.",
        "Strict-Transport-Security": "Fuerza el uso de HTTPS (HSTS) para evitar ataques de degradación."
    }

    try:
        # verify=False evita que el escaneo muera si el sitio tiene un SSL mal configurado
        response = requests.get(target_url, timeout=5, verify=False, allow_redirects=True)
        headers = response.headers

        for header, descripcion in headers_criticos.items():
            if header not in headers:
                resultados.append({
                    "puerto": 80 if target_url.startswith('http://') else 443,
                    "servicio": "WEB-SEC",  # <--- CLAVE CORREGIDA: Ahora el HTML no se rompe
                    "vector": f"Falta cabecera {header}",
                    "nivel_riesgo": "Medio",
                    "tip": f"Riesgo de seguridad web. {descripcion}",
                    "peligroso": False
                })
    except Exception as e:
        # Si falla la conexión web, devolvemos lista vacía para no romper el main.py
        print(f"Error en auditoría web: {e}")
        pass
        
    return resultados