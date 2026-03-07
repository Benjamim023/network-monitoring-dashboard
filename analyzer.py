def obtener_consejos_seguridad(puerto, banner=""):
    """
    Analiza el puerto y el banner para identificar vectores de ataque 
    y dar consejos de protección profesionales.
    """
    recomendaciones = {
        "vector": "Servicio estándar detectado",
        "nivel_riesgo": "Bajo",
        "consejo": "Mantenga sus servicios actualizados y monitoreados de forma proactiva."
    }

    # Lógica para Puertos Críticos (Fuerza Bruta)
    if puerto in [21, 22, 23, 3389]:
        recomendaciones["vector"] = "Acceso Remoto / Fuerza Bruta"
        recomendaciones["nivel_riesgo"] = "Alto"
        recomendaciones["consejo"] = (
            f"El puerto {puerto} está expuesto. Use autenticación de doble factor (2FA) "
            "o restrinja el acceso mediante una VPN para mitigar intentos de login."
        )

    # Lógica para Bases de Datos (Inyección SQL)
    elif puerto in [3306, 5432, 27017, 1433]:
        recomendaciones["vector"] = "Exposición de Base de Datos"
        recomendaciones["nivel_riesgo"] = "Crítico"
        recomendaciones["consejo"] = (
            "⚠️ NUNCA exponga bases de datos a Internet. Riesgo de filtración masiva. "
            "Cierre el puerto y use un túnel SSH para administración segura."
        )

    # Lógica para Web (Cleartext)
    elif puerto == 80:
        recomendaciones["vector"] = "Tráfico No Cifrado (Cleartext)"
        recomendaciones["nivel_riesgo"] = "Medio"
        recomendaciones["consejo"] = (
            "El puerto 80 (HTTP) viaja sin cifrar. Implemente un certificado SSL/TLS "
            "y configure una redirección permanente al puerto 443 (HTTPS)."
        )
    
    # Lógica para SMB (Ransomware)
    elif puerto == 445:
        recomendaciones["vector"] = "Vulnerabilidad SMB / Ransomware"
        recomendaciones["nivel_riesgo"] = "Crítico"
        recomendaciones["consejo"] = (
            "PELIGRO: SMB expuesto es la vía principal para ataques de Ransomware. "
            "Cierre este puerto inmediatamente en el firewall perimetral."
        )

    return recomendaciones