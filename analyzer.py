def obtener_consejos_seguridad(puerto, banner=""):
    """
    Analiza puertos y banners para identificar vectores de ataque.
    """
    recomendaciones = {
        "vector": "Servicio estándar",
        "nivel_riesgo": "Bajo",
        "tip": "Mantenga sus servicios actualizados y monitoreados."
    }

    # Lógica de Puertos Críticos
    if puerto in [21, 22, 23, 3389]:
        recomendaciones.update({
            "vector": "Acceso Remoto / Fuerza Bruta",
            "nivel_riesgo": "Alto",
            "tip": f"Puerto {puerto} expuesto. Use VPN o 2FA para mitigar riesgos."
        })

    # Lógica de Bases de Datos
    elif puerto in [3306, 5432, 27017, 1433]:
        recomendaciones.update({
            "vector": "Exposición de Base de Datos",
            "nivel_riesgo": "Crítico",
            "tip": "⚠️ NUNCA exponga bases de datos a Internet directamente."
        })

    return recomendaciones