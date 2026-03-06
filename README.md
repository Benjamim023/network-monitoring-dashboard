# 📡 NetWatch - AI Security Labs

![Security Audit](https://img.shields.io/badge/Security-Audit-emerald) ![FastAPI](https://img.shields.io/badge/Backend-FastAPI-blue) ![Python](https://img.shields.io/badge/Language-Python-yellow)

**NetWatch** es una herramienta avanzada de auditoría de red y monitoreo de infraestructura diseñada para identificar servicios expuestos y potenciales vulnerabilidades en tiempo real. Este proyecto combina técnicas de **Ciberseguridad** con un desarrollo web moderno y eficiente.

🌐 **Demo en vivo:** [https://network-monitoring-dashboard-kain.onrender.com](https://network-monitoring-dashboard-kain.onrender.com)

---

## 🚀 Funcionalidades Avanzadas

* **Escaneo Multihilo (Multithreading):** Implementación de `concurrent.futures` para realizar auditorías paralelas, reduciendo el tiempo de respuesta en un 80%.
* **Banner Grabbing:** Identificación de versiones de software y firmas de servidor (ej: Apache, OpenSSH, GWS) directamente desde los sockets.
* **Sistema de Recomendaciones:** Generación automática de consejos de seguridad (Audit Logs) basados en los puertos detectados.
* **Detección de Amenazas:** Filtro de criticidad para puertos vulnerables como FTP (21), Telnet (23) y SMB (445) con alertas visuales de alta visibilidad.
* **Interfaz Cyber-Dark:** Dashboard interactivo con fondo de red neuronal (Particles.js) y diseño responsivo utilizando Tailwind CSS y efectos de glassmorphism.

---

## 🛠️ Tecnologías Utilizadas

* **Backend:** Python 3.x con **FastAPI** para una gestión de peticiones asíncrona y veloz.
* **Networking:** Librería `socket` nativa para escaneo de bajo nivel y obtención de banners.
* **Frontend:** **Jinja2 Templates** y **Tailwind CSS**.
* **Efectos Visuales:** **Particles.js** para la visualización de la red de nodos interactiva.

---

## ⚙️ Instalación y Ejecución Local

1.  **Clona el repositorio:**
    ```bash
    git clone [https://github.com/Benjamim023/network-monitoring-dashboard.git](https://github.com/Benjamim023/network-monitoring-dashboard.git)
    cd network-monitoring-dashboard
    ```
2.  **Crea y activa un entorno virtual:**
    ```bash
    python -m venv venv
    # En Windows:
    .\venv\Scripts\activate
    ```
3.  **Instala las dependencias:**
    ```bash
    pip install fastapi uvicorn jinja2
    ```
4.  **Inicia el servidor:**
    ```bash
    uvicorn main:app --reload
    ```

---

## 🛡️ Aviso de Seguridad
Este proyecto fue desarrollado con fines educativos y de portafolio para mi formación en **Desarrollo de Software**. El uso de esta herramienta debe limitarse a infraestructuras propias o bajo autorización explícita.

**Desarrollado en Marzo 2026 • Portafolio Profesional.**