# 📡 NetWatch - Network Monitoring Dashboard

¡Bienvenido! Este es mi primer proyecto de portafolio enfocado en **Ciberseguridad** y **Desarrollo Web**. Es un dashboard que permite monitorear el estado de servidores y realizar auditorías de puertos abiertos en tiempo real.

## 🚀 Funcionalidades
* **Escaneo de Host:** Verifica si una IP o dominio está activo (Online/Offline) mediante Pings.
* **Auditoría de Puertos:** Escanea puertos comunes (80, 443, 22, etc.) para detectar servicios expuestos.
* **Interfaz Moderna:** Dashboard interactivo construido con FastAPI y Tailwind CSS.

## 🛠️ Tecnologías utilizadas
* **Lenguaje:** Python (Backend lógico).
* **Framework:** FastAPI (Servidor de alta velocidad).
* **Frontend:** Jinja2 Templates & Tailwind CSS.
* **Seguridad:** Librería `socket` para escaneo de conexiones.

## ⚙️ Cómo ejecutarlo
1. Clona el repositorio.
2. Crea un entorno virtual: `python -m venv venv`.
3. Activa el entorno e instala las dependencias: `pip install fastapi uvicorn jinja2`.
4. Ejecuta el servidor: `uvicorn main:app --reload`.