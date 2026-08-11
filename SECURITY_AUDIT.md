# Security audit

Estado: revisado el 2026-08-11.

- No se detectaron secretos reales, archivos `.env`, bases de datos ni artefactos privados versionados.
- La ejecución de herramientas externas está concentrada en `core/shell.py` y en módulos de pentesting autorizados; debe mantenerse la confirmación explícita de objetivos.
- La configuración YAML usa carga segura (`yaml.safe_load`).
- Validación: suite existente reportada como correcta (178 pruebas).

Pendiente operativo: ejecutar únicamente contra infraestructura propia o con autorización escrita y mantener las dependencias actualizadas.
