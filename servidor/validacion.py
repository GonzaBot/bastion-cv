"""Validación del lado servidor.

Espejo exacto de web/js/validacion.js. Las dos implementaciones se verifican
contra spec/casos.json, así que no pueden divergir en silencio.

Esta capa SÍ es un control de seguridad: el cliente está bajo control de quien
envía, así que todo lo que valida el navegador se vuelve a validar acá desde cero.
"""

import re
import unicodedata

# ── Expresiones precompiladas ───────────────────────────────────────────

_ESPACIOS_CONTROL = re.compile(r"[\t\n\r\f\v]")
_CONTROL_RESTANTE = re.compile(r"[\u0000-\u001F\u007F-\u009F]")
_ANCHO_CERO = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
# Marcas y aisladores bidireccionales: el texto se MUESTRA distinto de como
# está almacenado (clase Trojan Source, CVE-2021-42574).
_BIDI = re.compile(r"[\u200E\u200F\u202A-\u202E\u2066-\u2069]")
_ESPACIOS_MULTI = re.compile(r"\s+")

_CORREO = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

_CRLF_CRUDO = re.compile(r"[\r\n]")
_CRLF_CODIFICADO = re.compile(r"%0[aAdD]|%00|\\r|\\n|\u2028|\u2029")
# 'to' y 'from' quedan fuera a propósito: en español dan falsos positivos
# ("Presupuesto:", "punto:").
_CABECERAS = re.compile(
    r"(?:^|[\s;,])(bcc|cc|reply-to|content-type|content-transfer-encoding"
    r"|mime-version|x-mailer)\s*:",
    re.IGNORECASE,
)

_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
_A_ESCAPAR = re.compile(r"[&<>\"']")


# ── 1. normalizar ───────────────────────────────────────────────────────

def normalizar(valor):
    """Punto de entrada único. Todo lo demás asume texto ya normalizado."""
    if not isinstance(valor, str):
        return ""
    texto = unicodedata.normalize("NFC", valor)
    texto = _ESPACIOS_CONTROL.sub(" ", texto)
    texto = _CONTROL_RESTANTE.sub("", texto)
    texto = _ANCHO_CERO.sub("", texto)
    texto = _BIDI.sub("", texto)
    texto = _ESPACIOS_MULTI.sub(" ", texto)
    return texto.strip()


# ── 2. es_correo_valido ─────────────────────────────────────────────────

def es_correo_valido(valor):
    if not isinstance(valor, str):
        return False
    if len(valor) == 0 or len(valor) > 254:
        return False
    arroba = valor.find("@")
    if arroba == -1 or arroba > 64:
        return False
    return bool(_CORREO.match(valor))


# ── 3. tiene_inyeccion_de_cabecera ──────────────────────────────────────

def tiene_inyeccion_de_cabecera(valor):
    if not isinstance(valor, str):
        return False
    if _CRLF_CRUDO.search(valor):
        return True
    if _CRLF_CODIFICADO.search(valor):
        return True
    return bool(_CABECERAS.search(valor))


# ── 4. escapar_html ─────────────────────────────────────────────────────

def escapar_html(valor):
    """Defensa en profundidad. No escapa '/' ni backtick: seguro en nodos de
    texto y atributos entrecomillados, NO en atributos sin comillas."""
    if not isinstance(valor, str):
        return ""
    return _A_ESCAPAR.sub(lambda m: _ESCAPES[m.group(0)], valor)


# ── 5. longitud_en_rango ────────────────────────────────────────────────

def longitud_en_rango(valor, minimo, maximo):
    if not isinstance(valor, str):
        return False
    return minimo <= len(valor) <= maximo


# ── 6. evaluar_formulario ───────────────────────────────────────────────

CAMPOS = (
    {"nombre": "nombre", "min": 2, "max": 80, "correo": False},
    {"nombre": "mail", "min": 5, "max": 254, "correo": True},
    {"nombre": "motivo", "min": 3, "max": 120, "correo": False},
    {"nombre": "mensaje", "min": 20, "max": 4000, "correo": False},
)


def evaluar_formulario(datos, opciones=None):
    """Devuelve {'valido': bool, 'errores': [{'campo','codigo'}], 'limpio': {}}."""
    d = datos if isinstance(datos, dict) else {}
    o = opciones if isinstance(opciones, dict) else {}

    ms_minimos = o.get("msMinimos", 3000)
    if not isinstance(ms_minimos, (int, float)):
        ms_minimos = 3000

    errores = []
    limpio = {}

    # El honeypot corta primero y sin detalle: a un bot no se le explica qué falló.
    if normalizar(o.get("honeypot")) != "":
        return {
            "valido": False,
            "errores": [{"campo": "honeypot", "codigo": "honeypot"}],
            "limpio": limpio,
        }

    for campo in CAMPOS:
        nombre = campo["nombre"]
        valor = normalizar(d.get(nombre))
        limpio[nombre] = valor

        if valor == "":
            errores.append({"campo": nombre, "codigo": "requerido"})
            continue
        if tiene_inyeccion_de_cabecera(valor):
            errores.append({"campo": nombre, "codigo": "inyeccion"})
            continue
        if campo["correo"] and not es_correo_valido(valor):
            errores.append({"campo": nombre, "codigo": "correo_invalido"})
            continue
        if not longitud_en_rango(valor, campo["min"], campo["max"]):
            errores.append({"campo": nombre, "codigo": "longitud"})

    # El umbral temporal se evalúa AL FINAL y sólo si los campos están bien:
    # si cortara antes, un humano rápido se quedaría sin saber qué corregir.
    if not errores:
        ms = o.get("msTranscurridos")
        if isinstance(ms, (int, float)) and not isinstance(ms, bool) and ms < ms_minimos:
            return {
                "valido": False,
                "errores": [{"campo": "formulario", "codigo": "demasiado_rapido"}],
                "limpio": limpio,
            }

    return {"valido": len(errores) == 0, "errores": errores, "limpio": limpio}
