"""Análisis de cabeceras de seguridad HTTP.

Función pura: recibe un diccionario de cabeceras y devuelve un informe.
No toca la red, así que se prueba sin servidor.

Cada regla dice qué mitiga y por qué, porque un informe que sólo dice
"falta X" no le enseña nada a quien lo lee.
"""

CRITICA = "critica"
IMPORTANTE = "importante"
RECOMENDADA = "recomendada"

_ORDEN = {CRITICA: 0, IMPORTANTE: 1, RECOMENDADA: 2}


def _csp(valor):
    if valor is None:
        return (False, "No hay Content-Security-Policy. El navegador ejecutará "
                       "cualquier script que llegue a inyectarse en la página.")
    problemas = []
    v = valor.lower()
    if "unsafe-inline" in v and "script-src" in v:
        problemas.append("permite scripts inline ('unsafe-inline'), que es "
                         "justamente lo que una CSP debería impedir")
    if "unsafe-eval" in v:
        problemas.append("permite eval()")
    if "default-src" not in v and "script-src" not in v:
        problemas.append("no declara default-src ni script-src")
    if "frame-ancestors" not in v:
        problemas.append("no declara frame-ancestors, así que no protege "
                         "contra clickjacking")
    if problemas:
        return (False, "Hay CSP pero " + "; ".join(problemas) + ".")
    return (True, "CSP presente y con las directivas base declaradas.")


def _hsts(valor):
    if valor is None:
        return (False, "Sin HSTS. Un atacante en la red puede forzar la primera "
                       "conexión por HTTP y quedarse en el medio.")
    v = valor.lower()
    edad = 0
    for parte in v.split(";"):
        parte = parte.strip()
        if parte.startswith("max-age="):
            try:
                edad = int(parte.split("=", 1)[1])
            except ValueError:
                edad = 0
    if edad < 15552000:
        return (False, "HSTS con max-age muy corto (%ss). Se recomienda al "
                       "menos 15552000, o sea seis meses." % edad)
    return (True, "HSTS con max-age suficiente.")


def _nosniff(valor):
    if valor is None:
        return (False, "Sin X-Content-Type-Options. El navegador puede adivinar "
                       "el tipo de un archivo y ejecutar como script algo que "
                       "se subió como imagen.")
    if valor.strip().lower() != "nosniff":
        return (False, "X-Content-Type-Options presente pero con un valor que "
                       "no es 'nosniff'.")
    return (True, "Sniffing de tipo desactivado.")


def _referrer(valor):
    inseguras = {"unsafe-url", "no-referrer-when-downgrade", ""}
    if valor is None:
        return (False, "Sin Referrer-Policy. Las URLs internas se filtran a los "
                       "sitios externos que se enlacen.")
    if valor.strip().lower() in inseguras:
        return (False, "Referrer-Policy con un valor permisivo: filtra la URL "
                       "completa hacia afuera.")
    return (True, "Política de referente restrictiva.")


def _permissions(valor):
    if valor is None:
        return (False, "Sin Permissions-Policy. No se restringe el acceso a "
                       "cámara, micrófono y geolocalización.")
    return (True, "Permisos de dispositivo restringidos explícitamente.")


def _server(valor):
    if valor is None:
        return (True, "El servidor no anuncia su versión.")
    if any(c.isdigit() for c in valor):
        return (False, "La cabecera Server expone versión ('%s'). Le regala al "
                       "atacante la lista de vulnerabilidades conocidas." % valor)
    return (True, "Cabecera Server sin número de versión.")


REGLAS = (
    ("content-security-policy", "Content-Security-Policy", CRITICA, _csp),
    ("strict-transport-security", "Strict-Transport-Security", CRITICA, _hsts),
    ("x-content-type-options", "X-Content-Type-Options", IMPORTANTE, _nosniff),
    ("referrer-policy", "Referrer-Policy", IMPORTANTE, _referrer),
    ("permissions-policy", "Permissions-Policy", RECOMENDADA, _permissions),
    ("server", "Server", RECOMENDADA, _server),
)

_PESOS = {CRITICA: 30, IMPORTANTE: 15, RECOMENDADA: 5}


def analizar(cabeceras):
    """Devuelve {'puntaje': 0-100, 'nota': 'A'..'F', 'hallazgos': [...]}"""
    cabeceras = {k.lower(): v for k, v in (cabeceras or {}).items()}

    hallazgos = []
    obtenido = 0
    total = 0

    for clave, etiqueta, gravedad, regla in REGLAS:
        peso = _PESOS[gravedad]
        total += peso
        cumple, detalle = regla(cabeceras.get(clave))
        if cumple:
            obtenido += peso
        hallazgos.append({
            "cabecera": etiqueta,
            "gravedad": gravedad,
            "cumple": cumple,
            "detalle": detalle,
            "valor": cabeceras.get(clave),
        })

    hallazgos.sort(key=lambda h: (h["cumple"], _ORDEN[h["gravedad"]]))
    puntaje = round(obtenido * 100 / total) if total else 0

    if puntaje >= 90:
        nota = "A"
    elif puntaje >= 75:
        nota = "B"
    elif puntaje >= 60:
        nota = "C"
    elif puntaje >= 40:
        nota = "D"
    else:
        nota = "F"

    return {"puntaje": puntaje, "nota": nota, "hallazgos": hallazgos}
