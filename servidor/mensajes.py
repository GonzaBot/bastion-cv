"""Lectura del buzón de contacto y render del panel de administración.

Server-rendered, sin JS: la misma filosofía que el resto del sitio. Todo
campo que viene del formulario pasa por escapar_html antes de imprimirse,
porque evaluar_formulario normaliza pero NO escapa (ver validacion.py) — el
panel es el primer lugar del código que efectivamente muestra ese texto.
"""

import json
from datetime import datetime, timezone

from servidor.validacion import escapar_html

ESTILO = """<style>
:root{--papel:#EDEBE2;--tinta:#161A17;--acero:#545E58;--regla:#C9C5B8;}
@media (prefers-color-scheme: dark){
  :root{--papel:#14170F;--tinta:#E6E4D9;--acero:#9AA398;--regla:#333A32;}
}
body{background:var(--papel);color:var(--tinta);font:16px/1.5 system-ui,sans-serif;
     max-width:760px;margin:2rem auto;padding:0 1rem;}
h1{font-size:1.3rem;margin:0 0 .25rem}
.contador{color:var(--acero);margin:0 0 2rem}
article{border:1px solid var(--regla);border-radius:6px;padding:1rem 1.25rem;margin-bottom:1rem}
article header{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;
                font-size:.9rem;color:var(--acero);margin-bottom:.5rem}
article h2{font-size:1.05rem;margin:0 0 .15rem}
.motivo{color:var(--acero);font-size:.9rem;margin:0 0 .5rem}
.mensaje{white-space:pre-wrap;margin:0}
a{color:inherit}
.vacio{color:var(--acero)}
</style>"""


def leer_mensajes(ruta):
    """Más reciente primero. Una línea corrupta se descarta y no tira abajo
    el resto del buzón."""
    if not ruta.exists():
        return []
    mensajes = []
    with open(ruta, encoding="utf-8") as archivo:
        for linea in archivo:
            linea = linea.strip()
            if not linea:
                continue
            try:
                mensajes.append(json.loads(linea))
            except json.JSONDecodeError:
                continue
    mensajes.sort(key=lambda m: m.get("recibido", 0) or 0, reverse=True)
    return mensajes


def _fecha(marca):
    try:
        return (datetime.fromtimestamp(marca, tz=timezone.utc)
                 .astimezone().strftime("%d/%m/%Y %H:%M"))
    except (TypeError, ValueError, OSError):
        return "fecha desconocida"


def _tarjeta(mensaje):
    nombre = escapar_html(mensaje.get("nombre", ""))
    mail = escapar_html(mensaje.get("mail", ""))
    motivo = escapar_html(mensaje.get("motivo", ""))
    cuerpo = escapar_html(mensaje.get("mensaje", ""))
    fecha = escapar_html(_fecha(mensaje.get("recibido")))
    return (
        "<article>"
        f"<header><span>{fecha}</span><a href=\"mailto:{mail}\">{mail}</a></header>"
        f"<h2>{nombre}</h2>"
        f"<p class=\"motivo\">{motivo}</p>"
        f"<p class=\"mensaje\">{cuerpo}</p>"
        "</article>"
    )


def renderizar_panel(mensajes):
    cuerpo = "".join(_tarjeta(m) for m in mensajes) or (
        '<p class="vacio">Todavía no llegó ningún mensaje.</p>')
    return (
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex, nofollow\">"
        f"<title>Mensajes</title>{ESTILO}</head><body>"
        "<h1>Mensajes recibidos</h1>"
        f"<p class=\"contador\">{len(mensajes)} en total</p>"
        f"{cuerpo}"
        "</body></html>"
    )
