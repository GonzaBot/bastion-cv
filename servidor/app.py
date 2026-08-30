"""Aplicación Flask.

Rutas:
  GET  /                    → la página
  GET  /api/token           → token anti-CSRF
  POST /api/contacto        → recepción del formulario
  POST /api/cabeceras       → analizador de cabeceras de seguridad
  GET  /api/salud           → chequeo de vida
  GET  /admin/mensajes      → panel de lectura del buzón, con Basic Auth

Ejecutar en desarrollo:
    export CLAVE_SECRETA="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
    python3 -m servidor.app
"""

import json
import logging
import os
import time
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler

from servidor import cabeceras as mod_cabeceras
from servidor import mensajes as mod_mensajes
from servidor import red
from servidor import validacion
from servidor.seguridad import (LimiteDoble, Tokens, admin_autorizado,
                                 aplicar_cabeceras, construir_csp, hash_css,
                                 origen_permitido)

RAIZ = Path(__file__).resolve().parent.parent
WEB = RAIZ / "web"
BUZON = RAIZ / "datos" / "mensajes.jsonl"

TAMANO_MAXIMO_PETICION = 64 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cv")


def _advertir_si_secreto_debil(nombre, valor, minimo):
    """Chequeo de higiene, no de negocio: nadie valida la fuerza de sus
    propios secretos hasta que alguien se la audita. Corto, no bloqueante —
    una clave débil sigue funcionando, sólo que peor."""
    if valor and len(valor) < minimo:
        log.warning(
            "%s tiene %d caracteres; se recomiendan al menos %d. Una clave "
            "corta es más fácil de adivinar por fuerza bruta.",
            nombre, len(valor), minimo,
        )


def _hashes_estilo():
    """Un hash CSP por cada <style> embebido que existe hoy en el sitio: las
    tres páginas estáticas más el panel de administración. Se recalcula acá,
    a partir de los archivos reales, para no tener un hash pegado a mano en
    seguridad.py que se desincronice el día que alguien edite el CSS."""
    hashes = []
    for nombre in ("index.html", "pruebas.html"):
        ruta = WEB / nombre
        if ruta.exists():
            h = hash_css(ruta.read_text(encoding="utf-8"))
            if h:
                hashes.append(h)
    h = hash_css(mod_mensajes.ESTILO)
    if h:
        hashes.append(h)
    return hashes


def crear_app(config=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(
        MAX_CONTENT_LENGTH=TAMANO_MAXIMO_PETICION,
        ORIGENES=[o for o in os.environ.get(
            "ORIGENES", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o],
        JSON_SORT_KEYS=False,
        ADMIN_USUARIO=os.environ.get("ADMIN_USUARIO", "admin"),
        ADMIN_CLAVE=os.environ.get("ADMIN_CLAVE", ""),
        DETRAS_DE_PROXY=os.environ.get("DETRAS_DE_PROXY") == "1",
    )
    if config:
        app.config.update(config)

    _advertir_si_secreto_debil("CLAVE_SECRETA", os.environ.get("CLAVE_SECRETA"), minimo=32)
    _advertir_si_secreto_debil("ADMIN_CLAVE", app.config["ADMIN_CLAVE"], minimo=12)

    if app.config["DETRAS_DE_PROXY"]:
        # Confía en UN proxy inverso propio delante (nginx). Sin esto, detrás
        # de un proxy que termina TLS, wsgi.url_scheme llega siempre en "http"
        # (Flask habla HTTP plano con nginx en localhost) y request.is_secure
        # da falso para siempre — HSTS no se manda nunca, aunque el visitante
        # sí esté en HTTPS de punta a punta.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1,
                                 x_host=0, x_port=0, x_prefix=0)

    tokens = Tokens()
    limite_contacto = LimiteDoble(maximo_por_ip=5, ventana_por_ip=300,
                                   maximo_global=40, ventana_global=300)
    limite_cabeceras = LimiteDoble(maximo_por_ip=10, ventana_por_ip=60,
                                    maximo_global=40, ventana_global=60)
    limite_admin = LimiteDoble(maximo_por_ip=20, ventana_por_ip=300,
                                maximo_global=60, ventana_global=300)

    app.extensions["tokens"] = tokens
    app.extensions["limite_contacto"] = limite_contacto
    app.extensions["limite_cabeceras"] = limite_cabeceras
    app.extensions["limite_admin"] = limite_admin

    csp = construir_csp(_hashes_estilo())

    # ── Cabeceras en toda respuesta ─────────────────────────────────────

    @app.after_request
    def _cabeceras(respuesta):
        return aplicar_cabeceras(respuesta, https=request.is_secure, csp=csp)

    # ── Utilidades ──────────────────────────────────────────────────────

    def cliente():
        """IP del cliente. Con DETRAS_DE_PROXY=1, ProxyFix ya reescribió
        request.remote_addr a partir de X-Forwarded-For (confiando en UN
        salto: el del proxy inverso propio). Sin la variable, esa cabecera
        se ignora del todo — si no, cualquiera la manda y falsea su IP,
        anulando el límite de tasa."""
        return request.remote_addr or "desconocido"

    def cuerpo_json():
        if not request.is_json:
            return None
        try:
            datos = request.get_json(silent=True)
        except Exception:
            return None
        return datos if isinstance(datos, dict) else None

    def verificar_csrf(datos):
        if not origen_permitido(
            request.headers.get("Origin"),
            request.headers.get("Referer"),
            app.config["ORIGENES"],
        ):
            return "origen_no_permitido"
        if not tokens.es_valido(datos.get("token")):
            return "token_invalido"
        return None

    # ── Rutas estáticas ─────────────────────────────────────────────────

    @app.get("/")
    def inicio():
        return send_from_directory(WEB, "index.html")

    @app.get("/<path:recurso>")
    def estatico(recurso):
        # send_from_directory ya bloquea el salto de directorio (..).
        return send_from_directory(WEB, recurso)

    # ── API ─────────────────────────────────────────────────────────────

    @app.get("/api/salud")
    def salud():
        return jsonify({"estado": "vivo"})

    @app.get("/api/token")
    def token():
        return jsonify({"token": tokens.emitir()})

    @app.post("/api/contacto")
    def contacto():
        datos = cuerpo_json()
        if datos is None:
            return jsonify({"valido": False, "errores": [
                {"campo": "formulario", "codigo": "peticion_invalida"}]}), 400

        if not limite_contacto.permitido(cliente()):
            return jsonify({"valido": False, "errores": [
                {"campo": "formulario", "codigo": "demasiados_intentos"}]}), 429

        problema = verificar_csrf(datos)
        if problema:
            return jsonify({"valido": False, "errores": [
                {"campo": "formulario", "codigo": problema}]}), 403

        resultado = validacion.evaluar_formulario(
            datos.get("datos"),
            {
                "honeypot": datos.get("honeypot", ""),
                "msTranscurridos": datos.get("msTranscurridos"),
                "msMinimos": 3000,
            },
        )

        if not resultado["valido"]:
            # Los rechazos anti-bot no se detallan.
            codigos = {e["codigo"] for e in resultado["errores"]}
            if codigos & {"honeypot", "demasiado_rapido"}:
                log.info("contacto rechazado (anti-bot) desde %s", cliente())
                return jsonify({"valido": False, "errores": [
                    {"campo": "formulario", "codigo": "rechazado"}]}), 400
            return jsonify({"valido": False, "errores": resultado["errores"]}), 400

        guardar(resultado["limpio"])
        log.info("contacto aceptado desde %s", cliente())
        return jsonify({"valido": True, "mensaje": "Mensaje recibido."})

    @app.post("/api/cabeceras")
    def analizar_cabeceras():
        datos = cuerpo_json()
        if datos is None:
            return jsonify({"error": "Petición inválida."}), 400

        if not limite_cabeceras.permitido(cliente()):
            return jsonify({"error": "Demasiadas consultas. Esperá un minuto."}), 429

        problema = verificar_csrf(datos)
        if problema:
            return jsonify({"error": "Origen o token no válido."}), 403

        try:
            estado, encabezados, url = red.descargar_cabeceras(datos.get("url"))
        except red.UrlRechazada as error:
            return jsonify({"error": str(error)}), 400

        informe = mod_cabeceras.analizar(encabezados)
        informe["url"] = url
        informe["estado_http"] = estado
        return jsonify(informe)

    @app.get("/admin/mensajes")
    def panel_mensajes():
        sin_autorizar = Response(status=401)
        sin_autorizar.headers["WWW-Authenticate"] = 'Basic realm="admin", charset="UTF-8"'

        if not app.config["ADMIN_CLAVE"]:
            return jsonify({"error": "Panel deshabilitado: falta ADMIN_CLAVE."}), 503
        if not limite_admin.permitido(cliente()):
            return jsonify({"error": "Demasiados intentos. Esperá unos minutos."}), 429
        if not admin_autorizado(request.headers.get("Authorization"),
                                 app.config["ADMIN_USUARIO"], app.config["ADMIN_CLAVE"]):
            return sin_autorizar

        lista = mod_mensajes.leer_mensajes(BUZON)
        return Response(mod_mensajes.renderizar_panel(lista), mimetype="text/html")

    return app


def guardar(limpio):
    """Se guarda como JSONL. json.dumps escapa el contenido, así que no hay
    forma de romper la estructura del archivo desde un campo del formulario."""
    BUZON.parent.mkdir(parents=True, exist_ok=True)
    registro = dict(limpio)
    registro["recibido"] = int(time.time())
    with open(BUZON, "a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(registro, ensure_ascii=False) + "\n")


app = crear_app()


class _SinCabeceraServer(WSGIRequestHandler):
    """Igual al manejador de Werkzeug, pero sin la cabecera Server.

    Auditoría 30/08/2026: `aplicar_cabeceras` ya intenta sacarla con
    `headers.pop("Server", None)`, pero esa cabecera no la pone el objeto
    Response de Flask, la agrega el propio servidor de desarrollo más abajo
    en la pila (BaseHTTPRequestHandler.send_response), así que ese pop()
    nunca la tocaba: quien mirara la respuesta seguía viendo la versión
    exacta de Werkzeug y Python corriendo del otro lado.
    """

    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())


if __name__ == "__main__":
    if not os.environ.get("CLAVE_SECRETA"):
        log.warning("CLAVE_SECRETA no definida: se usa una aleatoria y los "
                    "tokens se invalidan en cada reinicio.")
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PUERTO", "8000")),
        debug=False,
        request_handler=_SinCabeceraServer,
    )
