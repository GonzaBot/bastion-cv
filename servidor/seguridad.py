"""Controles transversales del servidor.

Acá viven las cosas que el documento HTML no puede resolver por sí solo y que
en la auditoría anterior quedaron pendientes: cabeceras HTTP reales, límite de
tasa, verificación de origen y token anti-CSRF.
"""

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import time
from collections import deque
from hashlib import sha256

# ── Cabeceras de respuesta ──────────────────────────────────────────────

CABECERAS_SEGURIDAD_FIJAS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    # Bloquea los viejos crossdomain.xml de Flash/Acrobat: nadie los sirve
    # acá, pero tampoco cuesta nada decirlo explícito.
    "X-Permitted-Cross-Domain-Policies": "none",
}

_ETIQUETA_STYLE = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)


def hash_css(html_o_fragmento):
    """Hash CSP ('sha256-BASE64') del primer <style> encontrado en el texto.

    Auditoría 30/08/2026: `style-src 'unsafe-inline'` le abre la puerta a
    CUALQUIER estilo inyectado, no sólo al bloque legítimo. Como las páginas
    de este sitio son estáticas (nada de Jinja ni nonce por pedido), la forma
    de sacar 'unsafe-inline' sin romper esa filosofía es fijar por hash el
    contenido exacto de cada <style> ya conocido. Si alguien edita el CSS sin
    recalcular el hash en construir_csp(), el navegador bloquea ESE bloque:
    la falla es visible (estilos rotos), nunca un permiso silenciosamente
    abierto de más.
    """
    coincidencia = _ETIQUETA_STYLE.search(html_o_fragmento)
    if not coincidencia:
        return None
    digesto = hashlib.sha256(coincidencia.group(1).encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digesto).decode("ascii")


def construir_csp(hashes_estilo=()):
    fuentes_estilo = " ".join("'%s'" % h for h in hashes_estilo if h)
    return (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'%s; "
        "img-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    ) % ((" " + fuentes_estilo) if fuentes_estilo else "")


def aplicar_cabeceras(respuesta, https=False, csp=None):
    for clave, valor in CABECERAS_SEGURIDAD_FIJAS.items():
        respuesta.headers[clave] = valor
    respuesta.headers["Content-Security-Policy"] = csp or construir_csp()
    # HSTS sólo tiene sentido sobre HTTPS. Mandarlo por HTTP no hace nada y
    # en desarrollo local puede dejarte el navegador clavado en https.
    if https:
        respuesta.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    respuesta.headers.pop("Server", None)
    return respuesta


# ── Token anti-CSRF (doble envío firmado) ───────────────────────────────

class Tokens:
    """Token firmado con HMAC y vencimiento. Sin estado de servidor: el token
    lleva su propia fecha y su firma, así que sobrevive a un reinicio y no
    necesita sesión ni base de datos."""

    def __init__(self, clave=None, vigencia=3600):
        self.clave = clave or os.environ.get("CLAVE_SECRETA") or secrets.token_bytes(32)
        if isinstance(self.clave, str):
            self.clave = self.clave.encode("utf-8")
        self.vigencia = vigencia

    def emitir(self, ahora=None):
        ahora = int(ahora if ahora is not None else time.time())
        azar = secrets.token_hex(16)
        cuerpo = "%d.%s" % (ahora, azar)
        firma = hmac.new(self.clave, cuerpo.encode("utf-8"), sha256).hexdigest()
        return "%s.%s" % (cuerpo, firma)

    def es_valido(self, token, ahora=None):
        if not isinstance(token, str):
            return False
        partes = token.split(".")
        if len(partes) != 3:
            return False
        marca, azar, firma = partes
        cuerpo = "%s.%s" % (marca, azar)
        esperada = hmac.new(self.clave, cuerpo.encode("utf-8"), sha256).hexdigest()
        # compare_digest: comparación en tiempo constante, para no filtrar la
        # firma correcta midiendo cuánto tarda en fallar.
        if not hmac.compare_digest(esperada, firma):
            return False
        try:
            emitido = int(marca)
        except ValueError:
            return False
        ahora = int(ahora if ahora is not None else time.time())
        if ahora < emitido - 60:
            return False
        return (ahora - emitido) <= self.vigencia


# ── Límite de tasa ──────────────────────────────────────────────────────

class LimiteDeTasa:
    """Ventana deslizante en memoria, con memoria acotada.

    Sin poda, cada IP nueva deja una entrada para siempre y el propio límite
    de tasa se vuelve un vector de agotamiento de memoria: basta rotar la IP
    de origen para hacer crecer el diccionario sin techo.

    LIMITACIÓN CONOCIDA: el estado vive en el proceso. Con varios workers de
    gunicorn cada uno lleva su cuenta, y un reinicio borra todo. Para una sola
    instancia en tu Debian alcanza; para producción real va Redis.
    """

    def __init__(self, maximo=5, ventana=60, reloj=time.time, maximo_claves=10000):
        self.maximo = maximo
        self.ventana = ventana
        self.reloj = reloj
        self.maximo_claves = maximo_claves
        self._registros = {}

    def _podar(self, ahora):
        """Descarta primero las claves vencidas.

        Si aun así se pasa del techo, se desaloja por CANTIDAD DE INTENTOS
        ascendente, no por antigüedad. La intuición de quedarse con los más
        recientes es exactamente al revés: el que está bloqueado tiene la cola
        llena y hace rato que no suma, así que sería el primero en caer — y
        desalojarlo le regala la cuota de nuevo. Se conserva a quien está más
        cerca del límite, que es a quien hay que seguir frenando.
        """
        vencidas = [k for k, cola in self._registros.items()
                    if not cola or ahora - cola[-1] > self.ventana]
        for k in vencidas:
            del self._registros[k]

        techo = max(1, self.maximo_claves - 1)
        if len(self._registros) > techo:
            ordenadas = sorted(
                self._registros.items(),
                key=lambda par: (len(par[1]), par[1][-1]),
                reverse=True,
            )
            self._registros = dict(ordenadas[:techo])

    def permitido(self, clave):
        ahora = self.reloj()

        if len(self._registros) >= self.maximo_claves:
            self._podar(ahora)

        cola = self._registros.setdefault(clave, deque())
        while cola and ahora - cola[0] > self.ventana:
            cola.popleft()
        if len(cola) >= self.maximo:
            return False
        cola.append(ahora)
        return True

    def restantes(self, clave):
        cola = self._registros.get(clave, deque())
        return max(0, self.maximo - len(cola))


class LimiteDoble:
    """LimiteDeTasa por IP + un techo global, para que rotar de IP no sirva.

    Confirmado en auditoría (30/08/2026): todo el bloque 127.0.0.0/8 es
    loopback en Linux sin ningún privilegio (`curl --interface 127.0.0.5`
    alcanza), así que un límite que sólo cuenta por IP se evade mandando cada
    pedido desde una dirección de loopback distinta. El techo global no
    distingue quién pide, así que no hay IP que rotar para esquivarlo.

    Los dos límites se consultan SIEMPRE, incluso si el de IP ya rechazó: si
    el global sólo contara pedidos que pasaron el de IP, alguien rotando IPs
    nunca gastaría cupo global y el bypass seguiría intacto.
    """

    def __init__(self, maximo_por_ip, ventana_por_ip, maximo_global, ventana_global,
                 reloj=time.time, maximo_claves=10000):
        self._por_ip = LimiteDeTasa(maximo=maximo_por_ip, ventana=ventana_por_ip,
                                     reloj=reloj, maximo_claves=maximo_claves)
        self._global = LimiteDeTasa(maximo=maximo_global, ventana=ventana_global,
                                     reloj=reloj, maximo_claves=1)

    def permitido(self, clave):
        ok_ip = self._por_ip.permitido(clave)
        ok_global = self._global.permitido("*")
        return ok_ip and ok_global


# ── Autenticación del panel de administración ───────────────────────────

def admin_autorizado(cabecera_autorizacion, usuario_esperado, clave_esperada):
    """Basic Auth manual, sin sesión ni cookie: cada pedido se autentica de
    nuevo y el navegador hace todo el trabajo con su propio diálogo nativo.

    Si no hay clave configurada el panel queda cerrado siempre, en vez de
    caer a una comparación contra cadena vacía que cualquiera pasaría.
    """
    if not clave_esperada:
        return False
    if not cabecera_autorizacion or not cabecera_autorizacion.startswith("Basic "):
        return False
    try:
        decodificado = base64.b64decode(cabecera_autorizacion[6:]).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    usuario, _, clave = decodificado.partition(":")
    # comparación en tiempo constante en ambos campos, no sólo en la clave.
    usuario_ok = hmac.compare_digest(usuario, usuario_esperado)
    clave_ok = hmac.compare_digest(clave, clave_esperada)
    return usuario_ok and clave_ok


# ── Verificación de origen ──────────────────────────────────────────────

def origen_permitido(origen, referente, permitidos):
    """Defensa en profundidad junto al token. Si no viene ninguna de las dos
    cabeceras se rechaza: un navegador moderno manda al menos una en un POST
    de otro origen, y no mandar nada es más propio de un cliente automatizado."""
    if origen:
        return origen in permitidos
    if referente:
        for permitido in permitidos:
            if referente.startswith(permitido + "/") or referente == permitido:
                return True
        return False
    return False
