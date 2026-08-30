"""Defensas de red para el analizador de cabeceras.

Un analizador que descarga una URL que le pasa el usuario es un SSRF de manual:
el atacante escribe una URL y el servidor la pide desde adentro de la red. Este
módulo existe para que eso no pase, y está separado del resto justamente para
poder probarlo sin tocar la red.

Defensas, en orden:
  1. Sólo http y https. Nada de file:, gopher:, ftp:, data:.
  2. Sin credenciales embebidas ni puertos fuera de una lista corta.
  3. Resolución DNS explícita y rechazo de toda IP que no sea pública
     (privada, loopback, enlace local, multicast, reservada).
  4. Conexión a la IP ya validada, no al nombre: sin esto, un DNS que devuelve
     distinto en la segunda consulta evade el control (DNS rebinding).
  5. Sin seguir redirecciones: una redirección a 127.0.0.1 anula todo lo anterior.
  6. Tiempo máximo (conexión, DNS y respuesta) y tamaño máximo de respuesta.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as TimeoutFuturo
from urllib.parse import urlsplit

ESQUEMAS = ("http", "https")
PUERTOS = (80, 443, 8000, 8080, 8443)
TIEMPO_LIMITE = 5.0
TAMANO_MAXIMO = 256 * 1024
LARGO_MAXIMO_URL = 2048


class UrlRechazada(Exception):
    """La URL no pasó los controles. El mensaje es apto para mostrar al usuario."""


def _resolver(host):
    try:
        info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UrlRechazada("No se pudo resolver el nombre del host.")
    return [dato[4][0] for dato in info]


def _con_tiempo_limite(funcion, *args, tiempo_limite=TIEMPO_LIMITE):
    """Corre `funcion` en otro hilo y corta a los `tiempo_limite` segundos.

    Auditoría 30/08/2026: socket.getaddrinfo no tiene forma de pasarle un
    timeout. Un dominio cuyo servidor DNS autoritativo no responde (atacante
    que controla su propio dominio, a propósito) cuelga la resolución sin
    límite, y como el resto del pedido corre en un hilo del pool de Flask,
    eso deja hilos bloqueados que se van acumulando con el tiempo. Python no
    puede matar un hilo desde afuera, así que esto no libera el hilo colgado:
    lo que hace es dejar de esperarlo, para que ESTE pedido no se cuelgue más
    de lo que ya se cuelga el resto de la conexión (ver TIEMPO_LIMITE).
    """
    ejecutor = ThreadPoolExecutor(max_workers=1)
    futuro = ejecutor.submit(funcion, *args)
    try:
        return futuro.result(timeout=tiempo_limite)
    except TimeoutFuturo:
        raise UrlRechazada("La resolución del nombre tardó demasiado.")
    finally:
        ejecutor.shutdown(wait=False)


def ip_es_publica(texto_ip):
    """True sólo si la IP es enrutable en internet."""
    try:
        ip = ipaddress.ip_address(texto_ip)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validar_url(url, resolver=None):
    """Valida y devuelve (url_normalizada, host, puerto, ip).

    `resolver` se inyecta para poder probar sin DNS real.
    """
    resolver = resolver or _resolver

    if not isinstance(url, str) or not url.strip():
        raise UrlRechazada("Falta la dirección.")
    url = url.strip()
    if len(url) > LARGO_MAXIMO_URL:
        raise UrlRechazada("La dirección es demasiado larga.")

    partes = urlsplit(url)

    if partes.scheme.lower() not in ESQUEMAS:
        raise UrlRechazada("Sólo se aceptan direcciones http o https.")
    if partes.username or partes.password:
        raise UrlRechazada("No se aceptan credenciales en la dirección.")
    if not partes.hostname:
        raise UrlRechazada("Falta el nombre del host.")

    puerto = partes.port or (443 if partes.scheme.lower() == "https" else 80)
    if puerto not in PUERTOS:
        raise UrlRechazada("Puerto no permitido.")

    host = partes.hostname

    # Si el host ya es una IP, se valida directo sin pasar por DNS.
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        ips = _con_tiempo_limite(resolver, host)

    if not ips:
        raise UrlRechazada("No se pudo resolver el nombre del host.")

    # TODAS las direcciones tienen que ser públicas: alcanza con una interna
    # para que el nombre sirva de puente hacia adentro.
    for ip in ips:
        if not ip_es_publica(ip):
            raise UrlRechazada("La dirección apunta a una red interna.")

    return url, host, puerto, ips[0]


def _contexto_tls():
    import ssl
    return ssl.create_default_context()


def abrir_conexion(esquema, ip, puerto, host, tiempo_limite=TIEMPO_LIMITE):
    """Devuelve una conexión HTTP(S) apuntada a `ip`, presentando `host`.

    El socket se arma a mano a propósito. HTTPSConnection resuelve `self.host`
    dentro de connect(), así que asignarle el nombre para el SNI hace que
    vuelva a consultar DNS y anula la validación de IP: entre la comprobación
    y la conexión, el atacante cambia el registro y entra igual.
    """
    import http.client
    import socket as mod_socket

    sock = mod_socket.create_connection((ip, puerto), tiempo_limite)

    if esquema.lower() == "https":
        sock = _contexto_tls().wrap_socket(sock, server_hostname=host)
        conexion = http.client.HTTPSConnection(host, puerto, timeout=tiempo_limite)
    else:
        conexion = http.client.HTTPConnection(host, puerto, timeout=tiempo_limite)

    # Con el socket ya puesto, request() no llama a connect() y no re-resuelve.
    conexion.sock = sock
    return conexion


def descargar_cabeceras(url, resolver=None, abridor=None):
    """Pide la URL y devuelve (estado, cabeceras, url_final).

    Conecta contra la IP validada y NO sigue redirecciones: una redirección a
    127.0.0.1 anularía todos los controles anteriores.
    """
    import http.client

    url, host, puerto, ip = validar_url(url, resolver=resolver)
    partes = urlsplit(url)
    ruta = partes.path or "/"
    if partes.query:
        ruta += "?" + partes.query

    if abridor is not None:
        return abridor(partes.scheme, ip, puerto, host, ruta)

    conexion = None
    try:
        conexion = abrir_conexion(partes.scheme, ip, puerto, host)
        conexion.request("GET", ruta, headers={
            "Host": host,
            "User-Agent": "auditor-cabeceras/1.0",
            "Accept": "text/html,*/*;q=0.5",
        })
        respuesta = conexion.getresponse()
        respuesta.read(TAMANO_MAXIMO)
        cabeceras = {k.lower(): v for k, v in respuesta.getheaders()}
        return respuesta.status, cabeceras, url
    except (OSError, http.client.HTTPException) as error:
        raise UrlRechazada("No se pudo conectar: %s" % type(error).__name__)
    finally:
        if conexion is not None:
            conexion.close()
