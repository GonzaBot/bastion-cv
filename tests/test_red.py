"""Pruebas de las defensas anti-SSRF.

No tocan la red: el resolvedor DNS se inyecta. Eso permite probar exactamente
los casos que en la vida real son difíciles de reproducir, como un dominio
público que resuelve a una dirección interna.
"""

import time

import pytest

from servidor import red


def resolver_fijo(ips):
    return lambda host: list(ips)


# ── Esquemas y forma de la URL ──────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://interno:70/",
    "ftp://interno/",
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert(1)",
])
def test_rechaza_esquemas_no_http(url):
    with pytest.raises(red.UrlRechazada):
        red.validar_url(url, resolver=resolver_fijo(["93.184.216.34"]))


def test_rechaza_credenciales_embebidas():
    with pytest.raises(red.UrlRechazada, match="credenciales"):
        red.validar_url("http://usuario:clave@ejemplo.com/",
                        resolver=resolver_fijo(["93.184.216.34"]))


def test_rechaza_puerto_no_permitido():
    with pytest.raises(red.UrlRechazada, match="Puerto"):
        red.validar_url("http://ejemplo.com:6379/",
                        resolver=resolver_fijo(["93.184.216.34"]))


def test_rechaza_url_vacia_o_no_texto():
    for entrada in [None, "", "   ", 42]:
        with pytest.raises(red.UrlRechazada):
            red.validar_url(entrada)


def test_rechaza_url_gigante():
    with pytest.raises(red.UrlRechazada, match="larga"):
        red.validar_url("http://ejemplo.com/" + "a" * 3000,
                        resolver=resolver_fijo(["93.184.216.34"]))


# ── Direcciones internas ────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1",        # loopback
    "0.0.0.0",          # sin especificar
    "10.0.0.5",         # privada A
    "172.16.3.9",       # privada B
    "192.168.1.1",      # privada C
    "169.254.169.254",  # metadatos de nube: el clásico
    "224.0.0.1",        # multicast
    "::1",              # loopback IPv6
    "fd00::1",          # única local IPv6
    "fe80::1",          # enlace local IPv6
])
def test_ip_interna_no_es_publica(ip):
    assert red.ip_es_publica(ip) is False


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2001:4860:4860::8888"])
def test_ip_publica(ip):
    assert red.ip_es_publica(ip) is True


@pytest.mark.parametrize("url", [
    "http://localhost:8000/",
    "http://127.0.0.1:8000/admin",
    "http://[::1]:8000/",
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.0.1:8080/",
])
def test_rechaza_destinos_internos(url):
    with pytest.raises(red.UrlRechazada, match="interna"):
        red.validar_url(url, resolver=resolver_fijo(["127.0.0.1"]))


def test_dominio_publico_que_resuelve_a_interna():
    """El caso que un filtro por texto no atrapa: el nombre parece externo
    pero el DNS devuelve una IP de la red interna."""
    with pytest.raises(red.UrlRechazada, match="interna"):
        red.validar_url("http://interno.ejemplo.com/",
                        resolver=resolver_fijo(["10.1.2.3"]))


def test_alcanza_con_una_ip_interna_entre_varias():
    """Si el nombre resuelve a varias direcciones y una es interna, se rechaza:
    de lo contrario el atacante gana la carrera con reintentar."""
    with pytest.raises(red.UrlRechazada, match="interna"):
        red.validar_url("http://mixto.ejemplo.com/",
                        resolver=resolver_fijo(["93.184.216.34", "127.0.0.1"]))


def test_dns_que_no_resuelve():
    def resolver_vacio(host):
        return []
    with pytest.raises(red.UrlRechazada):
        red.validar_url("http://inexistente.ejemplo/", resolver=resolver_vacio)


# ── Casos válidos ───────────────────────────────────────────────────────

def test_acepta_url_publica():
    url, host, puerto, ip = red.validar_url(
        "https://ejemplo.com/pagina", resolver=resolver_fijo(["93.184.216.34"]))
    assert host == "ejemplo.com"
    assert puerto == 443
    assert ip == "93.184.216.34"


def test_puerto_por_defecto_segun_esquema():
    assert red.validar_url("http://ejemplo.com/",
                           resolver=resolver_fijo(["8.8.8.8"]))[2] == 80
    assert red.validar_url("https://ejemplo.com/",
                           resolver=resolver_fijo(["8.8.8.8"]))[2] == 443


def test_no_sigue_redirecciones():
    """El abridor inyectado devuelve un 302 hacia loopback. La función tiene
    que devolver el 302 tal cual, sin ir a buscarlo."""
    visitas = []

    def abridor(esquema, ip, puerto, host, ruta):
        visitas.append(ip)
        return 302, {"location": "http://127.0.0.1:8000/admin"}, "http://ejemplo.com/"

    estado, cabeceras, _ = red.descargar_cabeceras(
        "http://ejemplo.com/", resolver=resolver_fijo(["93.184.216.34"]), abridor=abridor)
    assert estado == 302
    assert visitas == ["93.184.216.34"]


def test_conecta_a_la_ip_validada_no_al_nombre():
    """Contra DNS rebinding: la conexión usa la IP que ya se verificó."""
    usados = []

    def abridor(esquema, ip, puerto, host, ruta):
        usados.append((ip, host))
        return 200, {}, "http://ejemplo.com/"

    red.descargar_cabeceras("http://ejemplo.com/",
                            resolver=resolver_fijo(["93.184.216.34"]), abridor=abridor)
    assert usados == [("93.184.216.34", "ejemplo.com")]


# ── Conexión: se conecta a la IP, no al nombre ──────────────────────────

def test_https_conecta_al_socket_de_la_ip(monkeypatch):
    """Regresión. HTTPSConnection resuelve self.host en connect(); si se le
    asigna el nombre para el SNI, vuelve a consultar DNS y el control de IP
    queda anulado (DNS rebinding)."""
    import socket as mod_socket
    destinos = []

    class SocketFalso:
        def settimeout(self, *a): pass
        def close(self): pass

    class ContextoFalso:
        def wrap_socket(self, sock, server_hostname=None):
            destinos.append(("sni", server_hostname))
            return sock

    def create_connection_falsa(direccion, timeout=None, source_address=None):
        destinos.append(("tcp", direccion[0]))
        return SocketFalso()

    monkeypatch.setattr(mod_socket, "create_connection", create_connection_falsa)
    monkeypatch.setattr(red, "_contexto_tls", lambda: ContextoFalso())

    red.abrir_conexion("https", "93.184.216.34", 443, "ejemplo.com")

    assert ("tcp", "93.184.216.34") in destinos, "el TCP debe ir a la IP validada"
    assert ("sni", "ejemplo.com") in destinos, "el SNI debe llevar el nombre real"


# ── Timeout de resolución DNS ────────────────────────────────────────────

def test_dns_que_cuelga_no_bloquea_para_siempre():
    """Regresión (auditoría 30/08/2026). socket.getaddrinfo no acepta un
    timeout propio: un dominio cuyo servidor DNS no responde nunca colgaba
    la resolución sin límite, aunque la conexión HTTP sí tuviera TIEMPO_LIMITE."""
    def resolver_que_cuelga(host):
        time.sleep(30)
        return ["93.184.216.34"]

    inicio = time.time()
    with pytest.raises(red.UrlRechazada, match="tard"):
        red.validar_url("http://cuelga.ejemplo.com/", resolver=resolver_que_cuelga)
    transcurrido = time.time() - inicio

    assert transcurrido < red.TIEMPO_LIMITE + 2, (
        "validar_url no debería esperar más que TIEMPO_LIMITE por el DNS")


def test_dns_rapido_sigue_funcionando_con_el_wrapper_de_timeout():
    url, host, puerto, ip = red.validar_url(
        "https://ejemplo.com/", resolver=resolver_fijo(["93.184.216.34"]))
    assert ip == "93.184.216.34"
