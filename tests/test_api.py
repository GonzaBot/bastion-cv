"""Analizador de cabeceras, controles transversales y API."""

import base64
import json

import pytest

from servidor import cabeceras
from servidor.app import crear_app
from servidor.seguridad import (LimiteDeTasa, LimiteDoble, Tokens,
                                 admin_autorizado, construir_csp, hash_css,
                                 origen_permitido)

BUENAS = {
    "content-security-policy": "default-src 'none'; script-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


# ── Analizador ──────────────────────────────────────────────────────────

def test_sitio_sin_cabeceras_reprueba():
    informe = cabeceras.analizar({})
    assert informe["nota"] == "F"
    assert informe["puntaje"] < 40


def test_sitio_bien_configurado_saca_A():
    informe = cabeceras.analizar(BUENAS)
    assert informe["nota"] == "A"


def test_csp_con_unsafe_inline_no_cumple():
    malas = dict(BUENAS)
    malas["content-security-policy"] = "script-src 'self' 'unsafe-inline'"
    informe = cabeceras.analizar(malas)
    csp = [h for h in informe["hallazgos"] if h["cabecera"] == "Content-Security-Policy"][0]
    assert csp["cumple"] is False
    assert "unsafe-inline" in csp["detalle"]


def test_hsts_corto_no_cumple():
    malas = dict(BUENAS)
    malas["strict-transport-security"] = "max-age=300"
    informe = cabeceras.analizar(malas)
    hsts = [h for h in informe["hallazgos"] if h["cabecera"] == "Strict-Transport-Security"][0]
    assert hsts["cumple"] is False


def test_server_con_version_se_reporta():
    con_version = dict(BUENAS)
    con_version["server"] = "nginx/1.18.0"
    informe = cabeceras.analizar(con_version)
    srv = [h for h in informe["hallazgos"] if h["cabecera"] == "Server"][0]
    assert srv["cumple"] is False


def test_es_insensible_a_mayusculas_de_cabecera():
    mixtas = {k.upper(): v for k, v in BUENAS.items()}
    assert cabeceras.analizar(mixtas)["nota"] == "A"


def test_los_incumplimientos_van_primero():
    informe = cabeceras.analizar({"x-content-type-options": "nosniff"})
    assert informe["hallazgos"][0]["cumple"] is False


def test_analizar_tolera_none():
    """Sin cabeceras reprueba, pero no en cero: la ausencia de 'Server' es
    correcta por sí misma y suma."""
    informe = cabeceras.analizar(None)
    assert informe["nota"] == "F"
    assert informe["puntaje"] < 10


# ── Tokens ──────────────────────────────────────────────────────────────

def test_token_valido_recien_emitido():
    t = Tokens(clave=b"secreta")
    assert t.es_valido(t.emitir()) is True


def test_token_vencido():
    t = Tokens(clave=b"secreta", vigencia=10)
    token = t.emitir(ahora=1000)
    assert t.es_valido(token, ahora=1005) is True
    assert t.es_valido(token, ahora=1011) is False


def test_token_con_firma_alterada():
    t = Tokens(clave=b"secreta")
    token = t.emitir()
    cuerpo, firma = token.rsplit(".", 1)
    alterado = cuerpo + "." + ("0" * len(firma))
    assert t.es_valido(alterado) is False


def test_token_de_otra_clave_no_sirve():
    a, b = Tokens(clave=b"una"), Tokens(clave=b"otra")
    assert b.es_valido(a.emitir()) is False


@pytest.mark.parametrize("basura", [None, "", "abc", "1.2", 42, "a.b.c.d"])
def test_token_basura(basura):
    assert Tokens(clave=b"secreta").es_valido(basura) is False


def test_token_del_futuro_se_rechaza():
    t = Tokens(clave=b"secreta")
    assert t.es_valido(t.emitir(ahora=5000), ahora=1000) is False


# ── Autenticación del panel ──────────────────────────────────────────────

def _basic(usuario, clave):
    credencial = base64.b64encode(f"{usuario}:{clave}".encode()).decode()
    return f"Basic {credencial}"


def test_admin_autorizado_con_credenciales_correctas():
    assert admin_autorizado(_basic("gonza", "secreta"), "gonza", "secreta") is True


@pytest.mark.parametrize("cabecera,usuario,clave", [
    (None, "gonza", "secreta"),
    ("Bearer algo", "gonza", "secreta"),
    ("Basic no-es-base64!!", "gonza", "secreta"),
])
def test_admin_autorizado_rechaza_formatos_invalidos(cabecera, usuario, clave):
    assert admin_autorizado(cabecera, usuario, clave) is False


def test_admin_autorizado_rechaza_clave_incorrecta():
    assert admin_autorizado(_basic("gonza", "mala"), "gonza", "secreta") is False


def test_admin_autorizado_rechaza_usuario_incorrecto():
    assert admin_autorizado(_basic("otro", "secreta"), "gonza", "secreta") is False


def test_admin_autorizado_sin_clave_configurada_siempre_falso():
    """Sin ADMIN_CLAVE el panel se cierra, no cae a comparar contra ''."""
    assert admin_autorizado(_basic("gonza", ""), "gonza", "") is False


# ── Límite de tasa ──────────────────────────────────────────────────────

def test_limite_corta_al_superar_el_maximo():
    reloj = [1000.0]
    limite = LimiteDeTasa(maximo=3, ventana=60, reloj=lambda: reloj[0])
    assert [limite.permitido("ip") for _ in range(4)] == [True, True, True, False]


def test_la_ventana_se_desliza():
    reloj = [1000.0]
    limite = LimiteDeTasa(maximo=2, ventana=60, reloj=lambda: reloj[0])
    limite.permitido("ip"); limite.permitido("ip")
    assert limite.permitido("ip") is False
    reloj[0] += 61
    assert limite.permitido("ip") is True


def test_el_limite_es_por_clave():
    limite = LimiteDeTasa(maximo=1, ventana=60)
    assert limite.permitido("a") is True
    assert limite.permitido("b") is True
    assert limite.permitido("a") is False


# ── Origen ──────────────────────────────────────────────────────────────

def test_origen_permitido():
    ok = ["http://localhost:8000"]
    assert origen_permitido("http://localhost:8000", None, ok) is True
    assert origen_permitido("http://malicioso.com", None, ok) is False
    assert origen_permitido(None, "http://localhost:8000/pagina", ok) is True
    assert origen_permitido(None, "http://localhost:8000.malicioso.com/", ok) is False
    assert origen_permitido(None, None, ok) is False


# ── API ─────────────────────────────────────────────────────────────────

@pytest.fixture
def app(tmp_path, monkeypatch):
    import servidor.app as mod
    monkeypatch.setattr(mod, "BUZON", tmp_path / "mensajes.jsonl")
    aplicacion = crear_app({"ORIGENES": ["http://localhost:8000"], "TESTING": True})
    return aplicacion


@pytest.fixture
def cliente(app):
    return app.test_client()


def cabeceras_validas(app):
    token = app.extensions["tokens"].emitir()
    return token, {"Origin": "http://localhost:8000", "Content-Type": "application/json"}


DATOS_OK = {
    "nombre": "Gonza Rodríguez",
    "mail": "gonza@empresa.com.uy",
    "motivo": "Auditoría de red",
    "mensaje": "Necesito segmentar la red de planta del aserradero.",
}


def test_salud(cliente):
    assert cliente.get("/api/salud").get_json() == {"estado": "vivo"}


def test_cabeceras_de_seguridad_en_toda_respuesta(cliente):
    r = cliente.get("/api/salud")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert r.headers["X-Permitted-Cross-Domain-Policies"] == "none"


def test_csp_sin_unsafe_inline_en_style_src(cliente):
    """Regresión (auditoría 30/08/2026): el CSP tenía 'unsafe-inline' abierto
    para cualquier estilo. Ahora cada <style> conocido entra por su hash."""
    csp = cliente.get("/").headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "style-src 'self' 'sha256-" in csp


def test_hash_css_calcula_sha256_del_bloque_style():
    html = "<html><head><style>body{color:red}</style></head></html>"
    h = hash_css(html)
    assert h is not None and h.startswith("sha256-")


def test_hash_css_sin_style_devuelve_none():
    assert hash_css("<html><body>sin estilos</body></html>") is None


def test_construir_csp_sin_hashes_no_tiene_unsafe_inline():
    csp = construir_csp([])
    assert "'unsafe-inline'" not in csp
    assert "style-src 'self'" in csp


def test_hsts_solo_sobre_https(cliente):
    assert "Strict-Transport-Security" not in cliente.get("/api/salud").headers
    r = cliente.get("/api/salud", base_url="https://localhost:8000")
    assert "Strict-Transport-Security" in r.headers


def test_contacto_acepta_envio_valido(app, cliente):
    token, cab = cabeceras_validas(app)
    r = cliente.post("/api/contacto", headers=cab, json={
        "token": token, "datos": DATOS_OK, "honeypot": "", "msTranscurridos": 9000})
    assert r.status_code == 200
    assert r.get_json()["valido"] is True


def test_contacto_sin_token(app, cliente):
    _, cab = cabeceras_validas(app)
    r = cliente.post("/api/contacto", headers=cab, json={
        "datos": DATOS_OK, "msTranscurridos": 9000})
    assert r.status_code == 403


def test_contacto_desde_otro_origen(app, cliente):
    token, _ = cabeceras_validas(app)
    r = cliente.post("/api/contacto",
                     headers={"Origin": "http://malicioso.com", "Content-Type": "application/json"},
                     json={"token": token, "datos": DATOS_OK, "msTranscurridos": 9000})
    assert r.status_code == 403


def test_contacto_rechaza_datos_invalidos(app, cliente):
    token, cab = cabeceras_validas(app)
    malos = dict(DATOS_OK, mail="gonza@localhost")
    r = cliente.post("/api/contacto", headers=cab, json={
        "token": token, "datos": malos, "msTranscurridos": 9000})
    assert r.status_code == 400
    assert r.get_json()["errores"][0]["codigo"] == "correo_invalido"


def test_el_servidor_valida_aunque_el_cliente_no(app, cliente):
    """Lo central: un atacante que saltea el JS no gana nada."""
    token, cab = cabeceras_validas(app)
    inyectado = dict(DATOS_OK, motivo="Trabajo\nBcc: victima@mail.com")
    r = cliente.post("/api/contacto", headers=cab, json={
        "token": token, "datos": inyectado, "msTranscurridos": 9000})
    assert r.status_code == 400
    assert r.get_json()["errores"][0]["codigo"] == "inyeccion"


def test_honeypot_no_revela_el_motivo(app, cliente):
    token, cab = cabeceras_validas(app)
    r = cliente.post("/api/contacto", headers=cab, json={
        "token": token, "datos": DATOS_OK, "honeypot": "bot", "msTranscurridos": 9000})
    assert r.status_code == 400
    assert r.get_json()["errores"][0]["codigo"] == "rechazado"


def test_limite_de_tasa_en_contacto(app, cliente):
    codigos = []
    for _ in range(7):
        token, cab = cabeceras_validas(app)
        r = cliente.post("/api/contacto", headers=cab, json={
            "token": token, "datos": DATOS_OK, "msTranscurridos": 9000})
        codigos.append(r.status_code)
    assert 429 in codigos


def test_mensaje_valido_se_guarda(app, cliente, tmp_path):
    import servidor.app as mod
    token, cab = cabeceras_validas(app)
    cliente.post("/api/contacto", headers=cab, json={
        "token": token, "datos": DATOS_OK, "msTranscurridos": 9000})
    lineas = mod.BUZON.read_text(encoding="utf-8").strip().splitlines()
    assert json.loads(lineas[0])["mail"] == "gonza@empresa.com.uy"


def test_cabeceras_rechaza_url_interna(app, cliente):
    token, cab = cabeceras_validas(app)
    r = cliente.post("/api/cabeceras", headers=cab, json={
        "token": token, "url": "http://127.0.0.1:8000/"})
    assert r.status_code == 400
    assert "interna" in r.get_json()["error"]


def test_cabeceras_rechaza_esquema_file(app, cliente):
    token, cab = cabeceras_validas(app)
    r = cliente.post("/api/cabeceras", headers=cab, json={
        "token": token, "url": "file:///etc/passwd"})
    assert r.status_code == 400


def test_cuerpo_que_no_es_json(app, cliente):
    _, cab = cabeceras_validas(app)
    r = cliente.post("/api/contacto", headers={"Origin": "http://localhost:8000"},
                     data="no soy json")
    assert r.status_code == 400


# ── Límite de tasa: memoria acotada ─────────────────────────────────────

def test_el_limite_no_crece_sin_freno():
    """Regresión. Sin poda, cada IP nueva deja una entrada para siempre y
    el límite de tasa se convierte en un vector de agotamiento de memoria."""
    limite = LimiteDeTasa(maximo=5, ventana=60, maximo_claves=1000)
    for i in range(20000):
        limite.permitido("10.0.%d.%d" % (i // 256, i % 256))
    assert len(limite._registros) <= 1000


def test_la_poda_no_borra_a_quien_esta_activo():
    reloj = [1000.0]
    limite = LimiteDeTasa(maximo=2, ventana=60, maximo_claves=50, reloj=lambda: reloj[0])
    limite.permitido("activo"); limite.permitido("activo")
    for i in range(500):
        reloj[0] += 0.01
        limite.permitido("relleno-%d" % i)
    assert limite.permitido("activo") is False, "el atacante activo sigue bloqueado"


# ── Límite doble (IP + techo global) ─────────────────────────────────────

def test_limite_doble_respeta_el_limite_por_ip():
    limite = LimiteDoble(maximo_por_ip=2, ventana_por_ip=60,
                          maximo_global=1000, ventana_global=60)
    assert [limite.permitido("ip-a") for _ in range(3)] == [True, True, False]


def test_limite_doble_bloquea_aunque_cada_ip_rote():
    """Regresión (auditoría 30/08/2026): en vivo, agoté /api/contacto desde
    127.0.0.1 y seguí mandando pedidos válidos desde 127.0.0.2..127.0.0.34
    (curl --interface, sin ningún privilegio) y ninguno fue bloqueado, porque
    LimiteDeTasa sólo contaba por IP. El techo global tiene que frenar esto
    aunque cada IP nueva llegue fresca."""
    limite = LimiteDoble(maximo_por_ip=5, ventana_por_ip=300,
                          maximo_global=10, ventana_global=300)
    resultados = [limite.permitido("ip-%d" % i) for i in range(30)]
    assert resultados.count(True) == 10, "el techo global debe cortar en 10 pese a 30 IPs distintas"
    assert False in resultados[10:]


def test_limite_doble_no_penaliza_trafico_normal_de_varias_ips():
    """El techo global no debería molestar a un puñado de visitantes
    legítimos que por casualidad comparten ventana de tiempo."""
    limite = LimiteDoble(maximo_por_ip=5, ventana_por_ip=300,
                          maximo_global=40, ventana_global=300)
    for ip in ["visitante-1", "visitante-2", "visitante-3"]:
        assert limite.permitido(ip) is True


# ── Panel de mensajes ──────────────────────────────────────────────────

@pytest.fixture
def app_con_panel(tmp_path, monkeypatch):
    import servidor.app as mod
    monkeypatch.setattr(mod, "BUZON", tmp_path / "mensajes.jsonl")
    return crear_app({
        "ORIGENES": ["http://localhost:8000"],
        "TESTING": True,
        "ADMIN_USUARIO": "gonza",
        "ADMIN_CLAVE": "secreta",
    })


def test_panel_sin_credenciales_pide_basic_auth(app_con_panel):
    r = app_con_panel.test_client().get("/admin/mensajes")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Basic")


def test_panel_con_credenciales_malas_rechaza(app_con_panel):
    r = app_con_panel.test_client().get(
        "/admin/mensajes", headers={"Authorization": _basic("gonza", "mala")})
    assert r.status_code == 401


def test_panel_deshabilitado_sin_admin_clave():
    app = crear_app({"ORIGENES": ["http://localhost:8000"], "TESTING": True, "ADMIN_CLAVE": ""})
    r = app.test_client().get(
        "/admin/mensajes", headers={"Authorization": _basic("admin", "")})
    assert r.status_code == 503


def test_panel_vacio_con_credenciales_buenas(app_con_panel):
    r = app_con_panel.test_client().get(
        "/admin/mensajes", headers={"Authorization": _basic("gonza", "secreta")})
    assert r.status_code == 200
    assert "Todav" in r.get_data(as_text=True)


def test_panel_muestra_mensaje_guardado(app_con_panel):
    cliente = app_con_panel.test_client()
    token = app_con_panel.extensions["tokens"].emitir()
    cliente.post("/api/contacto",
                 headers={"Origin": "http://localhost:8000", "Content-Type": "application/json"},
                 json={"token": token, "datos": DATOS_OK, "msTranscurridos": 9000})

    r = cliente.get("/admin/mensajes", headers={"Authorization": _basic("gonza", "secreta")})
    cuerpo = r.get_data(as_text=True)
    assert "Gonza Rodríguez" in cuerpo
    assert "gonza@empresa.com.uy" in cuerpo


def test_panel_escapa_html_del_mensaje_guardado(app_con_panel):
    """Nada de lo que un visitante escribe debería ejecutarse como HTML acá:
    evaluar_formulario normaliza pero no escapa, así que el panel es el
    responsable de hacerlo antes de imprimir."""
    cliente = app_con_panel.test_client()
    token = app_con_panel.extensions["tokens"].emitir()
    inyectado = dict(DATOS_OK, nombre="<script>alert(1)</script>")
    cliente.post("/api/contacto",
                 headers={"Origin": "http://localhost:8000", "Content-Type": "application/json"},
                 json={"token": token, "datos": inyectado, "msTranscurridos": 9000})

    r = cliente.get("/admin/mensajes", headers={"Authorization": _basic("gonza", "secreta")})
    cuerpo = r.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in cuerpo
    assert "&lt;script&gt;" in cuerpo


def test_panel_ordena_mas_reciente_primero(app_con_panel, tmp_path):
    import servidor.app as mod
    mod.BUZON.parent.mkdir(parents=True, exist_ok=True)
    with open(mod.BUZON, "w", encoding="utf-8") as archivo:
        archivo.write(json.dumps({"nombre": "Viejo", "mail": "v@a.com",
                                   "motivo": "m", "mensaje": "m", "recibido": 1000}) + "\n")
        archivo.write(json.dumps({"nombre": "Nuevo", "mail": "n@a.com",
                                   "motivo": "m", "mensaje": "m", "recibido": 2000}) + "\n")

    r = app_con_panel.test_client().get(
        "/admin/mensajes", headers={"Authorization": _basic("gonza", "secreta")})
    cuerpo = r.get_data(as_text=True)
    assert cuerpo.index("Nuevo") < cuerpo.index("Viejo")


def test_panel_rate_limit(app_con_panel):
    cliente = app_con_panel.test_client()
    codigos = [cliente.get("/admin/mensajes",
                            headers={"Authorization": _basic("gonza", "mala")}).status_code
               for _ in range(25)]
    assert 429 in codigos
