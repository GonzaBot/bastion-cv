# Informe de seguridad — cv-gonza

**Fecha:** 30/08/2026
**Alcance:** la app completa corriendo en Docker (`http://127.0.0.1:8000` y `http://192.168.1.9:8000`) — estático, formulario de contacto, analizador de cabeceras, generador de contraseñas y panel de administración (`/admin/mensajes`).
**Tipo de trabajo:** pentest de caja blanca contra la app viva (no sólo lectura de código) + revisión de código donde el ataque en vivo no alcanzaba a probar algo (DNS que cuelga).
**Resultado:** 3 hallazgos reales, ya corregidos y verificados. El resto de la superficie de ataque aguantó todo lo que se le tiró.

---

## 1. Resumen ejecutivo

| # | Hallazgo | Severidad | Estado |
|---|----------|-----------|--------|
| 1 | Límite de tasa evadible rotando IP de loopback | 🟠 Media | ✅ Corregido |
| 2 | Resolución DNS sin timeout (DoS lento) | 🟠 Media-Alta | ✅ Corregido |
| 3 | Cabecera `Server` filtraba versión de Werkzeug/Python | 🟡 Baja | ✅ Corregido |
| — | Anti-bot (honeypot + tiempo) evadible por script | 🟢 Informativo | Ya documentado en README, sin cambios (ver §5) |
| — | `/api/token` sin límite de tasa | 🟢 Informativo | No se tocó, impacto despreciable (ver §5) |

Defensas que se probaron a fondo y **aguantaron**: SSRF (IPv6 mapeada, IPs en decimal/hex/octal, DNS rebinding), CSRF vía Basic Auth cacheado (bloqueado por `Cross-Origin-Resource-Policy`), XSS en el panel de mensajes y en el analizador de cabeceras, path traversal, generador de contraseñas (RNG), fuzzing del header `Authorization`, JSON con anidamiento extremo.

---

## 2. Metodología y herramientas

Todo el trabajo fue contra la app **corriendo de verdad** (contenedor Docker en `127.0.0.1:8000`, más una instancia aislada de Flask sin Docker en `127.0.0.1:8001` para descartar que el NAT de Docker enmascarara algún resultado).

| Herramienta | Para qué |
|---|---|
| `curl` | Toda la explotación HTTP: forjar tokens, cabeceras, `--interface` para rotar IP de origen |
| Scripts Python ad-hoc (`servidor.red`, `servidor.seguridad` importados directo) | Inyección de dependencias (`resolver=`) para probar SSRF y el timeout de DNS sin tocar la red real |
| Node.js + Playwright (Chromium real) | PoC de CSRF vía Basic Auth cacheado, embebiendo `/admin/mensajes` desde una página de otro origen |
| `docker compose logs` | Confirmar qué IP ve realmente el proceso Flask detrás del NAT de Docker |
| pytest (suite propia del repo + tests nuevos) | Regresión automatizada de cada arreglo |
| Lectura de `werkzeug/serving.py` y `flask/app.py` instalados en el venv | Entender por qué el `Server` header no se iba y por qué el dev server no se bloqueaba con un solo hilo (spoiler: `threaded=True` es el default de Flask desde la 1.0, no lo que decía la firma de `run_simple`) |

---

## 3. Hallazgos, con evidencia

### 🟠 Hallazgo 1 — El límite de tasa se evade rotando IP de loopback

**Dónde:** `servidor/seguridad.py`, clase `LimiteDeTasa`, usada por `/api/contacto`, `/api/cabeceras` y `/admin/mensajes`.

**Causa:** los tres limitadores cuentan intentos por `request.remote_addr` únicamente. Todo el bloque `127.0.0.0/8` es loopback en Linux — cualquier proceso, sin root ni configuración de red, puede originar tráfico desde `127.0.0.2`, `127.0.0.3`, etc.

**Cómo lo probé** (contra la instancia sin Docker en el puerto 8001, para que el hairpin NAT de Docker no ocultara el efecto — ver nota en §5):

```bash
# 1. Agoto el límite normal (5 pedidos / 300s) desde 127.0.0.1
for i in 1 2 3 4 5; do
  T=$(curl -s http://127.0.0.1:8001/api/token | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
  curl -s -o /dev/null -w "  intento $i -> %{http_code}\n" -X POST http://127.0.0.1:8001/api/contacto \
    -H "Content-Type: application/json" -H "Origin: http://127.0.0.1:8001" \
    -d "{\"token\":\"$T\",\"datos\":{\"nombre\":\"x\"},\"honeypot\":\"bot\"}"
done
# 6to intento -> 429 (correcto, el límite funciona... para ESA ip)

# 2. Repito rotando por 127.0.0.30 .. 127.0.0.34 (una IP distinta por pedido)
for i in 30 31 32 33 34; do
  ip="127.0.0.$i"
  T=$(curl -s --interface "$ip" http://127.0.0.1:8001/api/token | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
  curl -s --interface "$ip" -o /dev/null -w "  $ip -> %{http_code}\n" -X POST http://127.0.0.1:8001/api/contacto \
    -H "Content-Type: application/json" -H "Origin: http://127.0.0.1:8001" \
    -d "{\"token\":\"$T\",\"datos\":{\"nombre\":\"x\"},\"honeypot\":\"bot\"}"
done
```

**Resultado antes del arreglo:**
```
intento 1 -> 400   intento 2 -> 400   intento 3 -> 400   intento 4 -> 400   intento 5 -> 400
(6to intento, sin rotar IP) -> 429

127.0.0.30 -> 400   127.0.0.31 -> 400   127.0.0.32 -> 400   127.0.0.33 -> 400   127.0.0.34 -> 400
```
Los 5 pedidos "rotados" pasaron como si nada — el límite de 5/300s quedó completamente evadido.

**Impacto:** cualquiera con acceso local a la máquina (o, en teoría, un atacante en la misma LAN con varias direcciones IPv6 propias asignadas a su tarjeta de red) puede mandar mensajes de contacto o consultas SSRF sin ningún techo real. En el despliegue actual de Docker el impacto práctico es bajo porque el NAT "hairpin" de Docker colapsa todo el tráfico que sale del propio host a una sola IP (`172.18.0.1`) — lo confirmé mirando `docker compose logs`. Pero el propio README recomienda correr la app sin Docker (`python3 -m servidor.app`) en Debian, y ahí el bypass es 100% real.

**Arreglo aplicado:** clase nueva `LimiteDoble` en `servidor/seguridad.py` — combina el límite por IP de siempre con un **techo global** que no distingue quién pide, así que no hay IP que rotar para esquivarlo. Los tres limitadores de `servidor/app.py` (`limite_contacto`, `limite_cabeceras`, `limite_admin`) ahora son `LimiteDoble` en vez de `LimiteDeTasa` a secas.

```python
class LimiteDoble:
    def __init__(self, maximo_por_ip, ventana_por_ip, maximo_global, ventana_global, ...):
        self._por_ip = LimiteDeTasa(maximo=maximo_por_ip, ventana=ventana_por_ip, ...)
        self._global = LimiteDeTasa(maximo=maximo_global, ventana=ventana_global, maximo_claves=1)

    def permitido(self, clave):
        ok_ip = self._por_ip.permitido(clave)      # los dos se consultan SIEMPRE, aunque
        ok_global = self._global.permitido("*")     # el de IP ya haya rechazado — si no,
        return ok_ip and ok_global                  # rotar IP nunca gastaría cupo global
```

Techos elegidos: contacto 5/IP-300s + 40 global/300s; cabeceras 10/IP-60s + 40 global/60s; admin 20/IP-300s + 60 global/300s (deja margen para tráfico legítimo de varios visitantes reales sin abrir la puerta a la rotación).

**Verificación post-arreglo** (mismo ataque, mismo servidor con el código nuevo):

```
== Agotando limite_contacto (5/300s) desde 127.0.0.1 ==
  intento 1 -> 400   intento 2 -> 400   intento 3 -> 400   intento 4 -> 400   intento 5 -> 400

== Rotando por 127.0.0.2 .. 127.0.0.41 (40 IPs distintas) ==
Resultado: 35 permitidos, 5 bloqueados con 429
```
El techo global (40/300s) ya tenía 5 consumidos por la primera tanda, así que de los 40 intentos rotados dejó pasar 35 y cortó los últimos 5 — exactamente lo esperado. Antes del arreglo: **40 de 40 permitidos, 0 bloqueados.**

Tests de regresión: `tests/test_api.py::test_limite_doble_bloquea_aunque_cada_ip_rote` y dos más.

---

### 🟠 Hallazgo 2 — La resolución DNS del analizador de cabeceras no tiene timeout

**Dónde:** `servidor/red.py`, función `_resolver` (llama a `socket.getaddrinfo`), usada por `validar_url`.

**Causa:** `TIEMPO_LIMITE = 5.0` se aplica a la conexión TCP y a la lectura de la respuesta HTTP (`abrir_conexion`, `respuesta.read`), pero `socket.getaddrinfo` **no acepta un parámetro de timeout** en absoluto. Un dominio cuyo servidor DNS autoritativo simplemente no responde (algo que el dueño de cualquier dominio puede configurar a propósito) cuelga la resolución sin límite.

**Cómo lo probé** (inyección de dependencias, sin tocar la red real — el mismo patrón que ya usa `tests/test_red.py`):

```python
import time, threading
from servidor import red

def resolver_que_cuelga(host):
    time.sleep(9999)  # simula un DNS autoritativo que nunca responde

hilo = threading.Thread(
    target=lambda: red.validar_url("http://dominio-malicioso.com/", resolver=resolver_que_cuelga),
    daemon=True)
hilo.start()
hilo.join(timeout=6)  # más que TIEMPO_LIMITE=5.0
print("¿sigue colgado tras 6s?", hilo.is_alive())
```

**Resultado antes del arreglo:**
```
TIEMPO_LIMITE configurado para conexión HTTP: 5.0s
¿El hilo terminó dentro de 6s (>TIEMPO_LIMITE)? NO seguía colgado
CONFIRMADO: la resolución DNS no tiene ningún timeout aplicado por el código.
```

**Por qué importa:** confirmé leyendo el código fuente de Flask (`flask/app.py`, método `Flask.run`) que `threaded=True` es el default desde Flask 1.0 — lo probé en vivo con un endpoint que hace `time.sleep(5)` y otro instantáneo, ambos respondiendo en paralelo sin bloquearse entre sí. Eso significa que la app **sí** atiende pedidos en paralelo (bien), pero también que cada pedido "colgado" se lleva un hilo del sistema que Python no puede matar desde afuera. El limitador de tasa (aun con el arreglo del Hallazgo 1) sólo frena la **tasa de admisión**, no cuántos pedidos hay **en vuelo** al mismo tiempo. Un atacante que manda su cupo permitido de pedidos hacia un dominio con DNS que nunca responde, sostenido en el tiempo, va acumulando hilos bloqueados para siempre — un DoS lento por agotamiento de hilos/memoria.

**Arreglo aplicado:** función nueva `_con_tiempo_limite` en `servidor/red.py`, que corre el resolver en un hilo aparte con `concurrent.futures.ThreadPoolExecutor` y corta a los `TIEMPO_LIMITE` segundos:

```python
def _con_tiempo_limite(funcion, *args, tiempo_limite=TIEMPO_LIMITE):
    ejecutor = ThreadPoolExecutor(max_workers=1)
    futuro = ejecutor.submit(funcion, *args)
    try:
        return futuro.result(timeout=tiempo_limite)
    except TimeoutFuturo:
        raise UrlRechazada("La resolución del nombre tardó demasiado.")
    finally:
        ejecutor.shutdown(wait=False)  # no espera al hilo colgado, sólo deja de bloquear ESTE pedido
```

Usada en `validar_url`: `ips = _con_tiempo_limite(resolver, host)` en vez de `ips = resolver(host)`.

**Honestidad sobre el alcance del arreglo:** Python no puede matar un hilo desde afuera, así que esto no libera el hilo colgado — lo que hace es que **este pedido puntual** deje de esperarlo indefinidamente, acotándolo a los mismos 5 segundos que ya se banca el resto del flujo. Sigue siendo cierto que un atacante muy sostenido en el tiempo puede ir dejando hilos huérfanos atrás; combinado con el techo global del Hallazgo 1, el ritmo al que eso puede pasar ahora está acotado.

**Verificación post-arreglo:**
```
$ python3 -m pytest -q tests/test_red.py -k dns
test_dns_que_cuelga_no_bloquea_para_siempre PASSED
test_dns_rapido_sigue_funcionando_con_el_wrapper_de_timeout PASSED
```
El primer test confirma que `validar_url` corta en menos de `TIEMPO_LIMITE + 2` segundos aunque el resolver inyectado duerma 30 segundos.

---

### 🟡 Hallazgo 3 — La cabecera `Server` filtraba la versión exacta de Werkzeug y Python

**Dónde:** el propio código en `servidor/seguridad.py` ya intentaba evitarlo (`respuesta.headers.pop("Server", None)` dentro de `aplicar_cabeceras`), pero no funcionaba.

**Por qué no funcionaba:** ese `pop()` actúa sobre el objeto `Response` de Flask. La cabecera `Server` **no la pone ese objeto** — la agrega el servidor de desarrollo de Werkzeug más abajo en la pila (`BaseHTTPRequestHandler.send_response`, heredado de la librería estándar de Python), después de que la respuesta de Flask ya se armó. El `pop()` nunca llegaba a tocarla.

**Evidencia:**
```bash
$ curl -sI http://127.0.0.1:8000/ | grep -i "^server:"
Server: Werkzeug/3.1.8 Python/3.12.14
```
Con eso, cualquiera que escanee el sitio sabe exactamente qué versión de Werkzeug y de Python buscar en su base de CVEs.

**Arreglo aplicado:** subclase de `WSGIRequestHandler` en `servidor/app.py` que sobreescribe `send_response` para no mandar esa cabecera:

```python
class _SinCabeceraServer(WSGIRequestHandler):
    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
```

Esto sólo se puede inyectar pasando `request_handler=` a `app.run()` — el comando `flask run` (que era el `CMD` del `Dockerfile`) no expone esa opción por CLI. Por eso también:
- Cambié el `Dockerfile` para arrancar con `python3 -m servidor.app` (mismo código que ya corría en desarrollo) en vez de `flask run`, agregando `ENV HOST=0.0.0.0` para que siga escuchando en todas las interfaces dentro del contenedor.
- Hice el host/puerto de `app.run()` configurables por entorno (`HOST`, `PUERTO`) para no tener que tocar el código entre desarrollo local (`127.0.0.1`) y Docker (`0.0.0.0`).

**Verificación post-arreglo** (contenedor reconstruido y corriendo):
```bash
$ curl -sI http://127.0.0.1:8000/ | grep -i server
(nada)
```

---

## 4. Lo que ataqué y **no** se rompió

Vale documentarlo porque también es trabajo de auditoría — y porque explica por qué el resto del informe es corto.

**SSRF (`servidor/red.py`, analizador de cabeceras).** Probé:
- IPv6 mapeada a IPv4 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254` — el clásico metadata endpoint de nube)
- IPv6 "compatible" con IPv4 (`::127.0.0.1`)
- IPs en decimal/hex/octal (`http://2130706433/`, `http://0x7f000001/`, `http://017700000001/`, `http://127.1/`)
- DNS rebinding (nombre público que resuelve a IP interna)

Todo rechazado. El diseño resiste porque valida la IP **ya resuelta**, no el texto de entrada, y el chequeo combina `is_private or is_loopback or is_reserved or ...` — eso atrapa casos donde una sola de esas propiedades no alcanza (ej. `::ffff:127.0.0.1` da `is_loopback=False` pero `is_private=True`).

**CSRF vía Basic Auth cacheado (`/admin/mensajes`).** Armé una página de "atacante" servida en otro origen (`http://127.0.0.1:9000`) con un `<img>` oculto apuntando a `/admin/mensajes`, usando Playwright con credenciales ya cargadas en el contexto del navegador (simulando que el dueño del sitio ya entró una vez). Chrome bloqueó el pedido en la red misma:
```
FALLÓ: http://127.0.0.1:8000/admin/mensajes { errorText: 'net::ERR_BLOCKED_BY_RESPONSE.NotSameOrigin' }
```
Gracias a `Cross-Origin-Resource-Policy: same-origin`, ya presente en toda respuesta de la app.

**XSS en contenido reflejado.**
- `servidor/mensajes.py` (el panel): probé guardar un mensaje de contacto con `nombre="<script>alert(1)</script>"`. En el panel salió como texto escapado (`&lt;script&gt;`), nunca ejecutado — cubierto además por un test (`test_panel_escapa_html_del_mensaje_guardado`).
- `web/js/herramientas.js` (analizador de cabeceras en el navegador): revisé cómo pinta la URL reflejada y los valores de cabecera de un sitio remoto (potencialmente hostil) — todo vía `.textContent`/`createElement`, nunca `innerHTML`. Ni analizando un sitio malicioso se puede inyectar HTML en la propia página.

**Generador de contraseñas.** Usa `crypto.getRandomValues`, nunca `Math.random`, y descarta valores fuera de rango para no introducir sesgo de módulo al mapear bytes aleatorios a un alfabeto que no es potencia de dos. Bien hecho.

**Path traversal / archivos fuera de `web/`.** `../../../etc/passwd`, `/.env`, `/docker-compose.yml`, `/Dockerfile`, `/servidor/app.py`, `/spec/casos.json` → 404 en todos los casos (protección nativa de `send_from_directory`, más el hecho de que esos archivos ni están dentro de `web/`).

**Fuzzing del header `Authorization`.** Basura binaria no-UTF8, 100KB de relleno (Werkzeug lo corta solo con 431 antes de llegar a la app), esquema `Digest` en vez de `Basic` — todo devuelve 401/431 limpio, sin trazas ni crashes.

**JSON con anidamiento extremo** (5000 niveles de profundidad, ~35KB): parseado sin errores ni demoras (0.0026s) — el límite de 64KB de cuerpo de petición además acota cuánto puede crecer esto en la práctica, y el `except Exception` genérico en `cuerpo_json()` cubriría igual un `RecursionError` si llegara a pasar.

---

## 5. Cosas que quedaron anotadas pero sin tocar (a propósito)

**El anti-bot (honeypot + tiempo mínimo) lo evade cualquier script.** Lo demostré en vivo:
```bash
curl -X POST .../api/contacto -d '{"honeypot":"","msTranscurridos":99999999, "datos":{...}}'
# -> {"valido": true, "mensaje": "Mensaje recibido."}  (0.006s reales)
```
Un bot que sepa dejar el honeypot vacío y mentir el tiempo transcurrido pasa sin problema. **No es un bug nuevo:** el propio README ya lo documenta en "Limitaciones conocidas" ("el honeypot temporal usa el reloj del cliente, que el atacante controla. Filtra bots genéricos y nada más"). No lo toqué porque la defensa real contra contenido malicioso es la validación de servidor de cada campo, no el honeypot — agregar algo tipo CAPTCHA rompería la filosofía de "sin dependencias externas" del proyecto. Lo dejo mencionado acá para que quede registrado como parte de la auditoría.

**`/api/token` no tiene límite de tasa.** Mandé 30 pedidos seguidos en 0.13s sin ningún freno. No lo agregué porque emitir un token es una operación barata (un HMAC) que no consume ningún recurso que crezca sin límite, y el token por sí solo no habilita nada — igual hace falta pasar el chequeo de origen y, para las rutas que lo usan, el resto de la validación. Impacto: despreciable. Queda anotado por si en el futuro se agrega algo más costoso detrás de esa ruta.

**Nota operativa sobre Docker y las pruebas locales.** Mientras auditaba encontré que el NAT "hairpin" de Docker hace que **todo pedido que sale del propio host hacia `127.0.0.1:8000`** le llegue a Flask como si viniera de `172.18.0.1` (la puerta de enlace del bridge), sin importar qué IP de loopback se use en el origen. Confirmado mirando `docker compose logs`. Esto no es una falla — es *cómo funciona el NAT de Docker* — pero explica por qué probar el límite de tasa desde tu propia máquina contra `localhost:8000` comparte cupo con cualquier otra cosa que le pegue al contenedor desde el host. Pedidos de **otros** dispositivos de la LAN sí le llegan a Flask con su IP real (lo confirmé también), así que el límite de tasa por IP funciona correctamente para visitantes reales.

---

## 6. Archivos modificados

| Archivo | Qué cambió |
|---|---|
| `servidor/seguridad.py` | Clase nueva `LimiteDoble` (Hallazgo 1) |
| `servidor/app.py` | `LimiteDeTasa` → `LimiteDoble` en los tres limitadores; clase `_SinCabeceraServer` + `HOST`/`PUERTO` configurables (Hallazgo 3) |
| `servidor/red.py` | Función `_con_tiempo_limite`, usada en `validar_url` (Hallazgo 2) |
| `Dockerfile` | `CMD` cambiado de `flask run` a `python3 -m servidor.app`; `ENV HOST=0.0.0.0` (necesario para que el arreglo del Hallazgo 3 aplique dentro del contenedor) |
| `tests/test_api.py` | 3 tests nuevos para `LimiteDoble` |
| `tests/test_red.py` | 2 tests nuevos para el timeout de DNS |

**Suite completa tras los arreglos:** 147 tests de pytest + 149 pruebas de navegador (jsdom), todos verdes.

```
$ python3 -m pytest -q
147 passed in 8.90s

$ node herramientas/correr_pruebas_node.js
149 pruebas · 149 pasan · 0 fallan
```

Ningún cambio tocó `spec/casos.json`, `validacion.py` ni `validacion.js` — el contrato de validación compartido queda intacto.

---

## 7. Segunda pasada — endurecimiento adicional (30/08/2026)

Después de cerrar los tres hallazgos de arriba, se hizo una segunda revisión
con foco en preparar el repo para publicarse en GitHub bajo el nombre
`bastion-cv`. No son correcciones de bugs — son capas de defensa adicionales
sobre una app que ya estaba libre de los hallazgos anteriores.

| Cambio | Por qué |
|---|---|
| **CSP sin `unsafe-inline` en `style-src`** | Los tres `<style>` embebidos (`index.html`, `pruebas.html`, panel de admin) ahora entran por hash SHA-256 exacto, calculado en `servidor/app.py:_hashes_estilo()` a partir de los archivos reales en cada arranque — no un hash pegado a mano que se desincroniza. Verificado con Playwright contra las tres páginas: cero violaciones de CSP, estilos renderizando igual que antes. |
| **Cabecera `X-Permitted-Cross-Domain-Policies: none`** | Cierra el vector (viejo, pero gratis de cerrar) de los `crossdomain.xml` de Flash/Acrobat. |
| **Aviso de secreto débil al arrancar** | `CLAVE_SECRETA` y `ADMIN_CLAVE` ahora generan un `log.warning` si están configuradas pero son cortas (< 32 y < 12 caracteres respectivamente). No bloquea el arranque — sólo dejaba de haber ninguna señal de que una clave débil configurada por error pasaba desapercibida. |
| **`security.txt` (RFC 9116)** | En `web/.well-known/security.txt`, con contacto de ejemplo a reemplazar antes de publicar en un dominio real. |
| **Docker multi-stage** | `Dockerfile` separa build (pip + descarga de paquetes) de runtime: la imagen final no tiene pip, ni caché de descargas, ni herramientas de compilación — sólo el venv ya armado y el código. |
| **`HEALTHCHECK` en el contenedor** | Verificado en vivo: `docker compose ps` muestra `(healthy)` a los pocos segundos de levantar. |
| **`docker-compose.yml` endurecido** | `read_only: true` + `tmpfs: [/tmp]` (filesystem de solo lectura salvo el volumen de datos), `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `mem_limit: 256m`, `pids_limit: 128`. Probado en vivo: el contenedor arranca y responde igual con todo esto activado — nada dependía de escribir fuera de `datos/` o de una capacidad Linux de más. |
| **Dependencias fijadas a versión exacta** | `Flask==3.1.3`, `pytest==9.1.1` (antes `>=3.0,<4.0` y `>=8.0`) — una franja abierta deja que un `pip install` futuro traiga silenciosamente lo que sea que esté publicado ese día. |
| **`package.json` + `package-lock.json` versionados** | Antes `jsdom` se instalaba a mano con `npm install --no-save`, sin registro en el repo. Ahora es una dependencia de desarrollo declarada y con lockfile, para que el CI instale exactamente lo mismo cada vez. |
| **CI en GitHub Actions** (`.github/workflows/ci.yml`) | Tres jobs: pytest, la suite de navegador (jsdom sobre Node 20), y un `docker build` de control. Corre en cada push y pull request. |
| **Dependabot** (`.github/dependabot.yml`) | Vigila `pip`, `npm`, `docker` y las propias GitHub Actions, con PRs semanales de actualización. |
| **`LICENSE`** | Todos los derechos reservados — el código queda público para leer y evaluar, no para reusar sin permiso. |

**Verificación:** 151 tests de pytest (147 + 4 nuevos para el CSP por hash) y
149 pruebas de navegador, todos verdes. Contenedor reconstruido con el
Dockerfile multi-stage y el `docker-compose.yml` endurecido, confirmado
`(healthy)` y respondiendo con las tres páginas renderizando sin ninguna
violación de CSP.

