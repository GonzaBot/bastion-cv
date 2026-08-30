# bastion-cv

[![Pruebas](https://github.com/TU-USUARIO/bastion-cv/actions/workflows/ci.yml/badge.svg)](https://github.com/TU-USUARIO/bastion-cv/actions/workflows/ci.yml)

> Reemplazar `TU-USUARIO` por el usuario real de GitHub antes de publicar,
> para que el badge apunte al workflow correcto.

Página personal con dos herramientas funcionando y un backend Flask que las
respalda. Todo el código es propio: sin frameworks de frontend, sin CDN, sin
dependencias JavaScript.

El nombre no es casualidad: un *bastion host* es, en seguridad, un servidor
a propósito expuesto a la red y endurecido para resistir el ataque. Esa es
la idea acá — un sitio personal auditado y defendido en capas, no sólo
"funcional". El informe completo de la auditoría, con comandos y evidencia
de cada ataque probado, está en [`INFORME_SEGURIDAD.md`](INFORME_SEGURIDAD.md).

## Arranque rápido en Debian

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export CLAVE_SECRETA="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m servidor.app
```

Abrir <http://127.0.0.1:8000>.

Sin `CLAVE_SECRETA` el servidor arranca igual pero genera una clave aleatoria,
así que los tokens anti-CSRF se invalidan en cada reinicio.

## Panel de mensajes

`GET /admin/mensajes` muestra los envíos del formulario de contacto, más
reciente primero. Sin `ADMIN_CLAVE` definida el panel responde 503 (cerrado,
no abierto). Con la clave puesta, pide usuario y clave por Basic Auth:

```bash
export ADMIN_CLAVE="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
```

Usar una clave que no se reutilice en ningún otro lado: Basic Auth la manda
codificada en base64, no cifrada, así que sobre HTTP plano cualquiera en la
misma red la lee con un capturador de paquetes. Sobre HTTPS (o dentro de una
VPN/red de confianza) no hay ese problema.

## Docker

```bash
cp .env.ejemplo .env
# editar .env: CLAVE_SECRETA y ADMIN_CLAVE con valores reales, no los de ejemplo
docker compose up -d --build
```

Con eso alcanza para probarlo en la red local (`http://<ip-de-la-máquina>:8000`).
El contenedor corre sin root, con el filesystem de solo lectura salvo
`./datos` (el buzón, montado como volumen), sin capacidades Linux de más
(`cap_drop: ALL`), sin poder escalar privilegios (`no-new-privileges`), y con
techo de memoria y de procesos. Ver [`Dockerfile`](Dockerfile) y
[`docker-compose.yml`](docker-compose.yml).

## Pruebas

```bash
make pruebas          # pytest + suite del navegador (necesita node y jsdom)
python3 -m pytest -q  # sólo Python
```

Para las del navegador sin Node, abrir <http://127.0.0.1:8000/pruebas.html>.

## Endurecimiento, de un vistazo

Cada punto de esta lista salió de auditar la app de verdad (atacándola en
vivo, no sólo leyendo el código) — el detalle completo, con el comando exacto
usado para probar cada uno, está en
[`INFORME_SEGURIDAD.md`](INFORME_SEGURIDAD.md).

| Capa | Qué hace |
|---|---|
| Cabeceras HTTP | CSP sin `unsafe-inline` en ningún lado (estilos por hash SHA-256, calculados del archivo real en el arranque), HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Cross-Origin-*-Policy`, `X-Permitted-Cross-Domain-Policies`, sin cabecera `Server` |
| Anti-CSRF | Token HMAC con vencimiento + verificación de `Origin`/`Referer` en cada mutación |
| Anti-SSRF | El analizador de cabeceras resuelve DNS una sola vez, rechaza toda IP no pública (incluyendo variantes IPv6 mapeadas a IPv4 y IPs en decimal/hex/octal), conecta contra la IP ya validada y no sigue redirecciones — todo con timeout, incluida la resolución DNS |
| Límite de tasa | Doble: por IP **y** un techo global, para que rotar de IP no sirva de nada |
| Panel de administración | Basic Auth + límite de tasa propio, deshabilitado por completo si no hay clave configurada, todo el contenido escapado antes de imprimirse |
| Contenedor | Multi-stage (sin pip ni compiladores en la imagen final), usuario sin privilegios, filesystem de solo lectura, `cap_drop: ALL`, `no-new-privileges`, límites de memoria/procesos, healthcheck |
| Cadena de suministro | Dependencias fijadas a versión exacta, Dependabot activo para pip/npm/Docker/Actions, CI corriendo toda la suite en cada cambio |
| Divulgación responsable | `security.txt` (RFC 9116) en `/.well-known/` |

## Estructura

```
spec/casos.json          Contrato de validación. FUENTE ÚNICA.
herramientas/            Generador de web/js/casos.js a partir del contrato.
web/                     Página estática: HTML, CSS embebido, JS propio.
servidor/                Flask.
  validacion.py            Espejo de web/js/validacion.js.
  red.py                   Defensas anti-SSRF del analizador.
  cabeceras.py             Motor de análisis de cabeceras.
  seguridad.py             Cabeceras HTTP, tokens, límite de tasa, origen, Basic Auth del panel.
  mensajes.py              Lectura del buzón y render del panel de administración.
  app.py                   Rutas.
tests/                   pytest.
datos/                   Buzón JSONL. No se versiona.
Dockerfile, docker-compose.yml   Build multi-stage + despliegue endurecido.
.github/                 CI (pytest + suite de navegador + build de imagen) y Dependabot.
INFORME_SEGURIDAD.md     Auditoría completa: qué se atacó, con qué comando, y cómo se arregló.
```

## El contrato compartido

`spec/casos.json` es la única definición del comportamiento de validación. Lo
consumen dos suites: `tests/test_contrato.py` con pytest y `web/js/casos.test.js`
en el navegador. Si `validacion.py` y `validacion.js` divergen, una de las dos
se pone roja.

Tras editar el JSON hay que regenerar el archivo que consume el navegador:

```bash
make casos    # o: python3 herramientas/generar_casos_js.py
```

## Decisiones de seguridad

**La validación del cliente no es un control.** El navegador está bajo control
de quien envía. `servidor/validacion.py` revalida todo desde cero; el JS existe
para dar respuesta inmediata, nada más.

**El generador de contraseñas no habla con el servidor.** Ni las generadas ni la
que el usuario pega para evaluar. Se puede verificar en la pestaña Red de las
herramientas del navegador: mientras se escribe no sale ninguna petición.

**El analizador de cabeceras sí necesita servidor**, porque el navegador no puede
leer cabeceras de otro origen. Eso lo convierte en un SSRF potencial, y por eso
`servidor/red.py` existe como módulo aparte y probable sin red: sólo http/https,
sin credenciales embebidas, puertos en lista blanca, resolución DNS explícita,
rechazo de toda IP no pública, conexión contra la IP ya validada y sin seguir
redirecciones.

## Limitaciones conocidas

- El límite de tasa vive en memoria del proceso. Con varios workers cada uno
  lleva su cuenta y un reinicio la borra. Para una instancia alcanza; para
  producción real va Redis.
- El token anti-CSRF es reutilizable dentro de su hora de vigencia. Protege
  contra CSRF porque un tercero no puede leerlo, pero no es un nonce de un solo
  uso: no impide que el cliente legítimo reenvíe.
- El honeypot temporal usa el reloj del cliente, que el atacante controla.
  Filtra bots genéricos y nada más.
- `escapar_html` no escapa `/` ni backtick: seguro en nodos de texto y atributos
  entrecomillados, **no** en atributos sin comillas ni dentro de `<script>`.
- `tiene_inyeccion_de_cabecera` bloquea URLs legítimas que contengan `%0A`
  codificado. Falso positivo aceptado a cambio de la cobertura.
- HSTS sólo se emite sobre HTTPS. Detrás de un proxy TLS hay que definir
  `DETRAS_DE_PROXY=1` para que el servidor lo detecte, y sólo si el proxy
  realmente reescribe `X-Forwarded-For`.
- El panel de mensajes usa Basic Auth sin sesión: cada pedido reenvía usuario
  y clave. Cómodo para uso personal, pero sobre HTTP plano viaja en claro
  (ver "Panel de mensajes" arriba).
- El timeout de resolución DNS (`servidor/red.py`) acota cuánto puede esperar
  **un pedido puntual**, pero Python no puede matar un hilo desde afuera: un
  atacante muy sostenido en el tiempo contra un dominio con DNS que nunca
  responde igual puede ir dejando hilos huérfanos. El límite de tasa global
  acota el ritmo al que eso puede pasar, no lo elimina del todo.
- El hash SHA-256 del CSS en el CSP se recalcula en cada arranque a partir de
  los archivos reales (`web/index.html`, `web/pruebas.html`,
  `servidor/mensajes.py`). Si se agrega un `<style>` nuevo en algún otro
  lugar, hay que sumarlo a `_hashes_estilo()` en `servidor/app.py` o ese
  bloque queda bloqueado por el navegador.

## Publicar detrás de nginx

`frame-ancestors`, HSTS y `X-Content-Type-Options` ya se emiten desde Flask.
Si se sirve detrás de nginx, no duplicarlos: elegir un solo lugar donde vivan.

## Licencia

Todos los derechos reservados — ver [`LICENSE`](LICENSE). El código está
público para lectura y evaluación, no para reuso sin permiso.
