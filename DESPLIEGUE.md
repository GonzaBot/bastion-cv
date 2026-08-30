# Desplegar bastion-cv en un VPS real

Guía paso a paso para pasar de "corre en mi red local" a "está en internet,
con HTTPS de verdad, detrás de nginx". Asume un VPS Ubuntu/Debian con acceso
SSH y sudo, y `bastion-cv.duckdns.org` como dominio (DuckDNS, gratis).

## 1. DuckDNS

1. Entrar a <https://www.duckdns.org>, iniciar sesión (GitHub/Google/etc).
2. Crear el subdominio `bastion-cv` y apuntarlo a la **IP pública del VPS**.
3. Guardar el token que muestra la página — hace falta si la IP cambia.

Un VPS normalmente tiene IP fija, así que con el paso 2 alcanza. Por las
dudas, para que se actualice sola si algún día cambia:

```bash
mkdir -p ~/duckdns && cat > ~/duckdns/actualizar.sh <<'EOF'
#!/bin/bash
curl -fsS "https://www.duckdns.org/update?domains=bastion-cv&token=TU_TOKEN&ip=" > /dev/null
EOF
chmod +x ~/duckdns/actualizar.sh
(crontab -l 2>/dev/null; echo "*/30 * * * * ~/duckdns/actualizar.sh") | crontab -
```

## 2. Preparar el VPS

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y docker.io docker-compose-v2 nginx certbot python3-certbot-nginx ufw

sudo usermod -aG docker "$USER"   # cerrar sesión y volver a entrar para que tome efecto
```

**Firewall — sólo SSH, HTTP y HTTPS.** El puerto 8000 de la app *no* debe
quedar expuesto a internet: sólo nginx le habla, por `localhost`.

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

## 3. Clonar y configurar la app

```bash
git clone https://github.com/GonzaBot/bastion-cv.git
cd bastion-cv
cp .env.ejemplo .env
```

Editar `.env` con valores reales — **nada de los placeholders del ejemplo**:

```bash
CLAVE_SECRETA=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ADMIN_CLAVE=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
sed -i "s#^CLAVE_SECRETA=.*#CLAVE_SECRETA=$CLAVE_SECRETA#" .env
sed -i "s#^ADMIN_CLAVE=.*#ADMIN_CLAVE=$ADMIN_CLAVE#" .env
sed -i "s#^ORIGENES=.*#ORIGENES=https://bastion-cv.duckdns.org#" .env
sed -i "s#^DETRAS_DE_PROXY=.*#DETRAS_DE_PROXY=1#" .env
echo "ADMIN_CLAVE guardada: $ADMIN_CLAVE"   # anotarla, no vuelve a mostrarse
```

`DETRAS_DE_PROXY=1` es imprescindible acá: sin eso, `ProxyFix` no se activa,
el límite de tasa termina contando todo bajo la IP de nginx (`127.0.0.1`) en
vez de la IP real de cada visitante, y `HSTS` nunca se manda porque Flask
nunca se entera de que el tráfico llegó por HTTPS (ver `servidor/app.py`).

**El puerto de la app no debe mirar a internet.** `docker-compose.yml` por
defecto publica `8000:8000` (todas las interfaces) porque así conviene para
probarlo en la LAN de casa. Acá se necesita lo opuesto — sólo loopback, para
que únicamente nginx (que corre en el mismo VPS) le pueda hablar:

```bash
cat > docker-compose.override.yml <<'EOF'
services:
  cv-gonza:
    ports:
      - "127.0.0.1:8000:8000"
EOF
```

Este archivo ya está en `.gitignore` — vive sólo en el VPS, no se versiona.
`docker compose` lo combina automáticamente con `docker-compose.yml`, sin
flags extra.

```bash
docker compose up -d --build
curl http://127.0.0.1:8000/api/salud   # {"estado": "vivo"} — confirma que responde en loopback
```

## 4. nginx + certbot

```bash
sudo tee /etc/nginx/sites-available/bastion-cv.conf > /dev/null <<'EOF'
server {
    listen 80;
    server_name bastion-cv.duckdns.org;

    client_max_body_size 100k;   # con margen sobre el límite de 64KB de la app

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/bastion-cv.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

sudo certbot --nginx -d bastion-cv.duckdns.org
```

Certbot reescribe automáticamente el bloque de nginx para servir HTTPS y
redirigir el 80 al 443. No hace falta escribir el bloque `ssl` a mano.

**No duplicar cabeceras de seguridad en nginx.** `frame-ancestors`, HSTS,
`X-Content-Type-Options` y el resto ya salen de Flask (`servidor/seguridad.py`).
Agregarlas también acá no suma nada y es una fuente típica de valores
contradictorios entre las dos capas — un solo lugar donde viven.

## 5. Verificar

```bash
curl -sI https://bastion-cv.duckdns.org/ | grep -iE "strict-transport|content-security|x-frame"
```

Debería verse `Strict-Transport-Security` presente (antes, sin `DETRAS_DE_PROXY=1`
o sin nginx de por medio, no aparecía nunca). También:

- Abrir `https://bastion-cv.duckdns.org` y probar las tres herramientas.
- `https://bastion-cv.duckdns.org/admin/mensajes` con las credenciales de `.env`.
- Correr el sitio por <https://www.ssllabs.com/ssltest/> — con la config de
  certbot por defecto (TLS 1.2+) debería sacar A o A+.
- Confirmar que el límite de tasa ve la IP real: pedir el formulario de
  contacto desde dos dispositivos distintos no debería compartir cupo (si
  compartieran, `DETRAS_DE_PROXY` o el `proxy_set_header X-Forwarded-For`
  están mal).

## 6. security.txt

`web/.well-known/security.txt` tiene un contacto y un dominio de ejemplo.
Antes de dejarlo en línea, reemplazar:

```
Contact: mailto:tu-email-real@ejemplo.com
Canonical: https://bastion-cv.duckdns.org/.well-known/security.txt
```

y reconstruir la imagen (`docker compose up -d --build`) para que el cambio
se sirva.

## Mantenimiento

- **Renovar el certificado:** certbot instala un timer de systemd que
  renueva solo. Confirmar con `sudo systemctl status certbot.timer`.
- **Actualizar la app:**
  ```bash
  cd bastion-cv && git pull && docker compose up -d --build
  ```
- **Backup del buzón:** `datos/mensajes.jsonl` vive en un volumen montado
  fuera del contenedor — un `cp` o `rsync` periódico de esa carpeta alcanza.
- **Logs:** `docker compose logs -f` (app) y `sudo journalctl -u nginx -f`
  (proxy).
