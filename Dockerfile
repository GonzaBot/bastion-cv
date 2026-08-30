# ── Build: dependencias en un venv aislado, con pip y su caché que nunca
#    llegan a la imagen final ──────────────────────────────────────────────
FROM python:3.12-slim AS build

WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --upgrade pip \
    && /venv/bin/pip install --no-cache-dir -r requirements.txt

# ── Runtime: sólo el venv ya armado + el código. Sin pip, sin compiladores,
#    sin caché de descargas: lo que no está no se puede explotar. ─────────
FROM python:3.12-slim

RUN useradd --create-home --uid 1000 app
WORKDIR /app

COPY --from=build /venv /venv
COPY servidor/ servidor/
COPY web/ web/

RUN mkdir -p /app/datos && chown -R app:app /app
USER app

ENV PATH="/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/salud', timeout=2)" || exit 1

CMD ["python3", "-m", "servidor.app"]
