.PHONY: pruebas python navegador casos servidor limpiar

servidor:
	python3 -m servidor.app

pruebas: python navegador

python:
	python3 -m pytest -q

navegador:
	@node herramientas/correr_pruebas_node.js

casos:
	python3 herramientas/generar_casos_js.py

limpiar:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
