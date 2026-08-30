#!/usr/bin/env python3
"""Genera web/js/casos.js a partir de spec/casos.json.

La fuente única es el JSON. El navegador no puede leerlo con fetch sin abrir
connect-src en la CSP, así que se transpila a un archivo JS con una asignación.

Uso:  python3 herramientas/generar_casos_js.py
      make casos
"""

import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ORIGEN = RAIZ / "spec" / "casos.json"
DESTINO = RAIZ / "web" / "js" / "casos.js"

CABECERA = """/* casos.js — GENERADO AUTOMÁTICAMENTE. No editar a mano.
   Fuente: spec/casos.json
   Regenerar: python3 herramientas/generar_casos_js.py
*/
window.CASOS_COMPARTIDOS = """


def main():
    datos = json.loads(ORIGEN.read_text(encoding="utf-8"))
    cuerpo = json.dumps(datos, ensure_ascii=False, indent=2)
    DESTINO.write_text(CABECERA + cuerpo + ";\n", encoding="utf-8")

    total = sum(len(v) for v in datos.values() if isinstance(v, list))
    print("%s → %s (%d casos)" % (
        ORIGEN.relative_to(RAIZ), DESTINO.relative_to(RAIZ), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
