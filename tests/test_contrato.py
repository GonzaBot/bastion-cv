"""Contrato compartido: las mismas pruebas que corre el navegador.

Si validacion.py y validacion.js divergen, esta suite se pone roja. La fuente
única es spec/casos.json — no se editan los casos acá.
"""

import json
from pathlib import Path

import pytest

from servidor import validacion

CASOS = json.loads((Path(__file__).resolve().parent.parent / "spec" / "casos.json")
                   .read_text(encoding="utf-8"))


def ids(grupo, campo="nota"):
    return [c.get(campo) or repr(c.get("entrada"))[:40] for c in CASOS[grupo]]


@pytest.mark.parametrize("caso", CASOS["normalizar"], ids=ids("normalizar"))
def test_normalizar(caso):
    assert validacion.normalizar(caso["entrada"]) == caso["esperado"]


@pytest.mark.parametrize("caso", CASOS["correo"], ids=ids("correo"))
def test_correo(caso):
    assert validacion.es_correo_valido(caso["entrada"]) is caso["esperado"]


@pytest.mark.parametrize("caso", CASOS["inyeccion"], ids=ids("inyeccion"))
def test_inyeccion(caso):
    assert validacion.tiene_inyeccion_de_cabecera(caso["entrada"]) is caso["esperado"]


@pytest.mark.parametrize("caso", CASOS["escapar"], ids=ids("escapar"))
def test_escapar(caso):
    assert validacion.escapar_html(caso["entrada"]) == caso["esperado"]


@pytest.mark.parametrize("caso", CASOS["formulario"], ids=ids("formulario"))
def test_formulario(caso):
    resultado = validacion.evaluar_formulario(caso["datos"], caso["opciones"])
    assert resultado["valido"] is caso["valido"]
    assert sorted(e["codigo"] for e in resultado["errores"]) == sorted(caso["codigos"])


# ── Propiedades que no dependen de casos concretos ──────────────────────

def test_normalizar_nunca_lanza():
    for entrada in [None, 0, [], {}, object(), b"bytes", 3.14, True]:
        assert isinstance(validacion.normalizar(entrada), str)


def test_normalizar_es_idempotente():
    for caso in CASOS["normalizar"]:
        una = validacion.normalizar(caso["entrada"])
        assert validacion.normalizar(una) == una


def test_evaluar_no_muta_la_entrada():
    datos = {"nombre": "  Gonza  ", "mail": "g@a.com", "motivo": "x", "mensaje": "y"}
    copia = dict(datos)
    validacion.evaluar_formulario(datos, {})
    assert datos == copia


def test_limite_de_parte_local():
    assert validacion.es_correo_valido("a" * 64 + "@mail.com") is True
    assert validacion.es_correo_valido("a" * 65 + "@mail.com") is False


def test_etiqueta_de_dominio_muy_larga():
    assert validacion.es_correo_valido("g@" + "b" * 64 + ".com") is False


def test_booleano_no_cuenta_como_tiempo():
    """True es int en Python. Sin el guard, True < 3000 sería True y
    dispararía el rechazo por tiempo."""
    datos = {"nombre": "Gonza", "mail": "g@a.com.uy", "motivo": "Auditoría",
             "mensaje": "Necesito segmentar la red de planta hoy."}
    resultado = validacion.evaluar_formulario(datos, {"msTranscurridos": True})
    assert resultado["valido"] is True
