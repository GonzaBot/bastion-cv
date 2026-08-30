/* herramientas.js — capa DOM de las dos herramientas de la página.

   1. Generador y evaluador de contraseñas: 100 % en el navegador.
   2. Analizador de cabeceras de seguridad: consulta al backend Flask.

   Igual que interfaz.js, esta capa no calcula nada por su cuenta: llama a
   Claves para lo primero y a la API para lo segundo. */
(function (global) {
  'use strict';

  var C = global.Claves;

  function $(id) { return document.getElementById(id); }

  function texto(nodo, valor) { if (nodo) nodo.textContent = valor; }

  /* ── 1. Contraseñas ─────────────────────────────────────────────────── */

  function pintarEvaluacion(destino, resultado) {
    destino.textContent = '';
    var doc = destino.ownerDocument;

    var resumen = doc.createElement('p');
    resumen.className = 'medida';
    resumen.textContent = resultado.bits + ' bits · ' + resultado.veredicto +
      ' · resiste ' + resultado.tiempo;
    resumen.setAttribute('data-nivel', resultado.veredicto.replace(/\s/g, '-'));
    destino.appendChild(resumen);

    if (resultado.avisos.length) {
      var lista = doc.createElement('ul');
      lista.className = 'avisos';
      resultado.avisos.forEach(function (aviso) {
        var li = doc.createElement('li');
        li.textContent = aviso;   // textContent: nunca innerHTML
        lista.appendChild(li);
      });
      destino.appendChild(lista);
    }
  }

  function conectarClaves() {
    var salida = $('clave-salida');
    var largo = $('clave-largo');
    var largoValor = $('clave-largo-valor');
    var simbolos = $('clave-simbolos');
    var tipo = $('clave-tipo');
    var botonGenerar = $('clave-generar');
    var botonCopiar = $('clave-copiar');
    var medida = $('clave-medida');
    var propia = $('clave-propia');
    var medidaPropia = $('clave-propia-medida');

    if (!salida || !C) return;

    function generar() {
      var esFrase = tipo && tipo.value === 'frase';
      var clave;
      if (esFrase) {
        clave = C.generarFrase(Number(largo.value) >= 8 ? 7 : 6);
      } else {
        clave = C.generarClave({
          largo: Number(largo.value),
          simbolos: simbolos ? simbolos.checked : false
        });
      }
      salida.value = clave;
      var bits = esFrase
        ? Math.round(C.bitsDeFrase(clave.split('-').length))
        : C.evaluar(clave).bitsCrudos;
      texto(medida, bits + ' bits de entropía real de generación · resiste ' +
                    C.tiempoDeQuiebre(bits));
      if (botonCopiar) botonCopiar.textContent = 'Copiar';
    }

    if (largo && largoValor) {
      var refrescarLargo = function () { largoValor.textContent = largo.value; };
      largo.addEventListener('input', refrescarLargo);
      refrescarLargo();
    }

    if (botonGenerar) botonGenerar.addEventListener('click', generar);
    if (tipo) tipo.addEventListener('change', generar);

    if (botonCopiar) {
      botonCopiar.addEventListener('click', function () {
        if (!salida.value) return;
        salida.select();
        var copiado = false;
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(salida.value);
            copiado = true;
          } else if (document.execCommand) {
            copiado = document.execCommand('copy');
          }
        } catch (e) { copiado = false; }
        botonCopiar.textContent = copiado ? 'Copiado' : 'Copiá con Ctrl+C';
      });
    }

    if (propia && medidaPropia) {
      propia.addEventListener('input', function () {
        if (!propia.value) { medidaPropia.textContent = ''; return; }
        pintarEvaluacion(medidaPropia, C.evaluar(propia.value));
      });
      /* Al salir de la página no queda nada escrito en ningún lado. */
      global.addEventListener('pagehide', function () { propia.value = ''; });
    }

    generar();
  }

  /* ── 2. Analizador de cabeceras ─────────────────────────────────────── */

  var GRAVEDAD = { critica: 'Crítica', importante: 'Importante', recomendada: 'Recomendada' };

  function pintarInforme(destino, informe) {
    destino.textContent = '';
    var doc = destino.ownerDocument;

    var cabeza = doc.createElement('p');
    cabeza.className = 'nota-seguridad';
    cabeza.setAttribute('data-nota', informe.nota);
    cabeza.textContent = 'Nota ' + informe.nota + ' · ' + informe.puntaje + '/100 · ' + informe.url;
    destino.appendChild(cabeza);

    var tabla = doc.createElement('table');
    var thead = doc.createElement('thead');
    thead.innerHTML = '';
    var filaCab = doc.createElement('tr');
    ['Cabecera', 'Estado', 'Detalle'].forEach(function (t) {
      var th = doc.createElement('th');
      th.scope = 'col';
      th.textContent = t;
      filaCab.appendChild(th);
    });
    thead.appendChild(filaCab);
    tabla.appendChild(thead);

    var tbody = doc.createElement('tbody');
    informe.hallazgos.forEach(function (h) {
      var tr = doc.createElement('tr');
      var th = doc.createElement('th');
      th.scope = 'row';
      th.textContent = h.cabecera;
      tr.appendChild(th);

      var estado = doc.createElement('td');
      estado.textContent = (h.cumple ? 'OK' : 'Falta') + ' · ' + (GRAVEDAD[h.gravedad] || h.gravedad);
      estado.className = h.cumple ? 'ok' : 'falta';
      tr.appendChild(estado);

      var detalle = doc.createElement('td');
      detalle.textContent = h.detalle;
      tr.appendChild(detalle);

      tbody.appendChild(tr);
    });
    tabla.appendChild(tbody);

    var caja = doc.createElement('div');
    caja.className = 'tabla-scroll';
    caja.setAttribute('tabindex', '0');
    caja.setAttribute('role', 'region');
    caja.setAttribute('aria-label', 'Resultado del análisis de cabeceras');
    caja.appendChild(tabla);
    destino.appendChild(caja);
  }

  function conectarCabeceras() {
    var form = $('form-cabeceras');
    var entrada = $('cabeceras-url');
    var salida = $('cabeceras-salida');
    if (!form || !entrada || !salida) return;

    form.addEventListener('submit', function (evento) {
      evento.preventDefault();
      var url = entrada.value.trim();
      if (!url) return;

      salida.textContent = 'Consultando…';

      fetch('/api/token', { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          return fetch('/api/cabeceras', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: d.token, url: url })
          });
        })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, cuerpo: j }; }); })
        .then(function (res) {
          if (!res.ok) {
            salida.textContent = res.cuerpo.error || 'No se pudo analizar la dirección.';
            return;
          }
          pintarInforme(salida, res.cuerpo);
        })
        .catch(function () {
          salida.textContent = 'El analizador necesita el servidor Flask corriendo. ' +
            'Sin backend, esta herramienta no funciona: pedir una URL desde el navegador ' +
            'la bloquea la política de origen cruzado.';
        });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    conectarClaves();
    conectarCabeceras();
  });

  global.Herramientas = { pintarEvaluacion: pintarEvaluacion, pintarInforme: pintarInforme };
})(typeof window !== 'undefined' ? window : globalThis);
