/* mini-test.js — arnés de pruebas mínimo, sin dependencias.
   No usa red, no usa eval, no requiere instalación. */
(function (global) {
  'use strict';

  var grupos = [];
  var grupoActual = null;

  function describir(nombre, cuerpo) {
    grupoActual = { nombre: nombre, casos: [] };
    grupos.push(grupoActual);
    cuerpo();
    grupoActual = null;
  }

  function probar(nombre, cuerpo) {
    if (!grupoActual) throw new Error('probar() fuera de describir()');
    grupoActual.casos.push({ nombre: nombre, cuerpo: cuerpo });
  }

  function fallar(mensaje) {
    var e = new Error(mensaje);
    e.esFalloDeAsercion = true;
    throw e;
  }

  function representar(v) {
    if (typeof v === 'string') return JSON.stringify(v);
    if (v === undefined) return 'undefined';
    try { return JSON.stringify(v); } catch (_) { return String(v); }
  }

  function esperar(actual) {
    return {
      aSer: function (esperado) {
        if (actual !== esperado) {
          fallar('se esperaba ' + representar(esperado) + ' y se obtuvo ' + representar(actual));
        }
      },
      aSerVerdadero: function () {
        if (actual !== true) fallar('se esperaba true y se obtuvo ' + representar(actual));
      },
      aSerFalso: function () {
        if (actual !== false) fallar('se esperaba false y se obtuvo ' + representar(actual));
      },
      aSerIgualA: function (esperado) {
        var a = JSON.stringify(actual), b = JSON.stringify(esperado);
        if (a !== b) fallar('se esperaba ' + b + ' y se obtuvo ' + a);
      },
      aContener: function (item) {
        if (!Array.isArray(actual) || actual.indexOf(item) === -1) {
          fallar('se esperaba que ' + representar(actual) + ' contuviera ' + representar(item));
        }
      },
      aNoLanzar: function () {
        try { actual(); } catch (e) { fallar('lanzó una excepción inesperada: ' + e.message); }
      }
    };
  }

  function correr(destino) {
    var total = 0, pasaron = 0, fallaron = 0;
    var fragmento = document.createDocumentFragment();

    grupos.forEach(function (grupo) {
      var seccion = document.createElement('section');
      var titulo = document.createElement('h2');
      titulo.textContent = grupo.nombre;
      seccion.appendChild(titulo);

      var lista = document.createElement('ul');

      grupo.casos.forEach(function (caso) {
        total++;
        var li = document.createElement('li');
        try {
          caso.cuerpo();
          pasaron++;
          li.className = 'ok';
          li.textContent = 'PASA · ' + caso.nombre;
        } catch (e) {
          fallaron++;
          li.className = 'falla';
          li.textContent = 'FALLA · ' + caso.nombre + ' → ' + e.message;
        }
        lista.appendChild(li);
      });

      seccion.appendChild(lista);
      fragmento.appendChild(seccion);
    });

    var resumen = document.createElement('p');
    resumen.className = fallaron === 0 ? 'resumen ok' : 'resumen falla';
    resumen.textContent = total + ' pruebas · ' + pasaron + ' pasan · ' + fallaron + ' fallan';

    destino.textContent = '';
    destino.appendChild(resumen);
    destino.appendChild(fragmento);
  }

  global.Pruebas = { describir: describir, probar: probar, esperar: esperar, correr: correr };
})(window);
