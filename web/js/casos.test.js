/* casos.test.js — el mismo contrato que corre pytest, del lado del navegador.
   Los casos vienen de spec/casos.json vía casos.js. Si validacion.js y
   validacion.py divergen, una de las dos suites se pone roja. */
(function () {
  'use strict';

  var describir = Pruebas.describir;
  var probar = Pruebas.probar;
  var esperar = Pruebas.esperar;

  var V = window.Validacion || {};
  var CASOS = window.CASOS_COMPARTIDOS;

  if (!CASOS) {
    describir('0 · contrato compartido', function () {
      probar('casos.js está generado', function () {
        esperar('falta casos.js — correr: python3 herramientas/generar_casos_js.py').aSer('generado');
      });
    });
    return;
  }

  function etiqueta(caso, i) {
    return (caso.nota || JSON.stringify(caso.entrada)) + ' [' + i + ']';
  }

  describir('C1 · contrato · normalizar', function () {
    CASOS.normalizar.forEach(function (caso, i) {
      probar(etiqueta(caso, i), function () {
        esperar(V.normalizar(caso.entrada)).aSer(caso.esperado);
      });
    });
  });

  describir('C2 · contrato · correo', function () {
    CASOS.correo.forEach(function (caso, i) {
      probar(etiqueta(caso, i), function () {
        esperar(V.esCorreoValido(caso.entrada)).aSer(caso.esperado);
      });
    });
  });

  describir('C3 · contrato · inyección', function () {
    CASOS.inyeccion.forEach(function (caso, i) {
      probar(etiqueta(caso, i), function () {
        esperar(V.tieneInyeccionDeCabecera(caso.entrada)).aSer(caso.esperado);
      });
    });
  });

  describir('C4 · contrato · escape', function () {
    CASOS.escapar.forEach(function (caso, i) {
      probar(etiqueta(caso, i), function () {
        esperar(V.escaparHTML(caso.entrada)).aSer(caso.esperado);
      });
    });
  });

  describir('C5 · contrato · formulario', function () {
    CASOS.formulario.forEach(function (caso, i) {
      probar(etiqueta(caso, i), function () {
        var r = V.evaluarFormulario(caso.datos, caso.opciones);
        esperar(r.valido).aSer(caso.valido);
        var codigos = r.errores.map(function (e) { return e.codigo; }).sort();
        esperar(codigos).aSerIgualA(caso.codigos.slice().sort());
      });
    });
  });
})();
