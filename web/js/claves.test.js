/* claves.test.js — especificación del generador y evaluador. */
(function () {
  'use strict';

  var describir = Pruebas.describir;
  var probar = Pruebas.probar;
  var esperar = Pruebas.esperar;
  var C = window.Claves || {};

  describir('11 · aleatoriedad', function () {

    probar('enteroAleatorio se mantiene dentro del rango', function () {
      for (var i = 0; i < 500; i++) {
        var v = C.enteroAleatorio(10);
        esperar(v >= 0 && v < 10).aSerVerdadero();
      }
    });

    probar('enteroAleatorio no tiene sesgo de módulo apreciable', function () {
      /* Con 24000 muestras sobre 5 valores, cada casillero debería rondar 4800.
         Un módulo sesgado sobre 256 sobre-representa los primeros valores. */
      var cuentas = [0, 0, 0, 0, 0];
      for (var i = 0; i < 24000; i++) cuentas[C.enteroAleatorio(5)]++;
      var esperado = 24000 / 5;
      cuentas.forEach(function (n) {
        esperar(Math.abs(n - esperado) < esperado * 0.12).aSerVerdadero();
      });
    });

    probar('soporta rangos mayores a 256', function () {
      var vistos = {};
      for (var i = 0; i < 400; i++) vistos[C.enteroAleatorio(1000)] = true;
      esperar(Object.keys(vistos).length > 200).aSerVerdadero();
      for (var j = 0; j < 200; j++) {
        var v = C.enteroAleatorio(260);
        esperar(v >= 0 && v < 260).aSerVerdadero();
      }
    });

    probar('rechaza rangos no soportados', function () {
      [0, -3, 1.5, NaN, 5e9].forEach(function (malo) {
        var lanzo = false;
        try { C.enteroAleatorio(malo); } catch (e) { lanzo = true; }
        esperar(lanzo).aSerVerdadero();
      });
    });
  });

  describir('12 · generarClave', function () {

    probar('respeta el largo pedido', function () {
      esperar(C.generarClave({ largo: 24 }).length).aSer(24);
      esperar(C.generarClave({ largo: 32, simbolos: true }).length).aSer(32);
    });

    probar('aplica un mínimo de 8 caracteres', function () {
      esperar(C.generarClave({ largo: 3 }).length).aSer(8);
    });

    probar('incluye al menos un carácter de cada conjunto pedido', function () {
      for (var i = 0; i < 40; i++) {
        var c = C.generarClave({ largo: 12, simbolos: true });
        esperar(/[a-z]/.test(c)).aSerVerdadero();
        esperar(/[A-Z]/.test(c)).aSerVerdadero();
        esperar(/[0-9]/.test(c)).aSerVerdadero();
        esperar(/[^a-zA-Z0-9]/.test(c)).aSerVerdadero();
      }
    });

    probar('no coloca los obligatorios siempre al final', function () {
      /* Sin mezclar, el símbolo caería siempre en la misma posición. */
      var posiciones = {};
      for (var i = 0; i < 60; i++) {
        var c = C.generarClave({ largo: 12, simbolos: true });
        posiciones[c.search(/[^a-zA-Z0-9]/)] = true;
      }
      esperar(Object.keys(posiciones).length > 3).aSerVerdadero();
    });

    probar('omite caracteres ambiguos', function () {
      for (var i = 0; i < 60; i++) {
        esperar(/[l1IO0]/.test(C.generarClave({ largo: 24 }))).aSerFalso();
      }
    });

    probar('no repite la misma clave', function () {
      var vistas = {};
      for (var i = 0; i < 100; i++) vistas[C.generarClave({ largo: 16 })] = true;
      esperar(Object.keys(vistas).length).aSer(100);
    });

    probar('falla si no se habilita ningún conjunto', function () {
      var lanzo = false;
      try {
        C.generarClave({ minusculas: false, mayusculas: false, digitos: false, simbolos: false });
      } catch (e) { lanzo = true; }
      esperar(lanzo).aSerVerdadero();
    });
  });

  describir('13 · generarFrase', function () {

    probar('devuelve la cantidad de palabras pedida', function () {
      esperar(C.generarFrase(6).split('-').length).aSer(6);
      esperar(C.generarFrase(9).split('-').length).aSer(9);
    });

    probar('acepta separador propio', function () {
      esperar(C.generarFrase(4, '.').split('.').length).aSer(4);
    });

    probar('sólo usa palabras de la lista', function () {
      C.generarFrase(10).split('-').forEach(function (p) {
        esperar(C.PALABRAS.indexOf(p) !== -1).aSerVerdadero();
      });
    });

    probar('la lista no tiene duplicados', function () {
      var vistas = {};
      C.PALABRAS.forEach(function (p) { vistas[p] = (vistas[p] || 0) + 1; });
      var repetidas = Object.keys(vistas).filter(function (p) { return vistas[p] > 1; });
      esperar(repetidas.length).aSer(0);
    });

    probar('la entropía por palabra coincide con el tamaño de la lista', function () {
      var bits = C.bitsDeFrase(1);
      esperar(Math.abs(bits - Math.log2(C.PALABRAS.length)) < 0.001).aSerVerdadero();
    });
  });

  describir('14 · evaluar', function () {

    probar('la contraseña vacía no rompe nada', function () {
      var r = C.evaluar('');
      esperar(r.bits).aSer(0);
      esperar(r.veredicto).aSer('vacía');
    });

    probar('detecta contraseñas de diccionario', function () {
      esperar(C.evaluar('123456').avisos.length > 0).aSerVerdadero();
      esperar(C.evaluar('password').avisos.length > 0).aSerVerdadero();
    });

    probar('detecta el patrón palabra + número', function () {
      var r = C.evaluar('Montevideo2024');
      esperar(r.avisos.length > 0).aSerVerdadero();
    });

    probar('detecta repeticiones y secuencias', function () {
      esperar(C.evaluar('aaabbbccc').avisos.length > 0).aSerVerdadero();
      esperar(C.evaluar('xk123456pq').avisos.length > 0).aSerVerdadero();
    });

    probar('una clave generada no dispara avisos', function () {
      var limpias = 0;
      for (var i = 0; i < 30; i++) {
        if (C.evaluar(C.generarClave({ largo: 20, simbolos: true })).avisos.length === 0) limpias++;
      }
      esperar(limpias > 25).aSerVerdadero();
    });

    probar('más largo da más bits', function () {
      var corta = C.evaluar(C.generarClave({ largo: 12 })).bitsCrudos;
      var larga = C.evaluar(C.generarClave({ largo: 28 })).bitsCrudos;
      esperar(larga > corta).aSerVerdadero();
    });

    probar('no devuelve bits negativos', function () {
      esperar(C.evaluar('123456').bits >= 0).aSerVerdadero();
    });

    probar('el veredicto escala con los bits', function () {
      esperar(C.veredicto(20)).aSer('muy débil');
      esperar(C.veredicto(70)).aSer('aceptable');
      esperar(C.veredicto(130)).aSer('muy fuerte');
    });

    probar('el tiempo de quiebre crece con los bits', function () {
      esperar(C.tiempoDeQuiebre(20)).aSer('menos de un segundo');
      esperar(C.tiempoDeQuiebre(128)).aSer('más que la edad del universo');
    });
  });
})();
