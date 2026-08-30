/* validacion.test.js — ESPECIFICACIÓN.
   Escrito ANTES de la implementación (fase roja de XP).
   Módulo bajo prueba: window.Validacion (todavía no existe → todo falla). */
(function () {
  'use strict';

  var describir = Pruebas.describir;
  var probar = Pruebas.probar;
  var esperar = Pruebas.esperar;

  var V = window.Validacion || {};

  /* ── 1. normalizar(valor) → string ─────────────────────────
     Punto de entrada único. Todo lo demás asume texto ya normalizado. */

  describir('1 · normalizar', function () {

    probar('recorta espacios en los extremos', function () {
      esperar(V.normalizar('  hola  ')).aSer('hola');
    });

    probar('colapsa espacios internos repetidos', function () {
      esperar(V.normalizar('hola     mundo')).aSer('hola mundo');
    });

    probar('convierte saltos de línea y tabulaciones en un espacio', function () {
      esperar(V.normalizar('hola\n\t mundo')).aSer('hola mundo');
    });

    probar('elimina caracteres de control C0', function () {
      esperar(V.normalizar('a\u0000b\u0007c')).aSer('abc');
    });

    probar('elimina caracteres de ancho cero', function () {
      esperar(V.normalizar('a\u200Bb\uFEFFc')).aSer('abc');
    });

    probar('devuelve cadena vacía para null', function () {
      esperar(V.normalizar(null)).aSer('');
    });

    probar('devuelve cadena vacía para undefined', function () {
      esperar(V.normalizar(undefined)).aSer('');
    });

    probar('devuelve cadena vacía para tipos que no son texto', function () {
      esperar(V.normalizar(42)).aSer('');
      esperar(V.normalizar({})).aSer('');
      esperar(V.normalizar([])).aSer('');
    });

    probar('preserva acentos y ñ', function () {
      esperar(V.normalizar(' Añón  Gonzáles ')).aSer('Añón Gonzáles');
    });

    probar('elimina marcas de anulación bidireccional (Trojan Source)', function () {
      esperar(V.normalizar('factura\u202Egpj.exe')).aSer('facturagpj.exe');
      esperar(V.normalizar('a\u202Ab\u202Cc')).aSer('abc');
    });

    probar('elimina aisladores direccionales', function () {
      esperar(V.normalizar('a\u2066b\u2069c')).aSer('abc');
    });

    probar('no lanza nunca', function () {
      esperar(function () { V.normalizar(Object.create(null)); }).aNoLanzar();
    });
  });

  /* ── 2. esCorreoValido(valor) → boolean ──────────────────── */

  describir('2 · esCorreoValido', function () {

    probar('acepta un correo común', function () {
      esperar(V.esCorreoValido('gonza@empresa.com.uy')).aSerVerdadero();
    });

    probar('acepta subdominios y signo más', function () {
      esperar(V.esCorreoValido('g+cv@mail.utec.edu.uy')).aSerVerdadero();
    });

    probar('rechaza si falta la arroba', function () {
      esperar(V.esCorreoValido('gonzaempresa.com')).aSerFalso();
    });

    probar('rechaza dos arrobas', function () {
      esperar(V.esCorreoValido('a@b@c.com')).aSerFalso();
    });

    probar('rechaza espacios internos', function () {
      esperar(V.esCorreoValido('gon za@mail.com')).aSerFalso();
    });

    probar('rechaza dominio sin punto', function () {
      esperar(V.esCorreoValido('gonza@localhost')).aSerFalso();
    });

    probar('rechaza punto al inicio o al final de la parte local', function () {
      esperar(V.esCorreoValido('.gonza@mail.com')).aSerFalso();
      esperar(V.esCorreoValido('gonza.@mail.com')).aSerFalso();
    });

    probar('rechaza si supera 254 caracteres', function () {
      var largo = new Array(250).join('a') + '@mail.com';
      esperar(V.esCorreoValido(largo)).aSerFalso();
    });

    probar('respeta el límite de 64 de la parte local', function () {
      esperar(V.esCorreoValido(new Array(65).join('a') + '@mail.com')).aSerVerdadero();
      esperar(V.esCorreoValido(new Array(66).join('a') + '@mail.com')).aSerFalso();
    });

    probar('rechaza etiquetas de dominio de más de 63 caracteres', function () {
      esperar(V.esCorreoValido('g@' + new Array(65).join('b') + '.com')).aSerFalso();
    });

    probar('rechaza vacío y no-texto', function () {
      esperar(V.esCorreoValido('')).aSerFalso();
      esperar(V.esCorreoValido(null)).aSerFalso();
    });
  });

  /* ── 3. tieneInyeccionDeCabecera(valor) → boolean ─────────
     El riesgo real de un formulario de contacto: si el backend arma
     un correo con estos datos, un CRLF permite inyectar cabeceras. */

  describir('3 · tieneInyeccionDeCabecera', function () {

    probar('detecta salto de línea crudo', function () {
      esperar(V.tieneInyeccionDeCabecera('hola\nBcc: victima@mail.com')).aSerVerdadero();
    });

    probar('detecta retorno de carro', function () {
      esperar(V.tieneInyeccionDeCabecera('hola\r\nCc: otro@mail.com')).aSerVerdadero();
    });

    probar('detecta CRLF codificado en URL', function () {
      esperar(V.tieneInyeccionDeCabecera('hola%0aBcc:%20x@y.com')).aSerVerdadero();
      esperar(V.tieneInyeccionDeCabecera('hola%0D%0ACc: x@y.com')).aSerVerdadero();
    });

    probar('detecta nombres de cabecera de correo', function () {
      esperar(V.tieneInyeccionDeCabecera('Content-Type: text/html')).aSerVerdadero();
      esperar(V.tieneInyeccionDeCabecera('bcc: alguien@mail.com')).aSerVerdadero();
      esperar(V.tieneInyeccionDeCabecera('MIME-Version: 1.0')).aSerVerdadero();
    });

    probar('no se deja engañar por mayúsculas', function () {
      esperar(V.tieneInyeccionDeCabecera('BCC: x@y.com')).aSerVerdadero();
    });

    probar('acepta texto legítimo sin falsos positivos', function () {
      esperar(V.tieneInyeccionDeCabecera('Necesito una auditoría de red')).aSerFalso();
      esperar(V.tieneInyeccionDeCabecera('Presupuesto: 3 VLAN y 2 switches')).aSerFalso();
    });

    probar('devuelve false para no-texto', function () {
      esperar(V.tieneInyeccionDeCabecera(null)).aSerFalso();
    });
  });

  /* ── 4. escaparHTML(valor) → string ───────────────────────
     Defensa en profundidad: si algún día el texto vuelve al DOM. */

  describir('4 · escaparHTML', function () {

    probar('escapa las etiquetas', function () {
      esperar(V.escaparHTML('<script>alert(1)</script>'))
        .aSer('&lt;script&gt;alert(1)&lt;/script&gt;');
    });

    probar('escapa comillas dobles y simples', function () {
      esperar(V.escaparHTML('dijo "hola" y \'chau\''))
        .aSer('dijo &quot;hola&quot; y &#39;chau&#39;');
    });

    probar('escapa el ampersand primero, sin doble escape cruzado', function () {
      esperar(V.escaparHTML('a & b')).aSer('a &amp; b');
      esperar(V.escaparHTML('&lt;')).aSer('&amp;lt;');
    });

    probar('deja intacto el texto sin metacaracteres', function () {
      esperar(V.escaparHTML('red industrial VLAN 10')).aSer('red industrial VLAN 10');
    });

    probar('devuelve cadena vacía para no-texto', function () {
      esperar(V.escaparHTML(null)).aSer('');
    });
  });

  /* ── 5. longitudEnRango(valor, min, max) → boolean ────────── */

  describir('5 · longitudEnRango', function () {

    probar('acepta dentro del rango, inclusive', function () {
      esperar(V.longitudEnRango('abc', 3, 5)).aSerVerdadero();
      esperar(V.longitudEnRango('abcde', 3, 5)).aSerVerdadero();
    });

    probar('rechaza fuera del rango', function () {
      esperar(V.longitudEnRango('ab', 3, 5)).aSerFalso();
      esperar(V.longitudEnRango('abcdef', 3, 5)).aSerFalso();
    });

    probar('cuenta caracteres, no bytes', function () {
      esperar(V.longitudEnRango('ñññ', 3, 3)).aSerVerdadero();
    });

    probar('rechaza no-texto', function () {
      esperar(V.longitudEnRango(null, 0, 10)).aSerFalso();
    });
  });

  /* ── 6. evaluarFormulario(datos, opciones) ────────────────
     Devuelve { valido, errores:[{campo, codigo}], limpio:{} } */

  describir('6 · evaluarFormulario', function () {

    function datosValidos() {
      return {
        nombre: 'Gonza Rodríguez',
        mail: 'gonza@empresa.com.uy',
        motivo: 'Diseño de red industrial',
        mensaje: 'Necesito segmentar la red de planta del aserradero.'
      };
    }

    var opcionesOk = { honeypot: '', msTranscurridos: 8000, msMinimos: 3000 };

    probar('acepta un envío legítimo', function () {
      var r = V.evaluarFormulario(datosValidos(), opcionesOk);
      esperar(r.valido).aSerVerdadero();
      esperar(r.errores.length).aSer(0);
    });

    probar('devuelve los campos ya normalizados', function () {
      var d = datosValidos();
      d.nombre = '  Gonza    Rodríguez  ';
      var r = V.evaluarFormulario(d, opcionesOk);
      esperar(r.limpio.nombre).aSer('Gonza Rodríguez');
    });

    probar('no muta el objeto de entrada', function () {
      var d = datosValidos();
      d.nombre = '  Gonza  ';
      V.evaluarFormulario(d, opcionesOk);
      esperar(d.nombre).aSer('  Gonza  ');
    });

    probar('marca campo requerido vacío', function () {
      var d = datosValidos(); d.nombre = '   ';
      var r = V.evaluarFormulario(d, opcionesOk);
      esperar(r.valido).aSerFalso();
      esperar(r.errores.map(function (e) { return e.campo; })).aContener('nombre');
      esperar(r.errores[0].codigo).aSer('requerido');
    });

    probar('marca correo inválido', function () {
      var d = datosValidos(); d.mail = 'gonza@localhost';
      var r = V.evaluarFormulario(d, opcionesOk);
      esperar(r.valido).aSerFalso();
      esperar(r.errores[0].codigo).aSer('correo_invalido');
    });

    probar('marca mensaje demasiado corto', function () {
      var d = datosValidos(); d.mensaje = 'hola';
      var r = V.evaluarFormulario(d, opcionesOk);
      esperar(r.errores[0].codigo).aSer('longitud');
    });

    probar('marca intento de inyección de cabecera', function () {
      var d = datosValidos(); d.motivo = 'Trabajo%0aBcc: victima@mail.com';
      var r = V.evaluarFormulario(d, opcionesOk);
      esperar(r.valido).aSerFalso();
      esperar(r.errores[0].codigo).aSer('inyeccion');
    });

    probar('rechaza si el honeypot viene lleno', function () {
      var r = V.evaluarFormulario(datosValidos(), { honeypot: 'bot', msTranscurridos: 8000, msMinimos: 3000 });
      esperar(r.valido).aSerFalso();
      esperar(r.errores[0].codigo).aSer('honeypot');
    });

    probar('rechaza envíos más rápidos que el mínimo humano', function () {
      var r = V.evaluarFormulario(datosValidos(), { honeypot: '', msTranscurridos: 400, msMinimos: 3000 });
      esperar(r.valido).aSerFalso();
      esperar(r.errores[0].codigo).aSer('demasiado_rapido');
    });

    probar('el rechazo por tiempo no oculta los errores de campo', function () {
      var d = datosValidos(); d.mail = 'no-es-un-correo'; d.nombre = '';
      var r = V.evaluarFormulario(d, { honeypot: '', msTranscurridos: 200, msMinimos: 3000 });
      esperar(r.valido).aSerFalso();
      var codigos = r.errores.map(function (e) { return e.codigo; });
      esperar(codigos).aContener('requerido');
      esperar(codigos).aContener('correo_invalido');
      esperar(codigos.indexOf('demasiado_rapido')).aSer(-1);
    });

    probar('acumula varios errores a la vez', function () {
      var r = V.evaluarFormulario({ nombre: '', mail: 'no', motivo: '', mensaje: '' }, opcionesOk);
      esperar(r.errores.length > 2).aSerVerdadero();
    });

    probar('no lanza con datos ausentes', function () {
      esperar(function () { V.evaluarFormulario(undefined, undefined); }).aNoLanzar();
    });

    probar('devuelve inválido con datos ausentes', function () {
      esperar(V.evaluarFormulario(undefined, undefined).valido).aSerFalso();
    });
  });
})();
