/* interfaz.test.js — especificación de la capa DOM.
   Requiere DOM real: corre en el navegador (pruebas.html) o bajo jsdom.
   No corre en Node pelado. */
(function () {
  'use strict';

  var describir = Pruebas.describir;
  var probar = Pruebas.probar;
  var esperar = Pruebas.esperar;

  var I = window.Interfaz || {};

  function armarFormulario() {
    var form = document.createElement('form');
    form.innerHTML =
      '<div class="campo"><label for="t-nombre">Nombre</label>' +
      '<input id="t-nombre" name="nombre" type="text"></div>' +
      '<div class="campo"><label for="t-mail">Correo</label>' +
      '<input id="t-mail" name="mail" type="email"></div>' +
      '<div class="campo"><label for="t-motivo">Motivo</label>' +
      '<input id="t-motivo" name="motivo" type="text"></div>' +
      '<div class="campo"><label for="t-mensaje">Mensaje</label>' +
      '<textarea id="t-mensaje" name="mensaje"></textarea></div>' +
      '<div class="trampa"><input name="sitio-web" type="text" tabindex="-1"></div>' +
      '<button type="submit">Enviar</button>';
    document.body.appendChild(form);
    return form;
  }

  function llenarValido(form) {
    form.elements.namedItem('nombre').value = 'Gonza Rodríguez';
    form.elements.namedItem('mail').value = 'gonza@empresa.com.uy';
    form.elements.namedItem('motivo').value = 'Diseño de red industrial';
    form.elements.namedItem('mensaje').value = 'Necesito segmentar la red de planta del aserradero.';
  }

  function enviar(form) {
    var ev = document.createEvent ? document.createEvent('Event') : null;
    if (ev) { ev.initEvent('submit', true, true); }
    else { ev = new Event('submit', { bubbles: true, cancelable: true }); }
    form.dispatchEvent(ev);
    return ev;
  }

  /* ── 7. mensajeDe ─────────────────────────────────────────── */

  describir('7 · mensajeDe', function () {

    probar('usa el mensaje específico del campo cuando existe', function () {
      esperar(I.mensajeDe('mensaje', 'longitud')).aSer('Contame un poco más: al menos 20 caracteres.');
    });

    probar('cae al mensaje genérico del código', function () {
      esperar(I.mensajeDe('motivo', 'requerido')).aSer('Este campo es obligatorio.');
    });

    probar('nunca devuelve vacío ante un código desconocido', function () {
      esperar(I.mensajeDe('x', 'codigo_que_no_existe').length > 0).aSerVerdadero();
    });

    probar('ignora claves heredadas del prototipo', function () {
      ['constructor', '__proto__', 'toString', 'hasOwnProperty'].forEach(function (clave) {
        var m = I.mensajeDe('nombre', clave);
        esperar(typeof m).aSer('string');
        esperar(m).aSer(I.MENSAJES.generico);
      });
    });

    probar('no revela el motivo de los rechazos anti-bot', function () {
      var m1 = I.mensajeDe('honeypot', 'honeypot');
      var m2 = I.mensajeDe('formulario', 'demasiado_rapido');
      esperar(m1).aSer(m2);
      esperar(m1.toLowerCase().indexOf('bot')).aSer(-1);
    });
  });

  /* ── 8. leerFormulario ────────────────────────────────────── */

  describir('8 · leerFormulario', function () {

    probar('extrae los cuatro campos', function () {
      var form = armarFormulario();
      llenarValido(form);
      var d = I.leerFormulario(form);
      esperar(d.nombre).aSer('Gonza Rodríguez');
      esperar(d.mensaje).aSer('Necesito segmentar la red de planta del aserradero.');
      form.remove();
    });

    probar('devuelve cadena vacía si falta un campo', function () {
      var form = document.createElement('form');
      esperar(I.leerFormulario(form).nombre).aSer('');
    });

    probar('no lanza con un formulario nulo', function () {
      esperar(function () { I.leerFormulario(null); }).aNoLanzar();
    });

    probar('ignora elementos duplicados (DOM clobbering)', function () {
      var form = armarFormulario();
      var extra = document.createElement('input');
      extra.name = 'nombre';
      extra.value = 'inyectado';
      form.appendChild(extra);
      esperar(I.leerFormulario(form).nombre).aSer('');
      form.remove();
    });
  });

  /* ── 9. pintarErrores ─────────────────────────────────────── */

  describir('9 · pintarErrores', function () {

    probar('inserta el mensaje dentro del contenedor del campo', function () {
      var form = armarFormulario();
      I.pintarErrores(form, [{ campo: 'nombre', codigo: 'requerido' }]);
      var p = form.querySelector('[data-error]');
      esperar(p !== null).aSerVerdadero();
      esperar(p.textContent).aSer('Este campo es obligatorio.');
      form.remove();
    });

    probar('marca el campo como inválido y lo describe', function () {
      var form = armarFormulario();
      I.pintarErrores(form, [{ campo: 'mail', codigo: 'correo_invalido' }]);
      var el = form.elements.namedItem('mail');
      var p = form.querySelector('[data-error]');
      esperar(el.getAttribute('aria-invalid')).aSer('true');
      esperar(el.getAttribute('aria-describedby')).aSer(p.id);
      form.remove();
    });

    probar('conserva un aria-describedby preexistente', function () {
      var form = armarFormulario();
      var el = form.elements.namedItem('nombre');
      el.setAttribute('aria-describedby', 'ayuda-nombre');
      I.pintarErrores(form, [{ campo: 'nombre', codigo: 'requerido' }]);
      var descrito = el.getAttribute('aria-describedby').split(/\s+/);
      esperar(descrito.indexOf('ayuda-nombre') !== -1).aSerVerdadero();
      esperar(descrito.length).aSer(2);
      form.remove();
    });

    probar('restaura el aria-describedby original al limpiar', function () {
      var form = armarFormulario();
      var el = form.elements.namedItem('nombre');
      el.setAttribute('aria-describedby', 'ayuda-nombre');
      I.pintarErrores(form, [{ campo: 'nombre', codigo: 'requerido' }]);
      I.limpiarErrores(form);
      esperar(el.getAttribute('aria-describedby')).aSer('ayuda-nombre');
      form.remove();
    });

    probar('usa identificadores distintos en formularios distintos', function () {
      var a = armarFormulario(), b = armarFormulario();
      I.pintarErrores(a, [{ campo: 'nombre', codigo: 'requerido' }]);
      I.pintarErrores(b, [{ campo: 'nombre', codigo: 'requerido' }]);
      var ida = a.querySelector('[data-error]').id;
      var idb = b.querySelector('[data-error]').id;
      esperar(ida !== idb).aSerVerdadero();
      esperar(document.querySelectorAll('#' + ida).length).aSer(1);
      a.remove(); b.remove();
    });

    probar('devuelve el primer campo con error para enfocarlo', function () {
      var form = armarFormulario();
      var primero = I.pintarErrores(form, [
        { campo: 'motivo', codigo: 'requerido' },
        { campo: 'mensaje', codigo: 'requerido' }
      ]);
      esperar(primero.name).aSer('motivo');
      form.remove();
    });

    probar('no acumula mensajes al pintar dos veces', function () {
      var form = armarFormulario();
      I.pintarErrores(form, [{ campo: 'nombre', codigo: 'requerido' }]);
      I.pintarErrores(form, [{ campo: 'nombre', codigo: 'requerido' }]);
      esperar(form.querySelectorAll('[data-error]').length).aSer(1);
      form.remove();
    });

    probar('nunca interpreta el mensaje como HTML', function () {
      var form = armarFormulario();
      I.pintarErrores(form, [{ campo: 'nombre', codigo: '<img src=x onerror=alert(1)>' }]);
      var p = form.querySelector('[data-error]');
      esperar(p.querySelectorAll('img').length).aSer(0);
      form.remove();
    });

    probar('limpiarErrores deja el formulario sin marcas', function () {
      var form = armarFormulario();
      I.pintarErrores(form, [{ campo: 'nombre', codigo: 'requerido' }]);
      I.limpiarErrores(form);
      esperar(form.querySelectorAll('[data-error]').length).aSer(0);
      esperar(form.elements.namedItem('nombre').hasAttribute('aria-invalid')).aSerFalso();
      form.remove();
    });
  });

  /* ── 10. conectar ─────────────────────────────────────────── */

  describir('10 · conectar', function () {

    probar('desactiva la validación nativa sólo al conectarse', function () {
      var form = armarFormulario();
      esperar(form.hasAttribute('novalidate')).aSerFalso();
      I.conectar(form, {});
      esperar(form.hasAttribute('novalidate')).aSerVerdadero();
      form.remove();
    });

    probar('cancela el envío cuando hay errores', function () {
      var form = armarFormulario();
      I.conectar(form, { msMinimos: 0 });
      var ev = enviar(form);
      esperar(ev.defaultPrevented).aSerVerdadero();
      esperar(form.querySelectorAll('[data-error]').length > 0).aSerVerdadero();
      form.remove();
    });

    probar('llama al manejador con los datos limpios cuando es válido', function () {
      var form = armarFormulario();
      llenarValido(form);
      form.elements.namedItem('nombre').value = '  Gonza    Rodríguez  ';
      var recibido = null;
      I.conectar(form, { msMinimos: 0, alEnviar: function (limpio) { recibido = limpio; } });
      enviar(form);
      esperar(recibido !== null).aSerVerdadero();
      esperar(recibido.nombre).aSer('Gonza Rodríguez');
      form.remove();
    });

    probar('rechaza en silencio si el honeypot viene lleno', function () {
      var form = armarFormulario();
      llenarValido(form);
      form.elements.namedItem('sitio-web').value = 'bot';
      var llamado = false;
      I.conectar(form, { msMinimos: 0, alEnviar: function () { llamado = true; } });
      enviar(form);
      esperar(llamado).aSerFalso();
      esperar(form.querySelectorAll('[data-error]').length).aSer(0);
      form.remove();
    });

    probar('anuncia el estado en una región accesible', function () {
      var form = armarFormulario();
      I.conectar(form, { msMinimos: 0 });
      enviar(form);
      var region = form.querySelector('[data-estado]');
      esperar(region.getAttribute('role')).aSer('status');
      esperar(region.textContent.length > 0).aSerVerdadero();
      form.remove();
    });

    probar('cada formulario tiene su propia región de estado', function () {
      var a = armarFormulario(), b = armarFormulario();
      I.conectar(a, { msMinimos: 0 });
      I.conectar(b, { msMinimos: 0 });
      enviar(a); enviar(b);
      esperar(a.querySelector('[data-estado]') !== null).aSerVerdadero();
      esperar(b.querySelector('[data-estado]') !== null).aSerVerdadero();
      var ia = a.querySelector('[data-estado]').id;
      var ib = b.querySelector('[data-estado]').id;
      esperar(ia !== ib).aSerVerdadero();
      a.remove(); b.remove();
    });

    probar('no lanza con formulario nulo', function () {
      esperar(function () { I.conectar(null, {}); }).aNoLanzar();
    });
  });
})();
