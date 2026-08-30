/* conectar-formulario.js — arranque del formulario de contacto.

   Archivo aparte, sin código inline: así la CSP queda en script-src 'self'
   sin necesitar 'unsafe-inline'.

   El envío va al backend Flask, que revalida todo desde cero. La validación
   del navegador es comodidad; la del servidor es el control real. */
(function () {
  'use strict';

  var MENSAJES_SERVIDOR = {
    demasiados_intentos: 'Demasiados envíos seguidos. Esperá unos minutos.',
    token_invalido: 'La sesión expiró. Recargá la página e intentá de nuevo.',
    origen_no_permitido: 'El envío fue rechazado por el servidor.',
    rechazado: 'No se pudo enviar el formulario.',
    peticion_invalida: 'El servidor no entendió la petición.',
    sin_servidor: 'No hay servidor escuchando. Levantá Flask con: python3 -m servidor.app'
  };

  var DE_CAMPO = ['requerido', 'longitud', 'correo_invalido', 'inyeccion'];

  function anunciar(form, texto, ok) {
    var region = form.querySelector('[data-estado]');
    if (!region) return;
    if (ok) region.setAttribute('data-ok', '');
    else region.removeAttribute('data-ok');
    region.textContent = texto;
  }

  function enviarAlServidor(limpio, form, inicio) {
    anunciar(form, 'Enviando...', false);

    fetch('/api/token', { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('token');
        return r.json();
      })
      .then(function (d) {
        return fetch('/api/contacto', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: d.token,
            datos: limpio,
            honeypot: '',
            msTranscurridos: Date.now() - inicio
          })
        });
      })
      .then(function (r) {
        return r.json().then(function (j) { return { ok: r.ok, cuerpo: j }; });
      })
      .then(function (res) {
        if (res.ok && res.cuerpo.valido) {
          form.reset();
          anunciar(form, 'Mensaje recibido. Te respondo apenas pueda.', true);
          return;
        }
        var errores = res.cuerpo.errores || [];
        var codigo = errores.length ? errores[0].codigo : 'rechazado';
        /* Si el servidor devolvio errores de campo, se pintan con la misma
           capa que los del cliente: el usuario no distingue de donde vienen. */
        var deCampo = errores.filter(function (e) {
          return DE_CAMPO.indexOf(e.codigo) !== -1;
        });
        if (deCampo.length && window.Interfaz) {
          window.Interfaz.pintarErrores(form, deCampo);
          anunciar(form, 'El servidor rechazo ' + deCampo.length +
                         (deCampo.length === 1 ? ' campo.' : ' campos.'), false);
          return;
        }
        anunciar(form, MENSAJES_SERVIDOR[codigo] || MENSAJES_SERVIDOR.rechazado, false);
      })
      .catch(function () {
        anunciar(form, MENSAJES_SERVIDOR.sin_servidor, false);
      });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var form = document.getElementById('form-contacto');
    if (!form || !window.Interfaz) return;

    var inicio = Date.now();

    window.Interfaz.conectar(form, {
      campoTrampa: 'sitio-web',
      msMinimos: 3000,
      alEnviar: function (limpio, formulario) {
        enviarAlServidor(limpio, formulario, inicio);
      }
    });
  });
})();
