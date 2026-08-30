/* interfaz.js — capa de presentación entre el formulario y el módulo Validacion.
   Depende de validacion.js. No valida nada por su cuenta: sólo traduce
   códigos de error a texto y los pinta de forma accesible.

   Mejora progresiva: si este script no carga, el formulario sigue funcionando
   con la validación nativa del navegador (required, type, minlength). */
(function (global) {
  'use strict';

  var V = global.Validacion;

  /* ── Traducción de códigos a texto ────────────────────────── */

  var MENSAJES = {
    requerido:       'Este campo es obligatorio.',
    correo_invalido: 'Revisá la dirección: no parece un correo válido.',
    longitud:        'La longitud no es válida.',
    inyeccion:       'El texto contiene caracteres no permitidos.',
    generico:        'No se pudo enviar el formulario. Revisá los datos e intentá de nuevo.'
  };

  var POR_CAMPO = {
    'nombre.longitud':  'El nombre debe tener entre 2 y 80 caracteres.',
    'motivo.longitud':  'El motivo debe tener entre 3 y 120 caracteres.',
    'mensaje.longitud': 'Contame un poco más: al menos 20 caracteres.',
    'mail.longitud':    'La dirección es demasiado larga.'
  };

  /* Códigos que NO se explican al usuario: son defensas anti-bot y
     detallarlas sería regalarle al atacante el criterio de rechazo. */
  var SILENCIOSOS = { honeypot: true, demasiado_rapido: true };

  /* Búsqueda por clave propia únicamente. Sin esto, un código llamado
     'constructor' o 'toString' devuelve una función heredada del prototipo
     en lugar de un texto. */
  function propia(mapa, clave) {
    return Object.prototype.hasOwnProperty.call(mapa, clave) ? mapa[clave] : null;
  }

  function mensajeDe(campo, codigo) {
    if (typeof codigo !== 'string') return MENSAJES.generico;
    if (propia(SILENCIOSOS, codigo)) return MENSAJES.generico;
    return propia(POR_CAMPO, campo + '.' + codigo)
        || propia(MENSAJES, codigo)
        || MENSAJES.generico;
  }

  /* ── Lectura del formulario ───────────────────────────────── */

  var NOMBRES = ['nombre', 'mail', 'motivo', 'mensaje'];

  /* namedItem puede devolver una RadioNodeList o un elemento inesperado si
     alguien duplica names (DOM clobbering). Sólo se acepta un control con
     value de tipo string. */
  function valorDe(form, nombre) {
    if (!form || !form.elements) return '';
    var el = form.elements.namedItem ? form.elements.namedItem(nombre) : form.elements[nombre];
    if (!el || typeof el.value !== 'string') return '';
    return el.value;
  }

  function leerFormulario(form) {
    var datos = {};
    NOMBRES.forEach(function (n) { datos[n] = valorDe(form, n); });
    return datos;
  }

  /* ── Pintado de errores ───────────────────────────────────── */

  /* Los identificadores tienen que ser únicos en TODO el documento, no dentro
     del formulario. Con dos formularios en la misma página, un id fijo como
     'error-nombre' se duplica y aria-describedby apunta al elemento equivocado. */
  var contador = 0;

  function prefijoDe(form) {
    var actual = form.getAttribute('data-form-id');
    if (!actual) {
      contador += 1;
      actual = 'f' + contador;
      form.setAttribute('data-form-id', actual);
    }
    return actual;
  }

  function contenedorDe(form, campo) {
    var el = form.elements.namedItem ? form.elements.namedItem(campo) : null;
    if (!el || !el.closest) return null;
    return el.closest('.campo');
  }

  /* El campo puede venir ya asociado a un texto de ayuda. Se conserva y se
     le suma el error, en vez de pisarlo. */
  function describirCon(el, id) {
    if (!el.hasAttribute('data-describedby-previo')) {
      el.setAttribute('data-describedby-previo', el.getAttribute('aria-describedby') || '');
    }
    var previo = el.getAttribute('data-describedby-previo');
    el.setAttribute('aria-describedby', previo ? previo + ' ' + id : id);
  }

  function restaurarDescrito(el) {
    if (el.hasAttribute('data-describedby-previo')) {
      var previo = el.getAttribute('data-describedby-previo');
      if (previo) el.setAttribute('aria-describedby', previo);
      else el.removeAttribute('aria-describedby');
      el.removeAttribute('data-describedby-previo');
    }
  }

  function limpiarErrores(form) {
    var previos = form.querySelectorAll('[data-error]');
    Array.prototype.forEach.call(previos, function (p) {
      if (p.parentNode) p.parentNode.removeChild(p);
    });
    NOMBRES.forEach(function (n) {
      var el = form.elements.namedItem ? form.elements.namedItem(n) : null;
      if (el && el.removeAttribute) {
        el.removeAttribute('aria-invalid');
        restaurarDescrito(el);
      }
    });
  }

  function pintarErrores(form, errores) {
    limpiarErrores(form);
    var primero = null;

    errores.forEach(function (err) {
      var el = form.elements.namedItem ? form.elements.namedItem(err.campo) : null;
      var caja = contenedorDe(form, err.campo);
      if (!el || !caja || typeof el.value !== 'string') return;

      var id = prefijoDe(form) + '-error-' + err.campo;
      var p = form.ownerDocument.createElement('p');
      p.setAttribute('data-error', '');
      p.setAttribute('id', id);
      p.className = 'error';
      /* textContent, nunca innerHTML: el texto sale del mapa de mensajes,
         pero la regla se sostiene aunque el mapa cambie. */
      p.textContent = mensajeDe(err.campo, err.codigo);
      caja.appendChild(p);

      el.setAttribute('aria-invalid', 'true');
      describirCon(el, id);

      if (!primero) primero = el;
    });

    return primero;
  }

  /* ── Región de estado para lectores de pantalla ───────────── */

  /* Se busca DENTRO del formulario, no en todo el documento: si no, el segundo
     formulario de la página encuentra la región del primero y anuncia ahí. */
  function regionEstado(form) {
    var region = form.querySelector('[data-estado]');
    if (!region) {
      region = form.ownerDocument.createElement('p');
      region.setAttribute('data-estado', '');
      region.id = prefijoDe(form) + '-estado';
      region.className = 'estado-formulario';
      region.setAttribute('role', 'status');
      region.setAttribute('aria-live', 'polite');
      form.insertBefore(region, form.firstChild);
    }
    return region;
  }

  function anunciar(form, texto) {
    regionEstado(form).textContent = texto;
  }

  /* ── Conexión ─────────────────────────────────────────────── */

  function conectar(form, opciones) {
    if (!form || !V) return null;
    var o = opciones || {};
    var msMinimos = typeof o.msMinimos === 'number' ? o.msMinimos : 3000;
    var campoTrampa = o.campoTrampa || 'sitio-web';
    var inicio = Date.now();

    /* Se apaga la validación nativa recién ahora: si el script falla antes
       de esta línea, el navegador sigue validando solo. */
    form.setAttribute('novalidate', 'novalidate');

    form.addEventListener('submit', function (evento) {
      evento.preventDefault();

      var resultado = V.evaluarFormulario(leerFormulario(form), {
        honeypot: valorDe(form, campoTrampa),
        msTranscurridos: Date.now() - inicio,
        msMinimos: msMinimos
      });

      if (resultado.valido) {
        limpiarErrores(form);
        anunciar(form, '');
        if (typeof o.alEnviar === 'function') o.alEnviar(resultado.limpio, form);
        return;
      }

      var visibles = resultado.errores.filter(function (e) { return !SILENCIOSOS[e.codigo]; });

      if (visibles.length === 0) {
        limpiarErrores(form);
        anunciar(form, MENSAJES.generico);
        return;
      }

      var primero = pintarErrores(form, visibles);
      anunciar(form, visibles.length === 1
        ? 'Hay 1 campo con problemas.'
        : 'Hay ' + visibles.length + ' campos con problemas.');
      if (primero && primero.focus) primero.focus();
    });

    form.addEventListener('reset', function () {
      limpiarErrores(form);
      anunciar(form, '');
      inicio = Date.now();
    });

    return {
      leer: function () { return leerFormulario(form); },
      limpiar: function () { limpiarErrores(form); }
    };
  }

  global.Interfaz = {
    mensajeDe: mensajeDe,
    leerFormulario: leerFormulario,
    limpiarErrores: limpiarErrores,
    pintarErrores: pintarErrores,
    conectar: conectar,
    MENSAJES: MENSAJES
  };
})(typeof window !== 'undefined' ? window : globalThis);
