/* validacion.js — implementación del contrato definido en validacion.test.js
   Funciones puras, sin DOM, sin red, sin estado global.

   ADVERTENCIA DE ALCANCE: esto es validación de cliente. Mejora la experiencia
   y filtra bots torpes. NO es un control de seguridad: el servidor debe repetir
   cada una de estas comprobaciones, porque el cliente está bajo control del atacante. */
(function (global) {
  'use strict';

  /* ── Expresiones precompiladas ────────────────────────────── */

  var ESPACIOS_CONTROL = /[\t\n\r\f\v]/g;
  var CONTROL_RESTANTE = /[\u0000-\u001F\u007F-\u009F]/g;
  var ANCHO_CERO       = /[\u200B-\u200D\u2060\uFEFF]/g;
  /* Marcas y aisladores bidireccionales: permiten que el texto se MUESTRE
     distinto de como está almacenado (clase Trojan Source). */
  var BIDI             = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
  var ESPACIOS_MULTI   = /\s+/g;

  /* Anclada y sin cuantificadores anidados sobre clases solapadas.
     Se aplica sólo después del tope de longitud, para acotar el costo. */
  var CORREO = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

  var CRLF_CRUDO     = /[\r\n]/;
  var CRLF_CODIFICADO = /%0[aAdD]|%00|\\r|\\n|\u2028|\u2029/;
  /* 'to' y 'from' quedan fuera a propósito: en español producen falsos
     positivos ("Presupuesto:", "punto:"). Ver nota de auditoría. */
  var CABECERAS = /(?:^|[\s;,])(bcc|cc|reply-to|content-type|content-transfer-encoding|mime-version|x-mailer)\s*:/i;

  var ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  var A_ESCAPAR = /[&<>"']/g;

  /* ── 1. normalizar ────────────────────────────────────────── */

  function normalizar(valor) {
    if (typeof valor !== 'string') return '';

    var texto = valor;
    try { texto = texto.normalize('NFC'); } catch (_) { /* motor sin normalize */ }

    return texto
      .replace(ESPACIOS_CONTROL, ' ')
      .replace(CONTROL_RESTANTE, '')
      .replace(ANCHO_CERO, '')
      .replace(BIDI, '')
      .replace(ESPACIOS_MULTI, ' ')
      .trim();
  }

  /* ── 2. esCorreoValido ────────────────────────────────────── */

  function esCorreoValido(valor) {
    if (typeof valor !== 'string') return false;
    if (valor.length === 0 || valor.length > 254) return false;

    var arroba = valor.indexOf('@');
    if (arroba === -1 || arroba > 64) return false;

    return CORREO.test(valor);
  }

  /* ── 3. tieneInyeccionDeCabecera ──────────────────────────── */

  function tieneInyeccionDeCabecera(valor) {
    if (typeof valor !== 'string') return false;
    if (CRLF_CRUDO.test(valor)) return true;
    if (CRLF_CODIFICADO.test(valor)) return true;
    return CABECERAS.test(valor);
  }

  /* ── 4. escaparHTML ───────────────────────────────────────── */

  function escaparHTML(valor) {
    if (typeof valor !== 'string') return '';
    return valor.replace(A_ESCAPAR, function (c) { return ESCAPES[c]; });
  }

  /* ── 5. longitudEnRango ───────────────────────────────────── */

  function longitudEnRango(valor, min, max) {
    if (typeof valor !== 'string') return false;
    var n = Array.from(valor).length;
    return n >= min && n <= max;
  }

  /* ── 6. evaluarFormulario ─────────────────────────────────── */

  var CAMPOS = [
    { nombre: 'nombre',  min: 2,  max: 80,   correo: false },
    { nombre: 'mail',    min: 5,  max: 254,  correo: true  },
    { nombre: 'motivo',  min: 3,  max: 120,  correo: false },
    { nombre: 'mensaje', min: 20, max: 4000, correo: false }
  ];

  function evaluarFormulario(datos, opciones) {
    var d = (datos && typeof datos === 'object') ? datos : {};
    var o = (opciones && typeof opciones === 'object') ? opciones : {};

    var msMinimos = typeof o.msMinimos === 'number' ? o.msMinimos : 3000;
    var errores = [];
    var limpio = {};

    /* El honeypot corta primero y sin detalle: a un bot no se le explica
       qué falló. Mismo criterio para el umbral temporal. */
    if (normalizar(o.honeypot) !== '') {
      return { valido: false, errores: [{ campo: 'honeypot', codigo: 'honeypot' }], limpio: limpio };
    }

    CAMPOS.forEach(function (campo) {
      var valor = normalizar(d[campo.nombre]);
      limpio[campo.nombre] = valor;

      if (valor === '') {
        errores.push({ campo: campo.nombre, codigo: 'requerido' });
        return;
      }
      if (tieneInyeccionDeCabecera(valor)) {
        errores.push({ campo: campo.nombre, codigo: 'inyeccion' });
        return;
      }
      if (campo.correo && !esCorreoValido(valor)) {
        errores.push({ campo: campo.nombre, codigo: 'correo_invalido' });
        return;
      }
      if (!longitudEnRango(valor, campo.min, campo.max)) {
        errores.push({ campo: campo.nombre, codigo: 'longitud' });
      }
    });

    /* El umbral temporal se evalúa AL FINAL y sólo si los campos están bien.
       Un humano rápido o con autocompletado dispara este umbral: si cortara
       antes, se quedaría sin saber qué campo corregir. Un bot que manda datos
       válidos a máquina sigue cayendo acá. */
    if (errores.length === 0) {
      var ms = o.msTranscurridos;
      if (typeof ms === 'number' && isFinite(ms) && ms < msMinimos) {
        return { valido: false, errores: [{ campo: 'formulario', codigo: 'demasiado_rapido' }], limpio: limpio };
      }
    }

    return { valido: errores.length === 0, errores: errores, limpio: limpio };
  }

  global.Validacion = {
    normalizar: normalizar,
    esCorreoValido: esCorreoValido,
    tieneInyeccionDeCabecera: tieneInyeccionDeCabecera,
    escaparHTML: escaparHTML,
    longitudEnRango: longitudEnRango,
    evaluarFormulario: evaluarFormulario
  };
})(typeof window !== 'undefined' ? window : globalThis);
