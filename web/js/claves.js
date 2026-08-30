/* claves.js — generador y evaluador de contraseñas.

   TODO ocurre en el navegador. Ninguna clave, ni generada ni pegada por el
   usuario, sale de esta máquina: no hay fetch, no hay almacenamiento, no hay
   registro. Es la única forma honesta de ofrecer una herramienta así.

   Aleatoriedad: crypto.getRandomValues, nunca Math.random. Math.random no es
   criptográficamente seguro y su estado se puede reconstruir observando
   suficientes salidas. */
(function (global) {
  'use strict';

  var MINUSCULAS = 'abcdefghijkmnopqrstuvwxyz';      // sin 'l'
  var MAYUSCULAS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';       // sin 'I' ni 'O'
  var DIGITOS    = '23456789';                        // sin '0' ni '1'
  var SIMBOLOS   = '!#$%&()*+-<=>?@[]^_{|}~';

  /* 260 palabras ≈ 8,02 bits por palabra. La lista es corta a propósito: la
     seguridad viene de la cantidad de palabras elegidas, no de que sean raras.
     Seis palabras dan unos 48 bits; ocho, unos 64. */
  var PALABRAS = ('abeja abrigo aceite acero agua aguja ala alambre alma almendra ambar ancla ' +
    'anillo antena arbol arcilla arena arroz asado avena avion azucar balde banco barco barro ' +
    'bosque bota botella brasa brisa bronce buho cable cabra cadena cafe caja calle cama camino ' +
    'campo canasta cancion carbon carpa casa cascara cedro cemento ceniza cepillo cerezo cielo ' +
    'cinta ciruela clavo cobre cocina codo columna conejo copa corcho cordon corteza cristal cuchara ' +
    'cuerda cuero cumbre dedo dique disco duna equipo escalera escoba espejo espiga espuma estano ' +
    'estufa fibra fierro flecha flor foco fogata fresa fruta fuente fuego funda gancho garra ' +
    'gaviota globo goma gota grano granja grieta grillo gruta guante harina hebra helecho herradura ' +
    'hierba hilo hoja hongo horno hueso huevo humo isla jarra jaula jazmin junco laurel leche ' +
    'lena lenteja libro lima limon linterna llave lluvia loma lupa madera maiz malla manta ' +
    'manzana maquina marfil martillo mesa miel mimbre molino monte mora mosaico motor muelle muro ' +
    'nido niebla nieve nogal nube nudo ola olivo olla orilla oro ortiga otono ovillo ' +
    'pala palma paloma pan panal papel pared pasto pecho pera perla pesca piedra pino ' +
    'pinza pipa piso pluma polea polvo pozo pradera puente puerta pulpo puno queso rama rana ' +
    'raiz rastro rayo red reja remo resina riego rincon rio roble rocio rueda ruta ' +
    'sal salto sauce semilla senda seta sierra silla soga sol sombra soplo suelo surco ' +
    'tabla taller tallo tapa techo tejido tela tiza tomate tornillo torre trigo trueno tuerca ' +
    'tulipa turba uva vaina valle vapor vara vela vena ventana verja vidrio viga vino ' +
    'violeta yema yeso yunque zanja zapato zorro zumo').split(/\s+/);

  var COMUNES = ('123456 password 123456789 12345678 12345 qwerty abc123 111111 123123 admin ' +
    'letmein welcome monkey dragon football iloveyou princess sunshine master 1234567890 ' +
    'contrasena contraseña hola1234 uruguay montevideo boca peñarol nacional rivera ' +
    'qwertyuiop asdfgh zxcvbn 000000 password1 admin123 root toor 1q2w3e4r').split(/\s+/);

  /* ── Aleatoriedad sin sesgo ──────────────────────────────────────────
     Tomar un valor y hacer % n reparte mal cuando n no divide a la potencia
     de dos: los primeros valores salen más seguido. Se descarta y se vuelve
     a pedir. Con 32 bits el descarte es raro y el rango queda sin tope
     práctico, así que la lista de palabras no tiene que ser potencia de dos. */

  var TECHO = 4294967296; // 2^32

  function enteroAleatorio(n) {
    if (!Number.isInteger(n) || n <= 0 || n > TECHO) {
      throw new RangeError('rango fuera de soporte');
    }
    var limite = Math.floor(TECHO / n) * n;
    var buffer = new Uint32Array(1);
    var valor;
    do {
      global.crypto.getRandomValues(buffer);
      valor = buffer[0];
    } while (valor >= limite);
    return valor % n;
  }

  function elegir(lista) {
    return lista[enteroAleatorio(lista.length)];
  }

  function mezclar(arreglo) {
    for (var i = arreglo.length - 1; i > 0; i--) {
      var j = enteroAleatorio(i + 1);
      var t = arreglo[i]; arreglo[i] = arreglo[j]; arreglo[j] = t;
    }
    return arreglo;
  }

  /* ── Generación ─────────────────────────────────────────────────────── */

  function alfabetoDe(opciones) {
    var o = opciones || {};
    var alfabeto = '';
    if (o.minusculas !== false) alfabeto += MINUSCULAS;
    if (o.mayusculas !== false) alfabeto += MAYUSCULAS;
    if (o.digitos !== false) alfabeto += DIGITOS;
    if (o.simbolos) alfabeto += SIMBOLOS;
    return alfabeto;
  }

  function generarClave(opciones) {
    var o = opciones || {};
    var largo = Math.max(8, Math.min(128, o.largo || 20));
    var alfabeto = alfabetoDe(o);
    if (!alfabeto) throw new Error('hay que habilitar al menos un conjunto');

    var salida = [];
    /* Se garantiza al menos un carácter de cada conjunto pedido, y después se
       mezcla: si no, la posición de cada tipo sería predecible. */
    var obligatorios = [];
    if (o.minusculas !== false) obligatorios.push(elegir(MINUSCULAS));
    if (o.mayusculas !== false) obligatorios.push(elegir(MAYUSCULAS));
    if (o.digitos !== false) obligatorios.push(elegir(DIGITOS));
    if (o.simbolos) obligatorios.push(elegir(SIMBOLOS));

    for (var i = 0; i < largo - obligatorios.length; i++) salida.push(elegir(alfabeto));
    salida = mezclar(salida.concat(obligatorios));
    return salida.join('');
  }

  function generarFrase(palabras, separador) {
    var n = Math.max(4, Math.min(12, palabras || 6));
    var sep = typeof separador === 'string' ? separador : '-';
    var salida = [];
    for (var i = 0; i < n; i++) salida.push(elegir(PALABRAS));
    return salida.join(sep);
  }

  /* ── Entropía ────────────────────────────────────────────────────────
     Se calcula la entropía de GENERACIÓN, no la de una clave arbitraria.
     Para una clave que pega el usuario sólo se puede estimar un techo:
     cuánto costaría si fuera aleatoria, que casi nunca lo es. */

  function bitsDeClave(largo, tamanoAlfabeto) {
    if (largo <= 0 || tamanoAlfabeto <= 1) return 0;
    return largo * Math.log2(tamanoAlfabeto);
  }

  function bitsDeFrase(palabras) {
    return palabras * Math.log2(PALABRAS.length);
  }

  function alfabetoObservado(clave) {
    var tamano = 0;
    if (/[a-z]/.test(clave)) tamano += 26;
    if (/[A-Z]/.test(clave)) tamano += 26;
    if (/[0-9]/.test(clave)) tamano += 10;
    if (/[^a-zA-Z0-9]/.test(clave)) tamano += 33;
    return tamano;
  }

  /* ── Evaluación de una clave existente ──────────────────────────────── */

  function avisos(clave) {
    var lista = [];
    var bajo = clave.toLowerCase();

    COMUNES.forEach(function (comun) {
      if (bajo === comun) lista.push('Es una de las contraseñas más usadas del mundo.');
      else if (comun.length >= 5 && bajo.indexOf(comun) !== -1) {
        lista.push('Contiene "' + comun + '", que está en cualquier diccionario de ataque.');
      }
    });

    if (/^[a-zA-Z]+[0-9]{1,4}[!#$%&*]?$/.test(clave)) {
      lista.push('Sigue el patrón palabra + números + símbolo, el primero que prueban.');
    }
    if (/(.)\1{2,}/.test(clave)) lista.push('Repite el mismo carácter tres o más veces seguidas.');
    if (/(012|123|234|345|456|567|678|789|890)/.test(clave)) lista.push('Contiene una secuencia numérica.');
    if (/(abc|bcd|cde|qwe|wer|asd|sdf|zxc)/i.test(clave)) lista.push('Contiene una secuencia de teclado.');
    if (/(19|20)\d{2}/.test(clave)) lista.push('Contiene algo que parece un año.');
    if (clave.length < 12) lista.push('Menos de 12 caracteres: hoy es corto para cualquier uso serio.');

    return lista.filter(function (v, i, a) { return a.indexOf(v) === i; });
  }

  function veredicto(bits) {
    if (bits < 40) return 'muy débil';
    if (bits < 60) return 'débil';
    if (bits < 80) return 'aceptable';
    if (bits < 100) return 'fuerte';
    return 'muy fuerte';
  }

  /* Tiempo de quiebre suponiendo un atacante offline con hardware dedicado.
     1e11 intentos/segundo es un orden razonable contra un hash rápido tipo
     SHA-1. Contra bcrypt o Argon2 sería muchísimo menos, y por eso el número
     de acá es el escenario PESIMISTA, no el probable. */
  function tiempoDeQuiebre(bits, intentosPorSegundo) {
    var tasa = intentosPorSegundo || 1e11;
    var segundos = Math.pow(2, bits - 1) / tasa;
    var unidades = [
      [1, 'menos de un segundo'], [60, 'segundos'], [3600, 'minutos'],
      [86400, 'horas'], [2592000, 'días'], [31536000, 'meses'],
      [31536000 * 1000, 'años'], [Infinity, 'siglos']
    ];
    if (segundos < 1) return 'menos de un segundo';
    if (segundos < 60) return Math.round(segundos) + ' segundos';
    if (segundos < 3600) return Math.round(segundos / 60) + ' minutos';
    if (segundos < 86400) return Math.round(segundos / 3600) + ' horas';
    if (segundos < 2592000) return Math.round(segundos / 86400) + ' días';
    if (segundos < 31536000) return Math.round(segundos / 2592000) + ' meses';
    var anios = segundos / 31536000;
    if (anios < 1000) return Math.round(anios) + ' años';
    if (anios < 1e6) return Math.round(anios / 1000) + ' mil años';
    if (anios < 1e9) return Math.round(anios / 1e6) + ' millones de años';
    return 'más que la edad del universo';
  }

  function evaluar(clave) {
    if (typeof clave !== 'string' || clave.length === 0) {
      return { bits: 0, veredicto: 'vacía', avisos: [], tiempo: '—', largo: 0 };
    }
    var bits = bitsDeClave(clave.length, alfabetoObservado(clave));
    var lista = avisos(clave);
    /* Cada patrón detectado descuenta: la fórmula del alfabeto supone
       aleatoriedad, y un patrón demuestra que no la hay. */
    var ajustados = Math.max(0, bits - lista.length * 12);
    return {
      largo: clave.length,
      bits: Math.round(ajustados),
      bitsCrudos: Math.round(bits),
      veredicto: veredicto(ajustados),
      avisos: lista,
      tiempo: tiempoDeQuiebre(ajustados)
    };
  }

  global.Claves = {
    generarClave: generarClave,
    generarFrase: generarFrase,
    evaluar: evaluar,
    bitsDeClave: bitsDeClave,
    bitsDeFrase: bitsDeFrase,
    alfabetoObservado: alfabetoObservado,
    tiempoDeQuiebre: tiempoDeQuiebre,
    veredicto: veredicto,
    enteroAleatorio: enteroAleatorio,
    PALABRAS: PALABRAS
  };
})(typeof window !== 'undefined' ? window : globalThis);
