/* Corre la suite del navegador bajo jsdom, para poder pedirla desde make.
   Requiere:  npm install jsdom   (o abrir web/pruebas.html en un navegador) */
const fs = require('fs'), path = require('path');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); }
catch (e) {
  console.error('Falta jsdom. Instalar con: npm install jsdom');
  console.error('Alternativa sin Node: abrir http://127.0.0.1:8000/pruebas.html');
  process.exit(1);
}
const B = path.join(__dirname, '..', 'web', 'js');
const dom = new JSDOM('<!DOCTYPE html><body><div id="r"></div></body>', { runScripts: 'outside-only' });
const w = dom.window;
global.window = w; global.document = w.document;
w.crypto = require('crypto').webcrypto;
['mini-test.js', 'casos.js', 'validacion.js', 'claves.js', 'interfaz.js',
 'validacion.test.js', 'interfaz.test.js', 'casos.test.js', 'claves.test.js']
  .forEach(f => w.eval(fs.readFileSync(path.join(B, f), 'utf8')));
w.Pruebas.correr(w.document.getElementById('r'));
const raiz = w.document.getElementById('r');
const fallas = raiz.querySelectorAll('li.falla');
fallas.forEach(li => console.log('  x ' + li.textContent));
console.log(raiz.querySelector('.resumen').textContent);
process.exit(fallas.length ? 1 : 0);
