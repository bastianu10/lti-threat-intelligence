// Prueba del reporte ejecutivo (modo demostracion) con jsdom: navegacion, contenido, PDF, impresion y texto hostil.
const fs = require("fs"), { JSDOM, VirtualConsole } = require("jsdom");
const base = fs.readFileSync(process.argv[2], "utf8");
const espera = ms => new Promise(r => setTimeout(r, ms));
let ok = 0, fallas = 0;
const comprobar = (c, t) => { c ? ok++ : fallas++; console.log((c ? "  OK    " : "  FALLA ") + t); };
function cargar(html, hash) {
  const errores = [], vc = new VirtualConsole();
  vc.on("jsdomError", e => { if (!/Could not load|Not implemented: navigation/.test(String(e.message))) errores.push(String(e.message)); });
  vc.on("error", m => errores.push(String(m)));
  const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true, url: "https://panel.ejemplo/" + (hash || "#reporte"),
    virtualConsole: vc, beforeParse(w) {
      w.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
      w.matchMedia = w.matchMedia || (() => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {} }));
      w.print = () => { w.__impreso = (w.__impreso || 0) + 1; w.__titulo = w.document.title; };
    } });
  return { w: dom.window, d: dom.window.document, errores };
}
function conReporte(transformar) {
  const i = base.indexOf('MOCK["reporte-semanal"]='), j = base.indexOf("})();", i) + 5;
  const src = base.slice(i, j);
  return base.slice(0, i) + src.replace("})();", "})();\n" + transformar + ";") + base.slice(j);
}
(async () => {
  console.log("== 1. Navegación y contenido");
  let { w, d, errores } = cargar(base); await espera(1200);
  const nav = d.getElementById("nav-rep");
  comprobar(!!nav && nav.getAttribute("aria-current") === "page", "enlace «Resumen semanal» en la navegación, marcado como página actual");
  const rep = d.getElementById("rep");
  comprobar(!!rep && rep.getAttribute("aria-busy") === null, "el reporte se pinta");
  const t = rep ? rep.textContent : "";
  comprobar(/CONFIDENCIAL/.test(t) && /no distribuir/.test(t), "etiqueta de clasificación CONFIDENCIAL");
  comprobar(["Hallazgos abiertos", "Prioridad crítica", "Dentro de plazo", "Explotación activa"].every(x => t.includes(x)), "4 indicadores clave");
  comprobar(["Tendencia de hallazgos abiertos", "Distribución actual", "Riesgo por proceso de negocio", "Vulnerabilidades más urgentes", "Gobierno."].every(x => t.includes(x)), "secciones del reporte");
  comprobar(/no vinculante/.test(t) && /decide el dueño/.test(t), "declara que la IA no es vinculante");
  comprobar(rep.querySelectorAll("svg[role=img] rect").length >= 14, "gráfica de tendencia (SVG accesible)");
  comprobar(/Vencido hace 13 d/.test(t) && /\+3 vs\. semana anterior/.test(t), "plazos vencidos y comparación semanal visibles");
  comprobar(rep.querySelectorAll("tbody tr").length === 4, "tablas de procesos (2) y urgentes (2)");
  comprobar(/IA: escalar/.test(t) && /USD 3\.97/.test(t), "recomendación de la IA y costo estimado del agente");
  comprobar(rep.querySelectorAll("button").length === 0, "el reporte no tiene acciones (solo lectura)");
  console.log("== 2. PDF e impresión");
  const pdf = d.getElementById("rep-pdf");
  comprobar(pdf && !pdf.disabled, "botón «Descargar PDF» habilitado cuando hay datos");
  pdf.click(); await espera(50);
  comprobar(w.__impreso === 1 && /^Resumen_semanal_LTI_/.test(w.__titulo), "abre el diálogo de impresión con nombre de archivo sugerido (" + w.__titulo + ")");
  await espera(600);
  comprobar(!/^Resumen_semanal/.test(d.title), "restaura el título de la página");
  const css = [...d.querySelectorAll("style")].map(s => s.textContent).join("\n");
  comprobar(/@media print\{[\s\S]*\.side[^}]*display:none/.test(css) && /@page\{size:A4/.test(css), "hoja de estilos de impresión: A4 y sin barra lateral");
  comprobar(d.querySelector(".top.solo-pantalla") !== null, "los controles de pantalla no salen en el PDF");
  comprobar(errores.length === 0, "sin errores de JavaScript" + (errores.length ? ": " + errores.join(" | ") : ""));
  console.log("== 3. Texto hostil en datos del agente y de la base");
  ({ w, d, errores } = cargar(conReporte(`
    MOCK["reporte-semanal"].procesos[0].proceso='<img src=x onerror="window.pwn1=1">';
    MOCK["reporte-semanal"].procesos[0].consecuencia='<script>window.pwn2=1<\\/script>';
    MOCK["reporte-semanal"].top[0].cve='<svg onload=window.pwn3=1>';
    MOCK["reporte-semanal"].top[0].activos=['<a href=javascript:alert(1)>x</a>'];
    MOCK["reporte-semanal"].periodo.semana='<b>W</b>';
    MOCK["reporte-semanal"].top[0].ia='<i>x</i>'`)));
  await espera(1200);
  const r2 = d.getElementById("rep");
  comprobar(r2 && r2.querySelectorAll("img,script,a,iframe,[onerror],[onload],td i").length === 0 && r2.querySelectorAll("svg").length === 1, "ningún elemento creado a partir de los datos");
  comprobar(!w.pwn1 && !w.pwn2 && !w.pwn3, "no se ejecuta código");
  comprobar(/<img src=x/.test(r2.textContent), "el texto hostil se muestra como texto");
  comprobar(errores.length === 0, "sin errores de JavaScript");
  console.log("== 4. Sin análisis del agente y error de la API");
  ({ w, d, errores } = cargar(conReporte(`MOCK["reporte-semanal"].procesos=[];MOCK["reporte-semanal"].agente={disponible:false}`)));
  await espera(1200);
  comprobar(/no está disponible/.test(d.getElementById("rep").textContent), "mensaje claro cuando el agente no está disponible");
  ({ w, d, errores } = cargar(conReporte(`delete MOCK["reporte-semanal"]`)));
  await espera(1200);
  comprobar(/No se pudo preparar el reporte/.test(d.getElementById("rep").textContent) && d.getElementById("rep-pdf").disabled, "error de la API: mensaje y PDF deshabilitado");
  console.log("== 5. El panel sigue igual");
  ({ w, d, errores } = cargar(base, "#panel")); await espera(1500);
  comprobar(d.querySelectorAll(".w").length > 3 && d.querySelectorAll("[data-ase]").length > 0, "el panel y la asesoría siguen funcionando");
  comprobar(d.getElementById("nav-panel").getAttribute("aria-current") === "page" && !d.getElementById("nav-rep").getAttribute("aria-current"), "navegación marca la página correcta");
  comprobar(errores.length === 0, "sin errores de JavaScript");
  console.log(`\n${ok}/${ok + fallas} conformes`); process.exit(fallas ? 1 : 0);
})();
