// Prueba del panel (modo demostración) con jsdom: render, panel lateral, foco y escape de texto hostil.
// El script del panel vive dentro de una IIFE, así que los casos se inyectan sustituyendo los datos de ejemplo.
const fs = require("fs"), { JSDOM, VirtualConsole } = require("jsdom");
const base = fs.readFileSync(process.argv[2], "utf8");
const espera = ms => new Promise(r => setTimeout(r, ms));
let ok = 0, fallas = 0;
const comprobar = (c, t) => { c ? ok++ : fallas++; console.log((c ? "  OK    " : "  FALLA ") + t); };

function cargar(html) {
  const errores = [], vc = new VirtualConsole();
  vc.on("jsdomError", e => { if (!/Could not load|Not implemented: navigation/.test(String(e.message))) errores.push(String(e.message)); });
  vc.on("error", m => errores.push(String(m)));
  const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true, url: "https://panel.ejemplo/#panel",
    virtualConsole: vc, beforeParse(w) {
      w.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
      w.matchMedia = w.matchMedia || (() => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {} }));
    } });
  return { w: dom.window, d: dom.window.document, errores };
}
function conAsesoria(obj) {
  const i = base.indexOf('MOCK["asesoria"]='), j = base.indexOf("};", i) + 2;
  return base.slice(0, i) + 'MOCK["asesoria"]=' + JSON.stringify(obj).replace(/<\//g, "<\\/") + ";" + base.slice(j);
}

(async () => {
  console.log("== 1. Render normal y panel lateral");
  let { w, d, errores } = cargar(base); await espera(1500);
  const botones = d.querySelectorAll("[data-ase]");
  comprobar(botones.length > 0, `la tabla de hallazgos muestra botones "Ver" (${botones.length})`);
  comprobar(d.querySelectorAll(".w").length > 3, `los demás widgets se pintan (${d.querySelectorAll(".w").length})`);
  if (!botones.length) { console.log(errores); process.exit(1); }
  botones[0].click(); await espera(600);
  const panel = d.getElementById("ase");
  comprobar(!!panel && panel.getAttribute("role") === "dialog" && panel.getAttribute("aria-modal") === "true", "panel lateral con role=dialog y aria-modal");
  comprobar(/no vinculante/i.test(panel.textContent), "etiqueta 'Asesoría de IA, no vinculante'");
  comprobar(["Por qué tiene esta prioridad", "Recomendación de urgencia", "Plan de acción propuesto", "Datos por verificar", "Propuesta para el dueño", "Revisión humana"]
    .every(t => panel.textContent.includes(t)), "secciones de la asesoría");
  comprobar(/1 · Cruce/.test(panel.textContent) && /Motor contextual/.test(panel.textContent), "distingue la prioridad del panel (cruce) y la del motor");
  comprobar(/Modelo de negocio en borrador/.test(panel.textContent), "avisa que el modelo de negocio es borrador");
  comprobar(panel.querySelectorAll("button").length === 1, "sin acciones: el único botón es Cerrar");
  comprobar(d.activeElement && d.activeElement.id === "ase-x", "el foco pasa al botón Cerrar");
  d.dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape" })); await espera(50);
  comprobar(!d.getElementById("ase-fondo"), "Escape cierra el panel");
  comprobar(d.activeElement === botones[0], "el foco vuelve al botón que lo abrió");
  botones[0].click(); await espera(400); d.getElementById("ase-fondo").dispatchEvent(new w.MouseEvent("click", { bubbles: true })); await espera(50);
  comprobar(!d.getElementById("ase-fondo"), "clic fuera cierra el panel");
  comprobar(errores.length === 0, "sin errores de JavaScript" + (errores.length ? ": " + errores.join(" | ") : ""));

  console.log("== 2. Texto hostil del agente");
  ({ w, d, errores } = cargar(conAsesoria({ disponible: true, vigente: false, corrida_id: "x", modelo: "<b>m</b>", confianza: 0.4,
    motor: { prioridad_final: 1, tipo: "investigacion", version: "<img src=x onerror=window.pwned1=1>" },
    explicacion: '<img src=x onerror="window.pwned2=1">', recomendacion: { efectiva: "<svg onload=window.pwned3=1>", justificacion: "<script>window.pwned4=1</script>" },
    escenario: { amenaza: "<a href=javascript:alert(1)>x</a>", tecnicas: ["<i>T</i>"] },
    plan: [{ tipo: "<u>t</u>", descripcion: "<iframe src=//mal></iframe>" }], controles: [], datos_a_verificar: [{ ruta_campo: "<b>r</b>", motivo: "<b>m</b>" }],
    observaciones: [], propuesta_dueno: { probabilidad: "<b>3</b>", impacto: 2, estado: "<b>e</b>" },
    revision: { requerida: true, prioridad: "<b>alta</b>", motivos: ["<b>z</b>"] }, contexto_negocio: { version: "<b>v</b>", aprobado: false } })));
  await espera(1500); d.querySelectorAll("[data-ase]")[0].click(); await espera(600);
  const c = d.getElementById("ase-c"); if (process.env.DBG) console.log("DBG:", c.textContent.slice(0, 400), errores);
  comprobar(c.querySelectorAll("img,script,iframe,a,u,i,svg").length === 0, "ningún elemento creado a partir del texto del agente");
  comprobar(!w.pwned1 && !w.pwned2 && !w.pwned3 && !w.pwned4, "no se ejecuta código");
  comprobar(c.textContent.includes('<img src=x onerror="window.pwned2=1">'), "el texto hostil se muestra literal");
  comprobar(/De una corrida anterior/.test(c.textContent), "avisa cuando la asesoría es de una corrida anterior");

  console.log("== 3. Sin asesoría disponible");
  ({ w, d, errores } = cargar(conAsesoria({ disponible: false, motivo: "El agente no ha asesorado este hallazgo <b>aún</b>" })));
  await espera(1500); d.querySelectorAll("[data-ase]")[0].click(); await espera(600);
  const c3 = d.getElementById("ase-c");
  comprobar(/no ha asesorado/.test(c3.textContent) && !c3.querySelector("b"), "muestra el motivo, también escapado");

  console.log("== 4. Evolución de la prioridad en cuatro etapas (reglas acordadas con el motor)");
  const etapas4 = async (obj) => { const r = cargar(obj ? conAsesoria(obj) : base); await espera(1500);
    r.d.querySelectorAll("[data-ase]")[0].click(); await espera(600); return r; };
  ({ w, d, errores } = await etapas4(null));
  let et = [...d.querySelectorAll("#ase-c .ase-et > div")];
  comprobar(et.length === 4, `4 etapas (${et.length})`);
  const tit = et.map(x => x.querySelector(".et-t").textContent);
  comprobar(/Cruce/.test(tit[0]) && /Motor/.test(tit[1]) && /agente/.test(tit[2]) && /dueño/.test(tit[3]), "orden: cruce, motor, agente, dueño");
  const est = et.map(x => x.children[2].textContent);
  comprobar(est[0] === "Oficial" && est[1] === "Sombra" && est[3] === "Pendiente", `estados distinguidos (${est.join(" / ")})`);
  comprobar(est[2] === "Condicionado" && !/P[1-4]/.test(et[2].querySelector(".et-v").textContent), "aplicabilidad condicionada: sin prioridad simulada");
  comprobar(et[2].classList.contains("et-hip"), "la etapa del agente se distingue visualmente (hipotética)");
  comprobar(!/P[1-4]|Crítica|Alta|Media|Baja/.test(et[3].querySelector(".et-v").textContent), "sin decisión del dueño: sin prioridad");
  const demo = d.querySelector("#ase-c details.ase-demo");
  comprobar(!!demo && /sintético/i.test(demo.textContent) && /No es un hallazgo real ni una aprobación real/.test(demo.textContent), "el ejemplo sintético está rotulado y separado");
  comprobar(errores.length === 0, "sin errores de JavaScript");
  ({ w, d, errores } = await etapas4({ disponible: true, vigente: true, corrida_id: "x", modelo: "m", confianza: 0.6,
    motor: { prioridad_final: 2, tipo: "tratamiento", version: "v" }, explicacion: "e", recomendacion: { efectiva: "mantener" },
    escenario: {}, plan: [], controles: [], datos_a_verificar: [], observaciones: [],
    propuesta_dueno: { probabilidad: 2, impacto: 3, condicion: null, estado: "pendiente_aprobacion_dueno" },
    revision: { requerida: true, prioridad: "normal", motivos: [] }, contexto_negocio: { version: "lyft-2026.11-v1", aprobado: true } }));
  et = [...d.querySelectorAll("#ase-c .ase-et > div")];
  comprobar(/Sin escenario/.test(et[2].textContent) && !/P[1-4] ·/.test(et[2].textContent), "aplicabilidad confirmada sin simulador: «sin escenario», nunca una prioridad");
  comprobar(/P 2 × I 3/.test(et[2].textContent) && /no vinculante/.test(et[2].textContent), "muestra la propuesta P × I como no vinculante");
  comprobar(!/Modelo de negocio en borrador/.test(d.getElementById("ase-c").textContent), "con el modelo v1 aprobado ya no avisa «borrador»");

  console.log(`\nRESULTADO: ${ok} conformes, ${fallas} fallas`);
  process.exit(fallas ? 1 : 0);
})();
