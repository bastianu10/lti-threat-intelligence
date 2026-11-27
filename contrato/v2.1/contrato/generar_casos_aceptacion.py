"""Genera los casos de aceptacion compartidos (contrato/casos_aceptacion/*.json).

Cada caso = una salida del motor con UNA evaluacion (`motor`) + lo esperado del adaptador (`esperado`).
Hoy `motor` se deriva de la salida simulada v1.3.3. El equipo del motor sustituye `motor` por la salida REAL
de su candidato para cada escenario; `esperado` no cambia: es el contrato.
"""
import copy
import json
import pathlib
import sys

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
MOTOR = json.loads((RAIZ / "insumos" / "motor-v1.3.3.json").read_text())
DESTINO = RAIZ / "contrato" / "casos_aceptacion"
TRIP = "53616cce-e721-4f80-a4e1-0df03349b980"      # CVE-2026-39819 en trip-service, P3, sin KEV
AUTH = "25cab4bf-0cb7-4085-a22c-34dd8649b22b"      # CVE-2026-111497 en auth-oidc, KEV


def base(case_id=TRIP):
    m = copy.deepcopy(MOTOR)
    m["evaluaciones"] = [copy.deepcopy(next(e for e in MOTOR["evaluaciones"] if e["resultado"]["case_id"] == case_id))]
    m.pop("_simulado", None)
    return m, m["evaluaciones"][0]


def caso(cid, descripcion, motor, esperado, modo_demo=True):
    return cid, {"id": cid, "descripcion": descripcion, "modo_demo": modo_demo,
                 "fuente_motor": "simulado v1.3.3 (sustituir por la salida real del candidato)",
                 "motor": motor, "esperado": esperado}


casos = []

m, e = base()
e["cruce"] = None
e["cruce_motivo_ausencia"] = "sin_historial"
casos.append(caso("CA-01", "Sin historial del cruce: el caso se envia sin comparacion previa", m,
                  {"resultado": "entrada", "campos": {"comparacion_previa.disponible": False,
                   "comparacion_previa.motivo": "sin_historial", "evaluacion_determinista.prioridad_base": None}}))

m, e = base()
e["contexto_agente"]["en_kev"] = False
e["contexto_agente"]["verificacion"]["kev"] = {"estado": "desconocido", "fuente": "cisa_kev", "referencia": None,
                                               "fecha_verificacion": None, "metodo": None}
casos.append(caso("CA-02", "KEV no comprobado con en_kev=false: no equivale a 'fuera de KEV'", m,
                  {"resultado": "entrada", "campos": {"vulnerabilidad.kev.valor": None,
                   "vulnerabilidad.kev.estado_verificacion": "desconocido"}}))

m, e = base()
m["fuentes_no_lectura"] = ["despliegue_dependencias"]
e["contexto_agente"]["dependientes_directos"] = None
e["contexto_agente"]["verificacion"]["dependencias"] = {"estado": "no_consultable", "fuente": "despliegue_dependencias",
                                                        "referencia": None, "fecha_verificacion": None, "metodo": None}
casos.append(caso("CA-03", "Dependencias no consultables: null, nunca cero", m,
                  {"resultado": "entrada", "campos": {"despliegue.dependencias.valor": None,
                   "despliegue.dependencias.estado_verificacion": "no_consultable"},
                   "advertencias_incluye": ["DEPENDENCIAS_NO_VERIFICADAS"]}))

m, e = base()
e["contexto_agente"]["inventario_estado"] = "no_vigente"
e["contexto_agente"]["verificacion"]["inventario"] = {"estado": "verificado", "fuente": "recertificaciones",
                                                      "referencia": None, "fecha_verificacion": "2026-06-01",
                                                      "metodo": "recertificacion"}
casos.append(caso("CA-04", "Recertificacion no vigente declarada como verificada: se degrada", m,
                  {"resultado": "entrada", "campos": {"inventario.valor": "no_vigente",
                   "inventario.estado_verificacion": "declarado_sin_evidencia"},
                   "advertencias_incluye": ["VERIFICACION_DEGRADADA_INVENTARIO"]}))

m, e = base()
e["contexto_agente"]["en_kev"] = True
e["contexto_agente"]["kev_fecha_limite"] = "2026-12-09"
e["resultado"].update(prioridad_operativa="P3", prioridad_final=1, prioridad_piso_efectivo=1, origen_piso="kev")
casos.append(caso("CA-05", "Pisos: el motor evalua P3 pero aplica el piso KEV y entrega P1", m,
                  {"resultado": "entrada", "campos": {"evaluacion_determinista.prioridad_final": 1,
                   "evaluacion_determinista.prioridad_piso_efectivo": 1, "evaluacion_determinista.origen_piso": "kev",
                   "evaluacion_determinista.origen": "motor"}}))

m, e = base(AUTH)
e["resultado"].update(prioridad_final=2, prioridad_piso_efectivo=1, origen_piso="kev")
casos.append(caso("CA-06", "El motor entrega una prioridad final que perfora su piso: inconsistencia", m,
                  {"resultado": "error", "error": "InconsistenciaMotor"}))

m, e = base()
e["contexto_agente"]["epss_fecha"] = "2026-11-25"
casos.append(caso("CA-07", "EPSS con fecha posterior a la evaluacion", m,
                  {"resultado": "entrada", "campos": {"vulnerabilidad.epss.estado_verificacion": "desconocido"},
                   "advertencias_incluye": ["EPSS_FECHA_POSTERIOR_A_EVALUACION"]}))

m, e = base()
e["contexto_agente"]["epss_percentil"] = None
casos.append(caso("CA-08", "EPSS sin percentil: no se rellena con 0.0", m,
                  {"resultado": "entrada", "campos": {"vulnerabilidad.epss.valor": None,
                   "vulnerabilidad.epss.estado_verificacion": "desconocido"}}))

m, e = base(AUTH)
e["contexto_agente"]["verificacion"]["exposicion"] = {"estado": "verificado", "fuente": "cmdb",
                                                      "referencia": "https://nvd.nist.gov/ejemplo",
                                                      "fecha_verificacion": None, "metodo": "observacion_cmdb"}
casos.append(caso("CA-09", "Exposicion con referencia pero sin fecha: no es verificada", m,
                  {"resultado": "entrada", "campos": {"despliegue.exposicion.estado_verificacion": "declarado_sin_evidencia"},
                   "advertencias_incluye": ["VERIFICACION_DEGRADADA_EXPOSICION"]}))

m, e = base()
m["tenant_id"] = e["resultado"]["tenant_id"] = "22222222-2222-2222-2222-222222222222"
casos.append(caso("CA-10", "Tenant distinto del tenant del servicio", m, {"resultado": "error", "error": "DatoFaltante"}))

m, e = base()
e["resultado"]["accion_automatica_autorizada"] = True
casos.append(caso("CA-11", "accion_automatica_autorizada=true", m, {"resultado": "error", "error": "DatoFaltante"}))

m, e = base()
e["resultado"].update(estado_aplicabilidad="confirmed", prioridad_tipo="tratamiento")
casos.append(caso("CA-12", "Caso no enrutado en produccion: P3 confirmado sin KEV recibe explicacion determinista", m,
                  {"resultado": "no_enviado"}, modo_demo=False))

m, e = base()
m["politica_verificacion"] = {"version": "otra", "sha256": "0" * 64}
casos.append(caso("CA-13", "El motor aplico otra version de politica-verificacion", m,
                  {"resultado": "error", "error": "DatoFaltante"}))

m, e = base()
for k in ("prioridad_final", "prioridad_piso_efectivo", "origen_piso"):
    e["resultado"].pop(k, None)
casos.append(caso("CA-14", "Salida con la forma de v1.3.2.1 (sin prioridad_final): el adaptador no recalcula", m,
                  {"resultado": "error", "error": "DatoFaltante"}))

if __name__ == "__main__":
    DESTINO.mkdir(parents=True, exist_ok=True)
    for viejo in DESTINO.glob("CA-*.json"):
        viejo.unlink()
    for cid, contenido in casos:
        (DESTINO / f"{cid}.json").write_text(json.dumps(contenido, ensure_ascii=False, indent=1))
        print(f"OK {cid}  {contenido['descripcion']}")
