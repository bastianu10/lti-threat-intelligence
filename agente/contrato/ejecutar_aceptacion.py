"""Ejecutor de los casos de aceptacion compartidos (equipo del motor y equipo Bedrock).

Uso:
    python3 contrato/ejecutar_aceptacion.py                      # casos CA-* + invariante INV-01
    python3 contrato/ejecutar_aceptacion.py --motor salida.json  # ademas, INV-01, INV-02 e INV-03 sobre una salida real

Solo biblioteca estandar. No usa red ni AWS.
"""
import argparse
import copy
import json
import pathlib
import sys

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
from agente_priorizacion.adaptador_v2_1 import ESTADOS_ENVIABLES, DatoFaltante, InconsistenciaMotor, construir_entrada  # noqa: E402
from agente_priorizacion.output_guard_v2_1 import EntradaInvalida, aplicar, validar_entrada  # noqa: E402

CASOS = RAIZ / "contrato" / "casos_aceptacion"
MODELO = json.loads((RAIZ / "contexto" / "modelo_negocio_lyft.json").read_text())


def leer(obj, ruta):
    for parte in ruta.split("."):
        obj = obj[parte]
    return obj


def salida_minima(entrada, direccion):
    """Una respuesta del agente valida en forma, para comprobar que el guard nunca mueve la prioridad."""
    ids = [x["id"] for x in entrada["evidencias"]]
    return {"schema_version": "agente-salida-v2", "hallazgo_id": entrada["hallazgo"]["hallazgo_id"],
            "escenario_riesgo": {"amenaza": "Actor externo", "vector_ataque": "Red", "proceso_negocio_afectado": "Proceso",
                                 "consecuencia_negocio": "Afectacion del servicio", "tecnicas_attack": []},
            "valoracion_negocio": {"probabilidad": {"valor": 1, "horizonte": "12m", "justificacion": "Prueba", "evidencias": ids[:1]},
                                   "impacto": {"valor": 1, "dimensiones": ["A"], "justificacion": "Prueba", "evidencias": ids[:1]}},
            "recomendacion_urgencia": {"direccion": direccion, "justificacion": "Prueba", "evidencias": ids[:1]},
            "datos_a_verificar": [], "observaciones_para_revision": [], "controles_sugeridos": [],
            "plan_accion": [{"orden": 1, "tipo": "verificacion", "descripcion": "Verificar la version"}],
            "mitigacion_temporal": "Restringir", "explicacion_dashboard": "Explicacion de prueba para el dashboard.",
            "senales": [], "confianza": 0.6}


def ejecutar_caso(c):
    motor, esperado = c["motor"], c["esperado"]
    original = copy.deepcopy(motor)
    try:
        entrada = construir_entrada(motor, motor["evaluaciones"][0], MODELO, tenant_id=c.get("tenant_servicio", MOTOR_TENANT),
                                    modo_demo=c["modo_demo"])
        error = None
    except InconsistenciaMotor:
        entrada, error = None, "InconsistenciaMotor"
    except DatoFaltante:
        entrada, error = None, "DatoFaltante"
    fallas = []
    if motor != original:
        fallas.append("el adaptador modifico la salida del motor")
    if esperado["resultado"] == "error":
        if error != esperado["error"]:
            fallas.append(f"se esperaba {esperado['error']}, se obtuvo {error or 'una entrada'}")
        return fallas
    if error:
        return fallas + [f"error inesperado {error}"]
    if esperado["resultado"] == "no_enviado":
        return fallas + ([] if entrada is None else ["se esperaba no enviar el caso"])
    if entrada is None:
        return fallas + ["se esperaba una entrada y el caso no se envio"]
    errores = validar_entrada(entrada)
    if errores:
        fallas.append("la entrada no cumple el esquema v2.1: " + "; ".join(errores[:3]))
    for ruta, valor in esperado.get("campos", {}).items():
        real = leer(entrada, ruta)
        if real != valor or type(real) is not type(valor):
            fallas.append(f"{ruta} = {real!r} (se esperaba {valor!r})")
    for codigo in esperado.get("advertencias_incluye", []):
        if codigo not in entrada["evaluacion_determinista"]["advertencias"]:
            fallas.append(f"falta la advertencia {codigo}")
    return fallas


# Rechazos que afectan al LOTE completo: no son una justificacion individual de omision.
RECHAZOS_DE_LOTE = ("tenant del motor distinto", "modelo de negocio pertenece a otro tenant",
                    "falta contexto_agente", "accion_automatica_autorizada", "politica-verificacion")


def _decision(motor, e, modo_demo):
    """Decision del adaptador para UNA evaluacion: (tipo, codigo, detalle, entrada)."""
    r = e["resultado"]
    try:
        entrada = construir_entrada(motor, e, MODELO, tenant_id=motor["tenant_id"], modo_demo=modo_demo)
    except InconsistenciaMotor as x:          # subclase de DatoFaltante: debe capturarse primero
        return "inconsistencia", "INCONSISTENCIA_MOTOR", str(x), None
    except DatoFaltante as x:
        lote = any(t in str(x) for t in RECHAZOS_DE_LOTE)
        return ("rechazo_lote" if lote else "omitido"), "DATO_FALTANTE", str(x), None
    if entrada is not None:
        return "enviado", entrada["motivo_envio"]["codigo"], "", entrada
    if r.get("estado_evaluacion") in ("excluded", "planned_asset") or r.get("estado_aplicabilidad") not in ESTADOS_ENVIABLES:
        return "omitido", "ESTADO_NO_ENVIABLE", f"{r.get('estado_aplicabilidad')}/{r.get('estado_evaluacion')}", None
    return "omitido", "NO_ENRUTADO", (f"P{r.get('prioridad_final')} {r.get('estado_aplicabilidad')}, sin KEV: "
                                      "explicacion determinista (politica enrutamiento-v1)"), None


def invariante(motor):
    """INV-01: toda evaluacion conserva su prioridad determinista, se envie o no al agente.
    Devuelve ademas el reporte de cobertura por hallazgo (INV-03)."""
    fallas, enviados, rechazos, reporte = [], 0, {}, []
    for e in motor["evaluaciones"]:
        r = e["resultado"]
        hid, final_motor = r["case_id"], r.get("prioridad_final")
        antes = copy.deepcopy(e)
        tipo_demo, cod_demo, det_demo, entrada = _decision(motor, e, True)
        tipo_prod, cod_prod, det_prod, _ = _decision(motor, e, False)
        if e != antes:
            fallas.append(f"{hid}: el adaptador modifico la evaluacion")
        fila = {"hallazgo_id": hid, "cve": r.get("cve"), "prioridad_motor": final_motor,
                "piso": r.get("prioridad_piso_efectivo"), "origen_piso": r.get("origen_piso"),
                "tipo_prioridad": r.get("prioridad_tipo"),
                "produccion": {"decision": tipo_prod, "codigo": cod_prod, "detalle": det_prod},
                "demostracion": {"decision": tipo_demo, "codigo": cod_demo, "detalle": det_demo},
                "prioridad_tras_guard": {}}
        reporte.append(fila)
        if "inconsistencia" in (tipo_demo, tipo_prod):
            fallas.append(f"{hid}: inconsistencia del motor: {det_demo or det_prod}")
        if entrada is None:
            if tipo_demo != "inconsistencia":
                rechazos[det_demo or cod_demo] = rechazos.get(det_demo or cod_demo, 0) + 1
            continue
        enviados += 1
        if entrada["evaluacion_determinista"]["prioridad_final"] != final_motor:
            fallas.append(f"{hid}: la entrada cambio la prioridad del motor")
        for direccion in ("escalar", "mantener", "revisar_a_la_baja"):
            try:
                res = aplicar(entrada, salida_minima(entrada, direccion), tenant_autorizado=motor["tenant_id"])
            except EntradaInvalida as x:
                fallas.append(f"{hid}: la entrada construida no cumple el esquema v2.1: {str(x)[:160]}")
                break
            fila["prioridad_tras_guard"][direccion] = res["prioridad"]["final"]
            if res["prioridad"]["final"] != final_motor or res.get("persistir_en_evaluaciones", False):
                fallas.append(f"{hid}: con '{direccion}' el guard altero la prioridad o pidio persistir")
    return fallas, enviados, rechazos, reporte


def cobertura_individual(motor, reporte):
    """INV-03: cada hallazgo tiene un veredicto propio y toda omision esta justificada individualmente."""
    fallas = []
    ids = [f["hallazgo_id"] for f in reporte]
    if len(set(ids)) != len(ids):
        fallas.append("hallazgo_id repetido en evaluaciones")
    errores = motor.get("errores") or []
    for x in errores:
        fallas.append(f"{x.get('hallazgo_id', '?')}: el motor no lo evaluo ({x.get('error_tipo')}: {x.get('detalle', '')})")
    leidos, evaluados = motor.get("total_leidos"), motor.get("total_evaluados")
    if evaluados is not None and evaluados != len(reporte):
        fallas.append(f"total_evaluados={evaluados} pero el archivo trae {len(reporte)} evaluaciones")
    if leidos is not None and leidos != len(reporte) + len(errores):
        fallas.append(f"total_leidos={leidos} no cuadra con {len(reporte)} evaluadas + {len(errores)} errores")
    for f in reporte:
        for modo in ("produccion", "demostracion"):
            d = f[modo]
            if d["decision"] == "rechazo_lote":
                fallas.append(f"{f['hallazgo_id']} ({modo}): omision por defecto de lote, no individual: {d['detalle']}")
            elif d["decision"] == "omitido" and not d["detalle"]:
                fallas.append(f"{f['hallazgo_id']} ({modo}): omision sin justificacion")
    return fallas


def imprimir_reporte(reporte):
    print("\nReporte de cobertura por hallazgo (INV-03)")
    print(f"  {'hallazgo':10} {'CVE':16} {'motor':6} {'piso':10} {'produccion':28} {'demo':20} guard e/m/b")
    for f in reporte:
        piso = f"P{f['piso']}/{f['origen_piso']}" if f["piso"] else "-"
        g = f["prioridad_tras_guard"]
        guard = "/".join(f"P{g[k]}" for k in ("escalar", "mantener", "revisar_a_la_baja")) if g else "-"
        prod = f"{f['produccion']['decision']}:{f['produccion']['codigo']}"
        demo = f"{f['demostracion']['decision']}:{f['demostracion']['codigo']}"
        print(f"  {f['hallazgo_id'][:8]:10} {str(f['cve'])[:16]:16} P{f['prioridad_motor']!s:5} {piso:10} {prod[:28]:28} {demo[:20]:20} {guard}")
        for modo in ("produccion", "demostracion"):
            if f[modo]["decision"] != "enviado" and f[modo]["detalle"]:
                print(f"  {'':10} {modo}: {f[modo]['detalle'][:120]}")


MOTOR_TENANT = "11111111-1111-1111-1111-111111111111"

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--motor", help="salida completa del motor para la invariante INV-01")
    ap.add_argument("--reporte", help="ruta JSON donde guardar el reporte de cobertura por hallazgo (requiere --motor)")
    args = ap.parse_args()
    total = ok = 0
    for ruta in sorted(CASOS.glob("CA-*.json")):
        c = json.loads(ruta.read_text())
        fallas = ejecutar_caso(c)
        total += 1
        ok += not fallas
        print(f"{'PASA ' if not fallas else 'FALLA'}  {c['id']}  {c['descripcion']}")
        for f in fallas:
            print(f"         - {f}")
    motor = json.loads(pathlib.Path(args.motor).read_text()) if args.motor else \
        json.loads((RAIZ / "insumos" / "motor-v1.3.3.json").read_text())
    fallas, enviados, rechazos, reporte = invariante(motor)
    total += 1
    ok += not fallas
    print(f"{'PASA ' if not fallas else 'FALLA'}  INV-01  Las {len(motor['evaluaciones'])} evaluaciones conservan su "
          f"prioridad determinista ({enviados} enviadas al agente)")
    for f in fallas:
        print(f"         - {f}")
    if args.motor:
        # INV-02: con una salida real, la invariante no puede pasar en vacio. Un rechazo que
        # alcanza a TODAS las evaluaciones es un defecto de lote (politica, tenant, forma), no de caso.
        total += 1
        cobertura = enviados > 0
        ok += cobertura
        print(f"{'PASA ' if cobertura else 'FALLA'}  INV-02  Cobertura: al menos una evaluacion real llega al agente "
              f"({enviados}/{len(motor['evaluaciones'])})")
        for motivo, n in sorted(rechazos.items(), key=lambda kv: -kv[1]):
            print(f"         - rechazadas {n}: {motivo}")
        fallas3 = cobertura_individual(motor, reporte)
        total += 1
        ok += not fallas3
        print(f"{'PASA ' if not fallas3 else 'FALLA'}  INV-03  Cobertura individual: {len(reporte)} hallazgos con veredicto propio "
              f"y omisiones justificadas una por una")
        for f in fallas3:
            print(f"         - {f}")
        imprimir_reporte(reporte)
        if args.reporte:
            pathlib.Path(args.reporte).write_text(json.dumps(reporte, ensure_ascii=False, indent=2))
            print(f"\nReporte guardado en {args.reporte}")
    print(f"\n{ok}/{total} casos de aceptacion pasan")
    sys.exit(0 if ok == total else 1)
