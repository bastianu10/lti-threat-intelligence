"""Ejecutor de los casos de aceptacion compartidos (equipo del motor y equipo Bedrock).

Uso:
    python3 contrato/ejecutar_aceptacion.py                      # casos CA-* + invariante INV-01
    python3 contrato/ejecutar_aceptacion.py --motor salida.json  # ademas, INV-01 sobre una salida real completa

Solo biblioteca estandar. No usa red ni AWS.
"""
import argparse
import copy
import json
import pathlib
import sys

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
from agente_priorizacion.adaptador_v2_1 import DatoFaltante, InconsistenciaMotor, construir_entrada  # noqa: E402
from agente_priorizacion.output_guard_v2_1 import aplicar, validar_entrada  # noqa: E402

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


def invariante(motor):
    """INV-01: toda evaluacion conserva su prioridad determinista, se envie o no al agente."""
    fallas, enviados = [], 0
    for e in motor["evaluaciones"]:
        hid, final_motor = e["resultado"]["case_id"], e["resultado"].get("prioridad_final")
        antes = copy.deepcopy(e)
        try:
            entrada = construir_entrada(motor, e, MODELO, tenant_id=motor["tenant_id"], modo_demo=True)
        except DatoFaltante:
            entrada = None
        if e != antes:
            fallas.append(f"{hid}: el adaptador modifico la evaluacion")
        if entrada is None:
            continue
        enviados += 1
        if entrada["evaluacion_determinista"]["prioridad_final"] != final_motor:
            fallas.append(f"{hid}: la entrada cambio la prioridad del motor")
        for direccion in ("escalar", "mantener", "revisar_a_la_baja"):
            r = aplicar(entrada, salida_minima(entrada, direccion), tenant_autorizado=motor["tenant_id"])
            if r["prioridad"]["final"] != final_motor or r.get("persistir_en_evaluaciones", False):
                fallas.append(f"{hid}: con '{direccion}' el guard altero la prioridad o pidio persistir")
    return fallas, enviados


MOTOR_TENANT = "11111111-1111-1111-1111-111111111111"

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--motor", help="salida completa del motor para la invariante INV-01")
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
    fallas, enviados = invariante(motor)
    total += 1
    ok += not fallas
    print(f"{'PASA ' if not fallas else 'FALLA'}  INV-01  Las {len(motor['evaluaciones'])} evaluaciones conservan su "
          f"prioridad determinista ({enviados} enviadas al agente)")
    for f in fallas:
        print(f"         - {f}")
    print(f"\n{ok}/{total} casos de aceptacion pasan")
    sys.exit(0 if ok == total else 1)
