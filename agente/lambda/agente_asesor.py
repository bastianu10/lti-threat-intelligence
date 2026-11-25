"""Lambda `lti-agente-asesor` v2.1: agente de priorizacion ASISTIDA (Bedrock Converse + Guardrail + output guard v2.1).

Contrato v2.1 acordado con el equipo del motor: el motor es la unica autoridad de la prioridad final, sus pisos y los
estados de verificacion (politica-verificacion-v1); el adaptador valida y solo degrada.

Corre FUERA de la VPC y sin credenciales de base de datos: si una inyeccion de prompt tuviera exito, solo
podria afectar un texto que despues valida el guard. Lo invoca Step Functions despues de VerificarMotor.

Acciones (lista blanca):
  {"accion": "listar",   "corrida_id", "archivo_sombra": {bucket, key, sha256}, "modo_demo": bool}
      -> {"casos": [hallazgo_id, ...], "omitidos": n}       (ids que el enrutamiento envia al agente)
  {"accion": "asesorar", "corrida_id", "archivo_sombra", "hallazgo_id", "modo_demo": bool}
      -> resumen pequeno; el resultado completo queda en S3 curada agente/<tenant>/<corrida>/<hallazgo>-<sha>.json

Defensa en capas por caso:
  1. Integridad: el archivo del motor debe venir del bucket EXACTO del motor, bajo
     risk-engine-shadow/, y su SHA-256 debe coincidir con el que reporto el motor.
  2. Adaptador v2.1: valida la prioridad del motor y degrada estados sin evidencia; DatoFaltante -> no se envia.
  3. Guardrail (ApplyGuardrail, INPUT) sobre los textos de terceros: si interviene, NO se invoca al modelo.
  4. Bedrock Converse con salida estructurada FORZADA (herramienta registrar_evaluacion).
  5. Output guard v2 (determinista): valida el contrato; la prioridad siempre es la del motor.
  6. Guardrail (ApplyGuardrail, OUTPUT) sobre los textos generados (PII y credenciales).
Cualquier fallo conserva la evaluacion determinista: el caso queda "sin_asesoria" con su motivo.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
import re
import time
from typing import Any

from agente_priorizacion.adaptador_v2_1 import DatoFaltante, InconsistenciaMotor, cargar_politica, construir_entrada
from agente_priorizacion.output_guard_v2_1 import VERSION_GUARD, EntradaInvalida, aplicar
from agente_priorizacion.herramienta import HERRAMIENTA, config_herramienta
from agente_priorizacion.coherencia import marcar_dominio, marcar_texto, normalizar_escalar

log = logging.getLogger()
log.setLevel(logging.INFO)

RAIZ = pathlib.Path(__file__).resolve().parent
MAX_CASOS = 50
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RE_SHA = re.compile(r"^[0-9a-f]{64}$")
# O-3 (24-nov): reutilizacion de asesorias. Si los datos del caso no cambiaron, no se vuelve a llamar a Bedrock.
REUSO_DIAS = float(os.environ.get("REUSO_DIAS", "5"))      # < 7: el panel y el notificador leen 7 dias
VOLATILES = (("corrida_id",), ("trazabilidad", "evaluacion_sha256"), ("trazabilidad", "snapshot_id"),
             ("comparacion_previa", "fecha"), ("comparacion_previa", "corrida_id_origen"),
             ("comparacion_previa", "misma_corrida"))
RE_INSTANTE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?")

_clientes: dict[str, Any] = {}
POLITICA = cargar_politica()


def _cliente(nombre: str):
    """Clientes perezosos e inyectables (las pruebas los sustituyen)."""
    if nombre not in _clientes:
        import boto3
        from botocore.config import Config
        cfg = Config(retries={"max_attempts": 3, "mode": "adaptive"}, read_timeout=90, connect_timeout=5)
        _clientes[nombre] = boto3.client(nombre, config=cfg)
    return _clientes[nombre]


def _cfg() -> dict:
    return {
        "tenant": os.environ["TENANT_ID"],
        "bucket_motor": os.environ["BUCKET_MOTOR"],     # nombre exacto del bucket del motor
        "bucket_curada": os.environ["BUCKET_CURADA"],
        "modelo": os.environ.get("MODELO_ID", "us.anthropic.claude-sonnet-4-6"),
        "guardrail_id": os.environ["GUARDRAIL_ID"],
        "guardrail_version": os.environ["GUARDRAIL_VERSION"],
        "max_tokens": int(os.environ.get("MAX_TOKENS", "6000")),
        "prompt": os.environ.get("PROMPT_ARCHIVO", "sistema_v2_8.md"),
    }


# La configuracion de la herramienta (con el enum de direccion acotado por caso) vive en agente_priorizacion.herramienta,
# compartida con las pruebas doradas para que ambas usen exactamente la misma restriccion.


# ------------------------------------------------------------------------------------- integridad

def _leer_archivo_motor(cfg: dict, evento: dict) -> dict:
    a = evento.get("archivo_sombra")
    if not isinstance(a, dict):
        raise ValueError("archivo_sombra ausente")
    bucket, key, sha = a.get("bucket"), a.get("key"), a.get("sha256")
    if bucket != cfg["bucket_motor"]:
        raise ValueError("bucket del motor no autorizado")
    if not (isinstance(key, str) and key.startswith("risk-engine-shadow/") and ".." not in key):
        raise ValueError("clave fuera del prefijo del motor")
    if not (isinstance(sha, str) and RE_SHA.match(sha) and sha in key):
        raise ValueError("sha256 invalido o no coincide con el nombre del archivo")
    cuerpo = _cliente("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
    if hashlib.sha256(cuerpo).hexdigest() != sha:
        raise ValueError("integridad: el SHA-256 del archivo no coincide con el reportado por el motor")
    motor = json.loads(cuerpo)
    if motor.get("tenant_id") != cfg["tenant"]:
        raise ValueError("tenant del archivo distinto del tenant del servicio")
    if motor.get("corrida_id") != evento.get("corrida_id"):
        raise ValueError("corrida del archivo distinta de la corrida en curso")
    return motor


def _modelo_negocio(cfg: dict) -> dict:
    key = f"contexto/{cfg['tenant']}.json"
    return json.loads(_cliente("s3").get_object(Bucket=cfg["bucket_curada"], Key=key)["Body"].read())


# ------------------------------------------------------------------------------------- bedrock

def _textos_terceros(entrada: dict) -> str:
    partes = [entrada["vulnerabilidad"]["descripcion_no_confiable"]]
    partes += [x["descripcion"] for x in entrada["evidencias"] if x["tipo"] == "precedente"]
    return "\n".join(p for p in partes if p)[:20000]


def _guardrail(cfg: dict, texto: str, fuente: str) -> tuple[bool, list[str]]:
    """Devuelve (intervino, politicas). fuente = INPUT | OUTPUT."""
    if not texto.strip():
        return False, []
    r = _cliente("bedrock-runtime").apply_guardrail(
        guardrailIdentifier=cfg["guardrail_id"], guardrailVersion=cfg["guardrail_version"],
        source=fuente, content=[{"text": {"text": texto}}])
    if r.get("action") != "GUARDRAIL_INTERVENED":
        return False, []
    politicas = []
    for a in r.get("assessments", []):
        politicas += [f["type"] for f in a.get("contentPolicy", {}).get("filters", [])]
        politicas += [p["type"] for p in a.get("sensitiveInformationPolicy", {}).get("piiEntities", [])]
    return True, sorted(set(politicas))


def _mensaje(entrada: dict) -> str:
    datos = json.dumps(entrada, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e")
    return ("Evalúa el siguiente hallazgo y responde llamando a la herramienta registrar_evaluacion.\n"
            f"<entrada_hallazgo>\n{datos}\n</entrada_hallazgo>")


def _invocar_modelo(cfg: dict, prompt: str, entrada: dict) -> tuple[Any, dict]:
    t0 = time.time()
    r = _cliente("bedrock-runtime").converse(
        modelId=cfg["modelo"], system=[{"text": prompt}],
        messages=[{"role": "user", "content": [{"text": _mensaje(entrada)}]}],
        toolConfig=config_herramienta(entrada), inferenceConfig={"maxTokens": cfg["max_tokens"], "temperature": 0})
    meta = {"stop": r.get("stopReason"), "uso": r.get("usage", {}), "latencia_ms": int((time.time() - t0) * 1000)}
    for b in r["output"]["message"]["content"]:
        if "toolUse" in b and b["toolUse"].get("name") == HERRAMIENTA:
            return b["toolUse"]["input"], meta
    return "".join(b.get("text", "") for b in r["output"]["message"]["content"]), meta


def _textos_generados(salida: dict) -> str:
    claves = ("amenaza", "vector_ataque", "proceso_negocio_afectado", "consecuencia_negocio", "justificacion",
              "observacion", "descripcion", "mitigacion_temporal", "explicacion_dashboard", "motivo")

    def recorrer(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and k in claves:
                    yield v
                else:
                    yield from recorrer(v)
        elif isinstance(o, list):
            for v in o:
                yield from recorrer(v)
    return "\n".join(recorrer(salida))


# ------------------------------------------------------------------------------------- acciones

def _listar(cfg: dict, evento: dict) -> dict:
    motor = _leer_archivo_motor(cfg, evento)
    modelo = _modelo_negocio(cfg)
    casos, omitidos = [], 0
    for ev in motor.get("evaluaciones", []):
        try:
            if construir_entrada(motor, ev, modelo, tenant_id=cfg["tenant"], politica=POLITICA,
                                 modo_demo=bool(evento.get("modo_demo"))) is not None:
                casos.append(ev["resultado"]["case_id"])
            else:
                omitidos += 1
        except DatoFaltante as e:
            omitidos += 1
            log.warning("caso omitido hallazgo=%s motivo=%s", ev.get("resultado", {}).get("case_id"), e)
    return {"casos": casos[:MAX_CASOS], "total": len(casos), "omitidos": omitidos,
            "truncado": len(casos) > MAX_CASOS}


def _guardar(cfg: dict, destino: str, documento: dict) -> None:
    cuerpo = json.dumps(documento, ensure_ascii=False, sort_keys=True).encode("utf-8")
    try:
        _cliente("s3").put_object(Bucket=cfg["bucket_curada"], Key=destino, Body=cuerpo,
                                  ContentType="application/json", ServerSideEncryption="AES256", IfNoneMatch="*")
    except Exception as exc:   # mismo contenido ya escrito en un reintento: idempotente
        codigo = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
        if codigo not in ("PreconditionFailed", "412"):
            raise


def _sin_asesoria(hallazgo_id: str, motivo: str, **extra) -> dict:
    return {"hallazgo_id": hallazgo_id, "estado": "sin_asesoria", "motivo": motivo,
            "revision": "alta" if motivo in ("guardrail_bloqueo_entrada", "inconsistencia_motor") else "normal", **extra}


def clave_reuso(cfg: dict, entrada: dict, prompt_sha: str) -> str:
    """Huella de lo que el modelo ve y de como se valida, sin los campos que cambian en cada corrida (id de corrida,
    instantaneas, hash con marca de tiempo del motor). Si cambia un dato del caso, la evaluacion del motor, el modelo
    de negocio, el prompt, el modelo, el guardrail o el guard, la huella cambia y se vuelve a asesorar."""
    import copy
    e = copy.deepcopy(entrada)
    for ruta in VOLATILES:
        nodo = e
        for k in ruta[:-1]:
            nodo = nodo.get(k) if isinstance(nodo, dict) else None
        if isinstance(nodo, dict):
            nodo.pop(ruta[-1], None)
    texto = json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    texto = RE_INSTANTE.sub("<t>", texto.replace(entrada.get("corrida_id") or "\x00", "<c>"))
    base = {"e": texto, "prompt": prompt_sha, "guard": VERSION_GUARD, "modelo": cfg["modelo"],
            "guardrail": [cfg["guardrail_id"], cfg["guardrail_version"]]}
    return hashlib.sha256(json.dumps(base, sort_keys=True).encode("utf-8")).hexdigest()


def _clave_indice(cfg: dict, hid: str, clave: str) -> str:
    return f"agente/{cfg['tenant']}/reuso/{hid}-{clave[:32]}.json"


def _buscar_reuso(cfg: dict, hid: str, clave: str) -> tuple[str, dict] | None:
    """Devuelve (clave_s3, documento) de una asesoria aceptada con la misma huella y vigente; ante cualquier duda, None
    (se asesora de nuevo: el reuso solo ahorra, nunca decide)."""
    s3 = _cliente("s3")
    try:
        ind = json.loads(s3.get_object(Bucket=cfg["bucket_curada"], Key=_clave_indice(cfg, hid, clave))["Body"].read())
        if ind.get("clave") != clave or time.time() - float(ind["creado_epoch"]) > REUSO_DIAS * 86400:
            return None
        origen = ind["destino"]
        if not re.match(rf"^agente/{re.escape(cfg['tenant'])}/[0-9a-f-]{{36}}/{re.escape(hid)}-[0-9a-f]{{16}}\.json$", origen):
            return None
        doc = json.loads(s3.get_object(Bucket=cfg["bucket_curada"], Key=origen)["Body"].read())
        if doc.get("estado") != "aceptada" or doc.get("hallazgo_id") != hid:
            return None
        return origen, doc
    except Exception as exc:   # NoSuchKey, AccessDenied, JSON invalido...: sin reuso
        log.info("sin reuso hallazgo=%s motivo=%s", hid, type(exc).__name__)
        return None


def _registrar_reuso(cfg: dict, hid: str, clave: str, destino: str) -> None:
    try:
        cuerpo = json.dumps({"clave": clave, "destino": destino, "creado_epoch": time.time()}).encode("utf-8")
        _cliente("s3").put_object(Bucket=cfg["bucket_curada"], Key=_clave_indice(cfg, hid, clave), Body=cuerpo,
                                  ContentType="application/json", ServerSideEncryption="AES256")
    except Exception as exc:
        log.warning("no se registro el indice de reuso hallazgo=%s motivo=%s", hid, type(exc).__name__)


def _asesorar(cfg: dict, evento: dict) -> dict:
    hid = evento.get("hallazgo_id")
    if not (isinstance(hid, str) and RE_UUID.match(hid)):
        raise ValueError("hallazgo_id invalido")
    motor = _leer_archivo_motor(cfg, evento)
    ev = next((e for e in motor.get("evaluaciones", []) if e["resultado"].get("case_id") == hid), None)
    if ev is None:
        raise ValueError("hallazgo no presente en el archivo del motor")
    try:
        modelo = _modelo_negocio(cfg)
        entrada = construir_entrada(motor, ev, modelo, tenant_id=cfg["tenant"], politica=POLITICA,
                                    modo_demo=bool(evento.get("modo_demo")))
    except InconsistenciaMotor as e:
        log.warning("inconsistencia del motor hallazgo=%s detalle=%s", hid, e)
        return _sin_asesoria(hid, "inconsistencia_motor", detalle=str(e)[:200])
    except DatoFaltante as e:
        return _sin_asesoria(hid, "dato_faltante", detalle=str(e)[:200])
    if entrada is None:
        return _sin_asesoria(hid, "no_enrutado")

    prompt = (RAIZ / "prompts" / cfg["prompt"]).read_text("utf-8")
    prompt_sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    clave = clave_reuso(cfg, entrada, prompt_sha)
    previo = _buscar_reuso(cfg, hid, clave)
    if previo:                 # mismos datos, mismo prompt, mismo guard: se publica la asesoria vigente sin Bedrock
        origen, doc = previo
        destino = f"agente/{cfg['tenant']}/{entrada['corrida_id']}/{origen.rsplit('/', 1)[1]}"
        _guardar(cfg, destino, {**doc, "reutilizada": {"de": origen, "corrida_id": entrada["corrida_id"]}})
        log.info("reutilizado hallazgo=%s de=%s", hid, origen)
        return {"hallazgo_id": hid, "estado": "reutilizado", "recomendacion": doc["recomendacion"]["efectiva"],
                "revision": doc["revision"]["prioridad"], "destino": destino}

    intervino, politicas = _guardrail(cfg, _textos_terceros(entrada), "INPUT")
    if intervino:          # no se envia al modelo un texto que el guardrail considera ataque
        log.warning("guardrail INPUT hallazgo=%s politicas=%s", hid, politicas)
        return _sin_asesoria(hid, "guardrail_bloqueo_entrada", politicas=politicas)

    salida, meta = _invocar_modelo(cfg, prompt, entrada)
    try:
        res = aplicar(entrada, salida, tenant_autorizado=cfg["tenant"])
    except EntradaInvalida as e:
        return _sin_asesoria(hid, "entrada_invalida", detalle=str(e)[:200])
    if meta["stop"] == "max_tokens":
        res = {**res, "estado": "rechazada"}

    if res["estado"] == "aceptada":
        intervino, politicas = _guardrail(cfg, _textos_generados(res["salida_validada"]), "OUTPUT")
        if intervino:
            log.warning("guardrail OUTPUT hallazgo=%s politicas=%s", hid, politicas)
            return _sin_asesoria(hid, "guardrail_bloqueo_salida", politicas=politicas)

    if res["estado"] != "aceptada":
        log.warning("salida rechazada hallazgo=%s errores=%s", hid, res.get("errores", [])[:3])
        return _sin_asesoria(hid, "salida_rechazada_por_guard", errores=res.get("errores", [])[:5])

    # Regla 7 evaluada con los datos: el modelo puede citar mal sus condiciones. Solo vuelve mas conservadora la recomendacion.
    res = marcar_texto(entrada, marcar_dominio(entrada, normalizar_escalar(entrada, res), modelo))

    documento = {**res, "modelo": cfg["modelo"],
                 "prompt_sha256": prompt_sha,
                 "guardrail": {"id": cfg["guardrail_id"], "version": cfg["guardrail_version"]},
                 "meta": meta, "entrada": entrada}
    _guardar(cfg, res["destino_s3"], documento)
    _registrar_reuso(cfg, hid, clave, res["destino_s3"])
    log.info("asesorado hallazgo=%s recomendacion=%s revision=%s tokens=%s latencia_ms=%s", hid,
             res["recomendacion"]["efectiva"], res["revision"]["prioridad"],
             meta["uso"].get("outputTokens"), meta["latencia_ms"])
    return {"hallazgo_id": hid, "estado": "asesorado", "recomendacion": res["recomendacion"]["efectiva"],
            "revision": res["revision"]["prioridad"], "destino": res["destino_s3"]}


ACCIONES = {"listar": _listar, "asesorar": _asesorar}


def handler(evento, contexto=None):
    if not isinstance(evento, dict) or evento.get("accion") not in ACCIONES:
        raise ValueError("accion no permitida")
    if not (isinstance(evento.get("corrida_id"), str) and RE_UUID.match(evento["corrida_id"])):
        raise ValueError("corrida_id invalido")
    permitidas = {"accion", "corrida_id", "archivo_sombra", "hallazgo_id", "modo_demo"}
    extra = set(evento) - permitidas
    if extra:
        raise ValueError(f"campos no permitidos en el evento: {sorted(extra)}")
    return ACCIONES[evento["accion"]](_cfg(), evento)
