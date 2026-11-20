"""Lambda `lti-agente-asesor`: agente de priorizacion ASISTIDA (Bedrock Converse + Guardrail + output guard).

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
  2. Adaptador v2: estados de verificacion en codigo, textos de terceros saneados, DatoFaltante -> no se envia.
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

from agente_priorizacion.adaptador_v2 import DatoFaltante, construir_entrada
from agente_priorizacion.output_guard_v2 import EntradaInvalida, aplicar

log = logging.getLogger()
log.setLevel(logging.INFO)

RAIZ = pathlib.Path(__file__).resolve().parent
HERRAMIENTA = "registrar_evaluacion"
MAX_CASOS = 50
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RE_SHA = re.compile(r"^[0-9a-f]{64}$")

_clientes: dict[str, Any] = {}


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
        "prompt": os.environ.get("PROMPT_ARCHIVO", "sistema_v2_4.md"),
    }


def _sin_refs(nodo, raiz):
    if isinstance(nodo, dict):
        if "$ref" in nodo:
            destino = raiz
            for parte in nodo["$ref"][2:].split("/"):
                destino = destino[parte]
            return _sin_refs(destino, raiz)
        return {k: _sin_refs(v, raiz) for k, v in nodo.items() if k not in ("$schema", "$id", "$defs")}
    if isinstance(nodo, list):
        return [_sin_refs(x, raiz) for x in nodo]
    return nodo


_ESQUEMA_SALIDA = json.loads((RAIZ / "agente_priorizacion" / "contrato" / "salida.v2.schema.json").read_text("utf-8"))
TOOL_CONFIG = {
    "tools": [{"toolSpec": {"name": HERRAMIENTA,
                            "description": "Registra la evaluacion asesora del hallazgo (contrato agente-salida-v2).",
                            "inputSchema": {"json": _sin_refs(_ESQUEMA_SALIDA, _ESQUEMA_SALIDA)}}}],
    "toolChoice": {"tool": {"name": HERRAMIENTA}},
}


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
        toolConfig=TOOL_CONFIG, inferenceConfig={"maxTokens": cfg["max_tokens"], "temperature": 0})
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
            if construir_entrada(motor, ev, modelo, tenant_id=cfg["tenant"],
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
            "revision": "alta" if motivo == "guardrail_bloqueo_entrada" else "normal", **extra}


def _asesorar(cfg: dict, evento: dict) -> dict:
    hid = evento.get("hallazgo_id")
    if not (isinstance(hid, str) and RE_UUID.match(hid)):
        raise ValueError("hallazgo_id invalido")
    motor = _leer_archivo_motor(cfg, evento)
    ev = next((e for e in motor.get("evaluaciones", []) if e["resultado"].get("case_id") == hid), None)
    if ev is None:
        raise ValueError("hallazgo no presente en el archivo del motor")
    try:
        entrada = construir_entrada(motor, ev, _modelo_negocio(cfg), tenant_id=cfg["tenant"],
                                    modo_demo=bool(evento.get("modo_demo")))
    except DatoFaltante as e:
        return _sin_asesoria(hid, "dato_faltante", detalle=str(e)[:200])
    if entrada is None:
        return _sin_asesoria(hid, "no_enrutado")

    intervino, politicas = _guardrail(cfg, _textos_terceros(entrada), "INPUT")
    if intervino:          # no se envia al modelo un texto que el guardrail considera ataque
        log.warning("guardrail INPUT hallazgo=%s politicas=%s", hid, politicas)
        return _sin_asesoria(hid, "guardrail_bloqueo_entrada", politicas=politicas)

    prompt = (RAIZ / "prompts" / cfg["prompt"]).read_text("utf-8")
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

    documento = {**res, "modelo": cfg["modelo"],
                 "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                 "guardrail": {"id": cfg["guardrail_id"], "version": cfg["guardrail_version"]},
                 "meta": meta, "entrada": entrada}
    _guardar(cfg, res["destino_s3"], documento)
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
