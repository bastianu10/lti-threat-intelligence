"""Output guard v2: priorizacion ASISTIDA.

Principio: la IA ASESORA, el motor CALCULA y el dueno del activo APRUEBA.

Diferencias con v1.1:
  * El guard ya NO calcula R = P x I ni aplica ajustes. La prioridad final es SIEMPRE la determinista.
    La valoracion P/I del agente queda como propuesta pendiente de aprobacion del dueno; el motor la
    usa como evidencia verificada solo despues de esa aprobacion (etapa B del motor v1.3.3).
  * Asimetria a favor de la seguridad: 'escalar' siempre se admite (pide revision prioritaria);
    'revisar_a_la_baja' solo se admite con aplicabilidad confirmada, KEV verificado y ausente, exposicion,
    inventario y dependencias verificados, sin piso alcanzado y con modelo de negocio aprobado.
  * Senales de incertidumbre obligatorias: si el agente omite una, el guard la agrega y lo registra.
  * Lista blanca de dominios en las URL, ademas de exigir que esten en las referencias de la entrada.
  * Deteccion determinista de manipulacion en la descripcion del feed (defensa en profundidad).

Modulo puro (biblioteca estandar, sin red ni base) para reutilizarlo en la Lambda y probarlo completo.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any
from urllib.parse import urlsplit

from .esquema import Validador

VERSION_GUARD = "output-guard-v2.0"
ESQUEMA_ENTRADA = "agente-entrada-v2"
ESQUEMA_SALIDA = "agente-salida-v2"

_DIR = pathlib.Path(__file__).resolve().parent / "contrato"
_V_ENTRADA = Validador(json.loads((_DIR / "entrada.v2.schema.json").read_text(encoding="utf-8")))
_V_SALIDA = Validador(json.loads((_DIR / "salida.v2.schema.json").read_text(encoding="utf-8")))

DOMINIOS_PERMITIDOS = frozenset({
    "nvd.nist.gov", "www.cve.org", "cve.org", "www.cisa.gov", "osv.dev", "github.com",
    "www.first.org", "api.first.org", "attack.mitre.org",
})
UMBRAL_CONFIANZA = 0.5

RE_URL = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
RE_CORREO = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
RE_UNICODE_ENGANOSO = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿  ]")
# Patrones tipicos de inyeccion en textos de feeds (NVD, OSV, avisos). No bloquea: marca para revision.
RE_INYECCION = re.compile(
    r"(ignor\w*\s+(all|todas|las|previous|anteriores)|system\s*(prompt|override)|</?\s*entrada_hallazgo|"
    r"you\s+are\s+now|act[uú]a\s+como|responde\s+con|new\s+instructions|nuevas\s+instrucciones|"
    r"https?://|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
    r"\[url-retirada\]|\[correo-retirado\])", re.IGNORECASE)   # marcas que deja el adaptador al sanear

SENALES_REVISION = {"requiere_validacion_dueno", "aplicabilidad_dudosa", "datos_insuficientes",
                    "exposicion_no_verificada", "dependencias_no_verificadas", "inventario_no_vigente",
                    "kev_no_verificado", "posible_manipulacion_feed"}


class EntradaInvalida(ValueError):
    """La entrada no cumple el contrato: no se invoca al modelo y el caso conserva su evaluacion determinista."""


def sha256_canonico(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def _textos(obj: Any, ruta: str = ""):
    if isinstance(obj, str):
        yield ruta, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _textos(v, f"{ruta}.{k}" if ruta else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _textos(v, f"{ruta}[{i}]")


def _dominio_permitido(url: str, extra: frozenset) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in DOMINIOS_PERMITIDOS or host in extra


# ------------------------------------------------------------------------------------- entrada

def validar_entrada(e: Any, *, dominios_extra: frozenset = frozenset()) -> list[str]:
    err = _V_ENTRADA.errores(e)
    if err:
        return err
    det = e["evaluacion_determinista"]
    base, piso, final = det["prioridad_base"], det["prioridad_piso"], det["prioridad_final"]
    if piso is not None and final > piso:
        err.append("evaluacion_determinista: prioridad_final perfora el piso")
    if det["origen"] == "cruce" and final != min(base, piso if piso is not None else base):
        err.append("evaluacion_determinista: en origen=cruce la final debe ser min(base, piso)")
    if (det["estado_aplicabilidad"] == "confirmed") != (det["prioridad_tipo"] == "tratamiento"):
        err.append("evaluacion_determinista: tratamiento exige aplicabilidad confirmed (y viceversa)")
    if (det["estado_puntaje"] == "no_calculado") != (det["puntaje_riesgo"] is None):
        err.append("evaluacion_determinista: puntaje_riesgo null si y solo si estado_puntaje=no_calculado")
    kev = e["vulnerabilidad"]["kev"]
    if kev["estado_verificacion"] == "verificado" and kev["valor"] is None:
        err.append("vulnerabilidad.kev: un KEV verificado debe declarar en_kev true/false")
    cp = e["comparacion_previa"]
    if not cp["disponible"] and not cp.get("motivo"):
        err.append("comparacion_previa: sin antes disponible se exige el motivo")
    ids = [x["id"] for x in e["evidencias"]]
    if len(ids) != len(set(ids)):
        err.append("evidencias: ids repetidos")
    for i, x in enumerate(e["evidencias"]):
        if "referencia" in x and not _dominio_permitido(x["referencia"], dominios_extra):
            err.append(f"evidencias[{i}].referencia: dominio fuera de la lista blanca")
    return err


# ------------------------------------------------------------------------------------- salida

def _citas(s: dict) -> set[str]:
    c = set(s["valoracion_negocio"]["probabilidad"]["evidencias"])
    c |= set(s["valoracion_negocio"]["impacto"]["evidencias"])
    c |= set(s["recomendacion_urgencia"]["evidencias"])
    for o in s["observaciones_para_revision"]:
        c |= set(o["evidencias"])
    return c


def validar_salida(s: Any, entrada: dict, *, dominios_extra: frozenset = frozenset()) -> list[str]:
    err = _V_SALIDA.errores(s)
    if err:
        return err
    if s["hallazgo_id"] != entrada["hallazgo"]["hallazgo_id"]:
        err.append("hallazgo_id: no corresponde al hallazgo enviado")
    disponibles = {x["id"] for x in entrada["evidencias"]}
    inventadas = sorted(_citas(s) - disponibles)
    if inventadas:
        err.append(f"evidencias: citas inexistentes en la entrada: {inventadas}")
    ordenes = [p["orden"] for p in s["plan_accion"]]
    if ordenes != list(range(1, len(ordenes) + 1)):
        err.append("plan_accion: el orden debe ser consecutivo desde 1")
    bloques = set(entrada)
    for campo in ("datos_a_verificar", "observaciones_para_revision"):
        for i, x in enumerate(s[campo]):
            ruta = x["ruta_campo"]
            if ruta.split(".")[0] not in bloques:
                err.append(f"{campo}[{i}].ruta_campo: no existe en la entrada")
            elif ruta.startswith("evidencias.") and ruta.split(".", 1)[1] not in disponibles:
                err.append(f"{campo}[{i}].ruta_campo: la evidencia senalada no existe en la entrada")
    permitidas = {x["referencia"] for x in entrada["evidencias"] if "referencia" in x}
    for ruta, texto in _textos(s):
        if RE_CONTROL.search(texto):
            err.append(f"{ruta}: contiene caracteres de control")
        if RE_UNICODE_ENGANOSO.search(texto):
            err.append(f"{ruta}: contiene caracteres Unicode bidireccionales o invisibles")
        for url in RE_URL.findall(texto):
            url = url.rstrip(".,;:")
            if url not in permitidas or not _dominio_permitido(url, dominios_extra):
                err.append(f"{ruta}: URL no permitida")
        if RE_CORREO.search(texto):
            err.append(f"{ruta}: contiene una direccion de correo (PII)")
    return err


# ------------------------------------------------------------------------------------- decision

def _senales_requeridas(e: dict) -> dict[str, str]:
    """Senal que el agente DEBE emitir -> razon. Se derivan solo de estados asignados por codigo."""
    req: dict[str, str] = {}
    det, dep, vul = e["evaluacion_determinista"], e["despliegue"], e["vulnerabilidad"]
    if det["estado_aplicabilidad"] != "confirmed":
        req["aplicabilidad_dudosa"] = "aplicabilidad no confirmada"
    if dep["exposicion"]["estado_verificacion"] != "verificado":
        req["exposicion_no_verificada"] = "exposicion sin verificar"
    if dep["dependencias"]["estado_verificacion"] != "verificado":
        req["dependencias_no_verificadas"] = "dependencias sin verificar"
    inv = e["inventario"]
    if inv["estado_verificacion"] != "verificado" or inv["valor"] != "vigente_conciliado":
        req["inventario_no_vigente"] = "inventario no vigente o sin conciliar"
    if vul["kev"]["estado_verificacion"] != "verificado":
        req["kev_no_verificado"] = "KEV sin verificar: null no significa fuera de KEV"
    return req


def _bloqueos_baja(e: dict, s: dict) -> list[str]:
    det, dep, vul = e["evaluacion_determinista"], e["despliegue"], e["vulnerabilidad"]
    b = []
    if det["estado_aplicabilidad"] != "confirmed":
        b.append("baja_sin_aplicabilidad_confirmada")
    kev = vul["kev"]
    if kev["estado_verificacion"] != "verificado":
        b.append("baja_con_kev_no_verificado")
    elif kev["valor"] and kev["valor"]["en_kev"]:
        b.append("baja_con_kev")
    for nombre, dato in (("exposicion", dep["exposicion"]), ("dependencias", dep["dependencias"]),
                         ("inventario", e["inventario"])):
        if dato["estado_verificacion"] != "verificado":
            b.append(f"baja_con_{nombre}_no_verificado")
    vn = s["valoracion_negocio"]
    if vn["probabilidad"]["valor"] == 3 or vn["impacto"]["valor"] == 3:
        b.append("baja_incoherente_con_valoracion")
    if det["prioridad_piso"] is not None and det["prioridad_final"] == det["prioridad_piso"]:
        b.append("baja_bloqueada_por_piso")
    if not e["contexto_negocio"]["aprobado"]:
        b.append("baja_sin_modelo_negocio_aprobado")
    return b


def aplicar(entrada: dict, salida: Any, *, tenant_autorizado: str,
            dominios_extra: frozenset = frozenset()) -> dict:
    """Valida y decide. Lanza EntradaInvalida si la entrada no cumple el contrato o el tenant no coincide.

    Devuelve {"estado": "aceptada" | "rechazada", ...}. La prioridad devuelta es SIEMPRE la determinista.
    """
    errores_entrada = validar_entrada(entrada, dominios_extra=dominios_extra)
    if errores_entrada:
        raise EntradaInvalida("; ".join(errores_entrada[:10]))
    if entrada["tenant_id"] != tenant_autorizado:
        raise EntradaInvalida("tenant_id de la entrada distinto del tenant autorizado del servicio")

    det = entrada["evaluacion_determinista"]
    prioridad = {"base": det["prioridad_base"], "piso": det["prioridad_piso"], "final": det["prioridad_final"],
                 "tipo": det["prioridad_tipo"], "fuente": "determinista"}
    entrada_sha = sha256_canonico(entrada)
    try:
        salida_sha = sha256_canonico(salida)
    except (TypeError, ValueError):
        salida_sha = None
    # Textos de terceros que llegan al modelo: la descripcion del feed y las justificaciones de precedentes.
    textos_externos = [entrada["vulnerabilidad"]["descripcion_no_confiable"]] + [
        x["descripcion"] for x in entrada["evidencias"] if x["tipo"] == "precedente"]
    feed_sospechoso = any(RE_INYECCION.search(t) for t in textos_externos)
    base_resultado = {"guard_version": VERSION_GUARD, "hallazgo_id": entrada["hallazgo"]["hallazgo_id"],
                      "tenant_id": entrada["tenant_id"], "corrida_id": entrada["corrida_id"],
                      "entrada_sha256": entrada_sha, "salida_sha256": salida_sha, "prioridad": prioridad}

    errores = validar_salida(salida, entrada, dominios_extra=dominios_extra)
    if errores:
        motivos = ["salida_agente_rechazada"] + (["descripcion_feed_sospechosa"] if feed_sospechoso else [])
        return {**base_resultado, "estado": "rechazada", "errores": errores[:25],
                "revision": {"requerida": True, "prioridad": "alta" if feed_sospechoso else "normal",
                             "motivos": motivos}}

    motivos: list[str] = []
    # 1) Recomendacion de urgencia: nunca modifica la prioridad; solo orienta la revision humana.
    propuesta = salida["recomendacion_urgencia"]["direccion"]
    efectiva = propuesta
    if propuesta == "escalar":
        motivos.append("agente_recomienda_escalar")
        if det["prioridad_final"] == 1:          # ya es la maxima urgencia: no hay nivel que subir
            efectiva = "mantener"
            motivos.append("escalar_sin_efecto_prioridad_maxima")
    elif propuesta == "revisar_a_la_baja":
        bloqueos = _bloqueos_baja(entrada, salida)
        if bloqueos:
            efectiva = "mantener"
            motivos += bloqueos
        else:
            motivos.append("baja_requiere_aprobacion_dueno")

    # 2) Senales de incertidumbre: el guard completa las omitidas y deja constancia.
    senales = list(salida["senales"])
    for senal in _senales_requeridas(entrada):
        if senal not in senales:
            senales.append(senal)
            motivos.append(f"senal_incertidumbre_omitida:{senal}")
    if feed_sospechoso:
        motivos.append("descripcion_feed_sospechosa")
        if "posible_manipulacion_feed" not in senales:
            senales.append("posible_manipulacion_feed")

    # 3) Calidad del plan y de la confianza.
    if det["prioridad_tipo"] == "investigacion" and salida["plan_accion"][0]["tipo"] != "verificacion":
        motivos.append("plan_sin_verificacion_previa")
    if salida["confianza"] < UMBRAL_CONFIANZA:
        motivos.append("confianza_baja")
    if salida["observaciones_para_revision"]:
        motivos.append("agente_reporta_discrepancia")
    motivos += [s_ for s_ in senales if s_ in SENALES_REVISION and s_ not in motivos]
    if entrada["restricciones"]["requiere_revision_humana"]:
        motivos.append("restriccion_motor_revision_humana")

    alta = (propuesta == "escalar" or feed_sospechoso or bool(salida["observaciones_para_revision"])
            or "plan_sin_verificacion_previa" in motivos)
    vn = salida["valoracion_negocio"]
    confirmada = det["estado_aplicabilidad"] == "confirmed"

    if prioridad["final"] != det["prioridad_final"]:                    # defensa en profundidad
        raise AssertionError("invariante violado: el guard no puede modificar la prioridad")

    return {
        **base_resultado,
        "estado": "aceptada",
        # La valoracion NO entra a ningun calculo hasta que el dueno la aprueba (decisiones -> motor etapa B).
        "propuesta_para_dueno": {
            "probabilidad": vn["probabilidad"]["valor"], "impacto": vn["impacto"]["valor"],
            "dimensiones": vn["impacto"]["dimensiones"], "estado": "pendiente_aprobacion_dueno",
            "condicion": None if confirmada else "condicionada_a_confirmar_aplicabilidad"},
        "recomendacion": {"propuesta": propuesta, "efectiva": efectiva},
        "senales": senales,
        "revision": {"requerida": True, "prioridad": "alta" if alta else "normal",
                     "motivos": list(dict.fromkeys(motivos))},
        "persistir_en_evaluaciones": False,
        "destino_s3": (f"agente/{entrada['tenant_id']}/{entrada['corrida_id']}/"
                       f"{entrada['hallazgo']['hallazgo_id']}-{salida_sha[:16]}.json"),
        "salida_validada": salida,
    }
