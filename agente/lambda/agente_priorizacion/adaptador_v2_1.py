"""Adaptador v2.1: salida del motor v1.3.3 (contrato acordado) -> `agente-entrada-v2.1`.

Acuerdos con el equipo del motor (20-nov-2026):
  1. El MOTOR es la unica autoridad de la prioridad final, sus pisos y los estados de verificacion.
     El adaptador NO recalcula: valida coherencia y, ante una inconsistencia, no envia el caso.
  2. `cruce` = evaluacion determinista vigente del cruce al inicio de la corrida, con trazabilidad temporal.
     Sin cruce el caso SI se envia, con comparacion_previa.disponible = false.
  3. `verificado` exige evidencia positiva identificable (politica-verificacion-v1). El adaptador solo DEGRADA
     un estado cuya evidencia no cumple la politica; nunca lo sube. La ausencia de advertencias no prueba nada.
  4. Las escalas no se mezclan: R ordinal 1-9 del motor en evaluacion_determinista; el 0-100 del cruce solo en
     comparacion_previa.

Modulo puro (biblioteca estandar).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
from datetime import date
from typing import Any

ESQUEMA = "agente-entrada-v2.1"
POLITICA_ENRUTAMIENTO = "enrutamiento-v1"
ESTADOS_ENVIABLES = {"confirmed", "candidate", "unknown"}
CAMPOS_VERIFICACION = ("exposicion", "dependencias", "inventario", "cvss", "kev", "epss")
ORIGENES_PISO = {"kev", "epss", "cvss_exposicion", "cruce", "politica", None}
METODOS_ESQUEMA = {"observacion_cmdb", "atestacion_dueno", "conciliacion_cmdb", "recertificacion", "consulta_bd",
                   "consulta_nvd", "catalogo_cisa", "api_first"}

RE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
RE_CWE = re.compile(r"^(CWE-[0-9]+|NVD-CWE-(Other|noinfo))$")
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RE_URL = re.compile(r"https?://\S+", re.IGNORECASE)
RE_CORREO = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁠-⁤⁦-⁩﻿  ]")

RUTA_POLITICA = pathlib.Path(__file__).resolve().parent / "contrato" / "politica-verificacion-v1.json"


class DatoFaltante(ValueError):
    """Falta un dato obligatorio: el caso NO se envia al agente y conserva su evaluacion determinista."""
    motivo = "dato_faltante"


class InconsistenciaMotor(DatoFaltante):
    """La salida del motor contradice el contrato (p. ej. perfora un piso): no se envia y se registra."""
    motivo = "inconsistencia_motor"


def sha256_json(obj: Any) -> str:
    """Hash canonico (sort_keys, separadores compactos, UTF-8). Lo calculan igual ambos equipos."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def cargar_politica(ruta: pathlib.Path = RUTA_POLITICA) -> dict:
    return json.loads(ruta.read_text(encoding="utf-8"))


def sanear(texto: Any, maximo: int) -> str:
    t = "" if texto is None else str(texto)
    t = RE_CONTROL.sub(" ", t)
    t = RE_URL.sub("[url-retirada]", t)
    t = RE_CORREO.sub("[correo-retirado]", t)
    return re.sub(r"\s+", " ", t).strip()[:maximo]


def _fecha(valor: Any) -> date | None:
    try:
        return date.fromisoformat(str(valor)[:10])
    except (TypeError, ValueError):
        return None


def _prioridad(valor: Any, campo: str, *, nula: bool) -> int | None:
    if valor is None and nula:
        return None
    if isinstance(valor, bool) or not isinstance(valor, int) or not 1 <= valor <= 4:
        raise DatoFaltante(f"{campo} debe ser un entero 1-4 entregado por el motor (contrato v2.1)")
    return valor


def _ordinal(valor: Any, permitidos: set) -> Any:
    if valor is None or (not isinstance(valor, bool) and valor in permitidos):
        return valor
    raise DatoFaltante(f"valor ordinal fuera de escala: {valor!r}")


# ------------------------------------------------------------------------------------- verificacion

def _verificar(campo: str, valor: Any, ev: dict | None, politica: dict, evaluado: date | None,
               advertencias: list) -> tuple[str, dict]:
    """Devuelve (estado, procedencia). Solo puede degradar el estado que declara el motor."""
    degradado = "declarado_sin_evidencia" if valor is not None else "desconocido"
    if not isinstance(ev, dict):
        return degradado, {"fuente": "motor", "fecha_verificacion": None, "metodo": None}
    estado = ev.get("estado")
    metodo = ev.get("metodo")
    fecha = _fecha(ev.get("fecha_verificacion"))
    proc = {"fuente": sanear(ev.get("fuente") or "motor", 60) or "motor",
            "fecha_verificacion": fecha.isoformat() if fecha else None,
            "metodo": metodo if metodo in METODOS_ESQUEMA else None}
    ref = ev.get("referencia")
    if isinstance(ref, str) and ref.startswith("https://") and len(ref) <= 500:
        proc["referencia"] = ref

    if estado == "no_consultable":
        return "no_consultable", {**proc, "metodo": "sin_permiso_o_desactivado"}
    if estado in ("declarado_sin_evidencia", "desconocido"):
        return (estado if valor is not None or estado == "desconocido" else "desconocido"), proc
    if estado != "verificado":
        advertencias.append(f"VERIFICACION_DEGRADADA_{campo.upper()}")
        return degradado, proc

    reglas = politica["campos"].get(campo, {}).get("metodos", {})
    regla = reglas.get(metodo)
    motivo = None
    if valor is None:
        motivo = "sin_valor"
    elif regla is None:
        motivo = "metodo_no_admitido"
    elif not ev.get("fuente"):
        motivo = "sin_fuente"
    elif fecha is None:
        motivo = "sin_fecha"
    elif evaluado is None:
        motivo = "sin_fecha_de_evaluacion"
    elif fecha > evaluado:
        motivo = "fecha_futura"
    elif (evaluado - fecha).days > regla["ventana_dias"]:
        motivo = "fuera_de_ventana"
    elif regla.get("estado_maximo") == "declarado_sin_evidencia":
        motivo = "metodo_solo_declarativo"
    elif campo == "inventario" and valor == "vigente_conciliado" and metodo != "conciliacion_cmdb":
        motivo = "conciliado_sin_cmdb"
    if motivo:
        advertencias.append(f"VERIFICACION_DEGRADADA_{campo.upper()}")
        return degradado, proc
    return "verificado", proc


def _dato(valor, estado, procedencia):
    return {"valor": valor, "estado_verificacion": estado, "procedencia": procedencia}


def motivo_envio(resultado: dict, contexto: dict, final: int, *, modo_demo: bool) -> str | None:
    if modo_demo:
        return "DEMOSTRACION_TODOS"
    if contexto.get("en_kev") is True:
        return "KEV"
    if final <= 2:
        return "PRIORIDAD_ALTA"
    if resultado.get("estado_aplicabilidad") != "confirmed" or contexto.get("metodo_deteccion") == "cruce_ambiguo_agente":
        return "APLICABILIDAD_AMBIGUA"
    return None


# ------------------------------------------------------------------------------------- construccion

def construir_entrada(motor: dict, evaluacion: dict, modelo_negocio: dict, *, tenant_id: str,
                      politica: dict | None = None, precedentes: list[dict] | None = None,
                      modo_demo: bool = False) -> dict | None:
    politica = politica or cargar_politica()
    r, ctx, cruce = evaluacion["resultado"], evaluacion.get("contexto_agente"), evaluacion.get("cruce")

    # --- Identidad, contrato y politica compartida ----------------------------------------------------
    if motor.get("tenant_id") != tenant_id or r.get("tenant_id") != tenant_id:
        raise DatoFaltante("tenant del motor distinto del tenant del servicio")
    if modelo_negocio.get("tenant_id") != tenant_id:
        raise DatoFaltante("el modelo de negocio pertenece a otro tenant")
    if not isinstance(ctx, dict):
        raise DatoFaltante("falta contexto_agente (motor v1.3.3)")
    if r.get("accion_automatica_autorizada") is not False:
        raise DatoFaltante("el motor no declaro accion_automatica_autorizada=false")
    pv = motor.get("politica_verificacion") or {}
    if pv.get("sha256") != sha256_json(politica):
        raise DatoFaltante("el motor no aplico la misma politica-verificacion (sha256 distinto o ausente)")
    if r.get("estado_aplicabilidad") not in ESTADOS_ENVIABLES or r.get("estado_evaluacion") in ("excluded", "planned_asset"):
        return None
    cve, codigo = r.get("cve"), r.get("asset_code")
    if not RE_CVE.match(cve or ""):
        raise DatoFaltante("CVE con formato invalido")

    # --- Prioridad: el motor decide; el adaptador solo valida ------------------------------------------
    final = _prioridad(r.get("prioridad_final"), "resultado.prioridad_final", nula=False)
    piso = _prioridad(r.get("prioridad_piso_efectivo"), "resultado.prioridad_piso_efectivo", nula=True)
    origen_piso = r.get("origen_piso")
    if origen_piso not in ORIGENES_PISO:
        raise DatoFaltante("origen_piso no reconocido")
    if piso is not None and final > piso:
        raise InconsistenciaMotor(f"prioridad_final P{final} perfora el piso efectivo P{piso}")
    if isinstance(cruce, dict):
        piso_cruce = _prioridad(cruce.get("prioridad_piso"), "cruce.prioridad_piso", nula=True)
        if piso_cruce is not None and final > piso_cruce:
            raise InconsistenciaMotor(f"prioridad_final P{final} perfora el piso del cruce P{piso_cruce}")
        base = _prioridad(cruce.get("prioridad_final"), "cruce.prioridad_final", nula=False)
    else:
        cruce, piso_cruce, base = None, None, None
    motivo = motivo_envio(r, ctx, final, modo_demo=modo_demo)
    if motivo is None:
        return None

    # --- Estados de verificacion: los asigna el motor; aqui solo se degradan ---------------------------
    adv = list(dict.fromkeys(r.get("advertencias", [])))
    fnl = set(motor.get("fuentes_no_lectura", []))
    evaluado = _fecha(motor.get("assessed_at"))
    ver = ctx.get("verificacion") if isinstance(ctx.get("verificacion"), dict) else {}

    expuesto = ctx.get("expuesto_internet")
    valor_exp = None if expuesto is None else ("internet" if expuesto else "interna")
    exposicion = _dato(valor_exp, *_verificar("exposicion", valor_exp, ver.get("exposicion"), politica, evaluado, adv))

    deps = ctx.get("dependientes_directos")
    valor_deps = None if deps is None else [{k: d[k] for k in ("activo_codigo", "criticidad", "ambiente", "tipo_dependencia")}
                                            for d in deps]
    est_deps, proc_deps = _verificar("dependencias", valor_deps, ver.get("dependencias"), politica, evaluado, adv)
    if valor_deps is None and "despliegue_dependencias" in fnl:
        est_deps, proc_deps = "no_consultable", {**proc_deps, "metodo": "sin_permiso_o_desactivado"}
    dependencias = _dato(valor_deps, est_deps, proc_deps)
    if est_deps != "verificado" and "DEPENDENCIAS_NO_VERIFICADAS" not in adv:
        adv.append("DEPENDENCIAS_NO_VERIFICADAS")

    valor_inv = ctx.get("inventario_estado")
    if valor_inv not in ("vigente_conciliado", "vigente_sin_conciliar", "no_vigente"):
        valor_inv = None
    inventario = _dato(valor_inv, *_verificar("inventario", valor_inv, ver.get("inventario"), politica, evaluado, adv))

    cvss_valor = [{"version": m["version"], "vector": str(m["vector"])[:200], "puntaje_base": float(m["score"]),
                   "fuente": str(m.get("source", ""))[:30]} for m in r.get("metricas_cvss_disponibles", [])] or None
    cvss = _dato(cvss_valor, *_verificar("cvss", cvss_valor, ver.get("cvss"), politica, evaluado, adv))

    en_kev = ctx.get("en_kev")
    kev_completo = None if en_kev is None else {"en_kev": bool(en_kev), "fecha_limite": ctx.get("kev_fecha_limite"),
                                                "uso_ransomware": ctx.get("uso_ransomware")}
    est_kev, proc_kev = _verificar("kev", kev_completo, ver.get("kev"), politica, evaluado, adv)
    if en_kev is True:
        kev = _dato(kev_completo, est_kev, proc_kev)
    elif en_kev is False and est_kev == "verificado":
        kev = _dato(kev_completo, "verificado", proc_kev)
    else:                                  # false sin evidencia positiva NO es "fuera de KEV"
        kev = _dato(None, "desconocido", proc_kev)

    epss_valor = None
    if ctx.get("epss") is not None and ctx.get("epss_percentil") is not None and _fecha(ctx.get("epss_fecha")):
        epss_valor = {"puntaje": float(ctx["epss"]), "percentil": float(ctx["epss_percentil"]),
                      "fecha": _fecha(ctx["epss_fecha"]).isoformat()}
        if evaluado and _fecha(ctx["epss_fecha"]) > evaluado:
            adv.append("EPSS_FECHA_POSTERIOR_A_EVALUACION")
    est_epss, proc_epss = _verificar("epss", epss_valor, ver.get("epss"), politica, evaluado, adv)
    if "EPSS_FECHA_POSTERIOR_A_EVALUACION" in adv and est_epss == "verificado":
        est_epss = "desconocido"
    epss = _dato(epss_valor, est_epss, proc_epss)

    # --- Evaluacion determinista y antes/despues ------------------------------------------------------
    razones = [{"codigo": x["regla"], "explicacion": str(x.get("explicacion", ""))[:500]} for x in r.get("razones", [])]
    if base is not None:
        razones.append({"codigo": "PRIORIDAD_CRUCE_A_MOTOR",
                        "explicacion": f"Antes (cruce): P{base}. Despues (motor): P{final} de tipo {r.get('prioridad_tipo')}."})
    if cruce is not None:
        puntaje = cruce.get("puntaje_riesgo")
        puntaje = None if puntaje is None else float(puntaje)
        corrida_origen = cruce.get("corrida_id_origen")
        comparacion = {"disponible": True, "prioridad": base, "prioridad_piso": piso_cruce, "puntaje_riesgo": puntaje,
                       "escala_puntaje": "cruce_0_100" if puntaje is not None else None,
                       "fecha": str(cruce["fecha"])[:25] if cruce.get("fecha") else None, "origen": "cruce",
                       "corrida_id_origen": corrida_origen if isinstance(corrida_origen, str) and RE_UUID.match(corrida_origen) else None,
                       "misma_corrida": cruce.get("misma_corrida") if isinstance(cruce.get("misma_corrida"), bool) else None,
                       "motivo": None}
    else:
        ausencia = evaluacion.get("cruce_motivo_ausencia")
        if ausencia not in ("sin_historial", "sin_permiso"):
            ausencia = "sin_permiso" if "evaluaciones" in fnl else "sin_historial"
        comparacion = {"disponible": False, "prioridad": None, "prioridad_piso": None, "puntaje_riesgo": None,
                       "escala_puntaje": None, "fecha": None, "origen": None, "corrida_id_origen": None,
                       "misma_corrida": None, "motivo": ausencia}

    # --- Evidencias numeradas (lo unico citable) -------------------------------------------------------
    ev: list[dict] = []

    def add(tipo, descripcion, referencia=None):
        x = {"id": f"ev-{len(ev) + 1:02d}", "tipo": tipo, "descripcion": sanear(descripcion, 500)}
        if referencia:
            x["referencia"] = referencia
        ev.append(x)

    def nota(d):
        p = d["procedencia"]
        extra = f" por {p['metodo']} el {p['fecha_verificacion']}" if d["estado_verificacion"] == "verificado" else ""
        return f"[{d['estado_verificacion']}{extra}]"

    ref_nvd = f"https://nvd.nist.gov/vuln/detail/{cve}"
    for m in cvss_valor or []:
        add("cvss", f"CVSS {m['version']} = {m['puntaje_base']} ({m['fuente']}), vector {m['vector']} {nota(cvss)}", ref_nvd)
    cwe = [c for c in (ctx.get("cwe") or []) if RE_CWE.match(c)][:10]
    if cwe:
        add("cwe", ", ".join(cwe))
    if kev["valor"] and kev["valor"]["en_kev"]:
        texto_kev = "En CISA KEV" + (f", fecha limite {kev['valor']['fecha_limite']}" if kev["valor"]["fecha_limite"] else "")
    elif kev["valor"]:
        texto_kev = "Fuera de CISA KEV"
    else:
        texto_kev = "KEV sin verificar: no se puede afirmar que este fuera de KEV"
    add("kev", f"{texto_kev} {nota(kev)}")
    if epss["valor"]:
        add("epss", f"EPSS {epss['valor']['puntaje']:.5f}, percentil {epss['valor']['percentil']}, fecha "
                    f"{epss['valor']['fecha']} (senal poblacional a 30 dias) {nota(epss)}")
    add("activo", f"Activo {codigo}: tipo {ctx.get('activo_tipo')}, criticidad {ctx.get('criticidad')}/5, "
                  f"informacion {ctx.get('clasificacion_informacion')}, dominio {ctx.get('dominio_negocio')}")
    add("exposicion", f"Exposicion {valor_exp or 'desconocida'} {nota(exposicion)}")
    add("despliegue", f"Ambiente {ctx.get('ambiente')}, RTO {ctx.get('rto_minutes')} min, RPO {ctx.get('rpo_minutes')} min")
    add("dependencia", (f"{len(valor_deps)} dependientes directos {nota(dependencias)}" if valor_deps is not None
                        else f"Dependencias {dependencias['estado_verificacion']}: no afirmar que hay cero dependientes"))
    add("inventario", f"Inventario {inventario['valor'] or 'desconocido'} {nota(inventario)}")
    add("componente", f"{ctx.get('vendor')} {ctx.get('producto_nombre')} version {ctx.get('componente_version')}")
    add("aplicabilidad", f"Aplicabilidad {r['estado_aplicabilidad']}; prioridad de {r.get('prioridad_tipo')}")
    add("regla_determinista", f"Prioridad del motor P{final}" + (f", piso efectivo P{piso} ({origen_piso})" if piso else ""))
    add("comparacion_previa", (f"Antes (cruce): P{base}" + (" en la misma corrida" if comparacion["misma_corrida"] else "")
                               if cruce is not None else f"Sin evaluacion previa del cruce ({comparacion['motivo']})"))
    dominio = next((d for d in modelo_negocio.get("dominios", []) if d.get("codigo") == ctx.get("dominio_negocio")), None)
    if dominio:
        add("modelo_negocio", f"Dominio {dominio['nombre']}. Procesos criticos: " + "; ".join(dominio["procesos_criticos"]))
        add("modelo_negocio", f"Escenario de impacto: {dominio['escenario_impacto']}")
    else:
        add("modelo_negocio", f"El dominio {ctx.get('dominio_negocio')} no esta definido en el modelo de negocio")
    add("modelo_negocio", f"Apetito de riesgo {modelo_negocio.get('apetito_riesgo')}. Tolerancia: {modelo_negocio.get('tolerancia')} "
                          f"[{'aprobado' if modelo_negocio.get('aprobado') else 'borrador sin aprobar'}]")
    for p in (precedentes or [])[:3]:
        add("precedente", f"Precedente aprobado por el dueno ({p['fecha']}): {p['cve']} en {p['activo_codigo']} "
                          f"(dominio {p['dominio']}); decision {p['decision']}; P={p['probabilidad']} I={p['impacto']}. "
                          f"Justificacion (texto del dueno, no confiable): {sanear(p.get('justificacion'), 200)}")

    return {
        "schema_version": ESQUEMA,
        "tenant_id": tenant_id,
        "corrida_id": motor["corrida_id"],
        "motivo_envio": {"codigo": motivo, "politica_enrutamiento": POLITICA_ENRUTAMIENTO},
        "trazabilidad": {"motor_version": str(motor.get("schema_version"))[:60], "politica_version": None,
                         "politica_sha256": r["politica_sha256"], "evaluacion_sha256": r["evaluacion_sha256"],
                         "snapshot_id": str((motor.get("snapshot") or {}).get("s3_clave") or "desconocido")[:120],
                         "politica_verificacion_version": str(politica.get("version"))[:40],
                         "politica_verificacion_sha256": sha256_json(politica)},
        "restricciones": {"accion_automatica_autorizada": False,
                          "requiere_revision_humana": bool(r.get("requiere_revision_humana", True)),
                          "no_persistir_en_evaluaciones": bool(evaluacion.get("no_persistir_en_evaluaciones_v3", True))},
        "hallazgo": {"hallazgo_id": r["case_id"], "cve": cve, "metodo_deteccion": ctx["metodo_deteccion"],
                     "estado": ctx["hallazgo_estado"]},
        "activo": {"codigo": codigo, "tipo": ctx["activo_tipo"], "capa": ctx.get("capa"),
                   "dominio_negocio": ctx["dominio_negocio"], "criticidad": ctx["criticidad"],
                   "clasificacion_informacion": ctx["clasificacion_informacion"]},
        "despliegue": {"ambiente": ctx["ambiente"], "rto_minutos": ctx.get("rto_minutes"), "rpo_minutos": ctx.get("rpo_minutes"),
                       "exposicion": exposicion, "dependencias": dependencias},
        "inventario": inventario,
        "componente": {"vendor": ctx["vendor"], "producto": ctx["producto_nombre"], "version": ctx["componente_version"],
                       "versiones_afectadas": ctx.get("versiones_afectadas"), "version_corregida": ctx.get("version_corregida")},
        "vulnerabilidad": {"descripcion_no_confiable": sanear(ctx.get("descripcion"), 4000), "cwe": cwe,
                           "cvss": cvss, "kev": kev, "epss": epss},
        "evaluacion_determinista": {
            "origen": "motor", "prioridad_base": base, "prioridad_final": final,
            "prioridad_piso_efectivo": piso, "origen_piso": origen_piso,
            "prioridad_tipo": r["prioridad_tipo"], "estado_aplicabilidad": r["estado_aplicabilidad"],
            "probabilidad_tamizaje": _ordinal(r.get("probabilidad_tamizaje"), {1, 2, 3}),
            "impacto_tamizaje": _ordinal(r.get("impacto_tamizaje"), {1, 2, 3}),
            "riesgo_inherente": _ordinal(r.get("riesgo_inherente"), {1, 2, 3, 4, 6, 9}),
            "riesgo_residual": _ordinal(r.get("riesgo_residual"), {1, 2, 3, 4, 6, 9}),
            "escala_riesgo": "ordinal_1_9",
            "advertencias": list(dict.fromkeys(adv))[:30], "razones": razones[:30]},
        "comparacion_previa": comparacion,
        "contexto_negocio": {"version": str(modelo_negocio["version"])[:40], "sha256": sha256_json(modelo_negocio),
                             "aprobado": modelo_negocio.get("aprobado") is True},
        "evidencias": ev,
    }
