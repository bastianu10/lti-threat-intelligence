"""Adaptador v2: salida del motor v1.3.3 (una evaluacion) -> `agente-entrada-v2`.

Reglas (equipo Bedrock, para confirmar con el equipo del motor):
  * Solo el CODIGO asigna `estado_verificacion`; se deriva de advertencias, fuentes_no_lectura y evidencia
    autenticada del motor. El modelo nunca lo decide.
  * Nunca inventa datos: si falta algo obligatorio lanza DatoFaltante y el caso conserva su evaluacion
    determinista sin pasar por el agente.
  * `null` sin verificar se conserva como null (no significa "cero dependencias" ni "fuera de KEV").
  * Los textos de terceros (descripcion del feed, justificaciones de precedentes) se sanean y se marcan.
  * Sin nombres, correos ni credenciales: el bloque contexto_agente del motor ya excluye dueno_id.

Modulo puro (biblioteca estandar). Lo usa la Lambda del agente antes de invocar a Bedrock.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from typing import Any

ESQUEMA = "agente-entrada-v2"
POLITICA_ENRUTAMIENTO = "enrutamiento-v1"
ESTADOS_ENVIABLES = {"confirmed", "candidate", "unknown"}
MAX_DIAS_EPSS = 2

RE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
RE_CWE = re.compile(r"^(CWE-[0-9]+|NVD-CWE-(Other|noinfo))$")
RE_URL = re.compile(r"https?://\S+", re.IGNORECASE)
RE_CORREO = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁠-⁤⁦-⁩﻿  ]")


class DatoFaltante(ValueError):
    """Falta un dato obligatorio: el caso NO se envia al agente (se conserva lo determinista)."""


def sanear(texto: Any, maximo: int) -> str:
    """Texto de terceros: sin URLs, correos, caracteres de control ni Unicode invisible; longitud acotada."""
    t = "" if texto is None else str(texto)
    t = RE_CONTROL.sub(" ", t)
    t = RE_URL.sub("[url-retirada]", t)
    t = RE_CORREO.sub("[correo-retirado]", t)
    return re.sub(r"\s+", " ", t).strip()[:maximo]


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def _dato(valor, estado, fuente, **procedencia):
    p = {"fuente": fuente}
    p.update({k: v for k, v in procedencia.items() if v is not None or k in ("fecha_verificacion", "metodo")})
    return {"valor": valor, "estado_verificacion": estado, "procedencia": p}


def _dias(a: str | None, b: str | None) -> int | None:
    try:
        return abs((date.fromisoformat(a[:10]) - date.fromisoformat(b[:10])).days)
    except (TypeError, ValueError):
        return None


def motivo_envio(resultado: dict, contexto: dict, piso_final: int, *, modo_demo: bool) -> str | None:
    """Politica de enrutamiento en CODIGO. None = no se envia (explicacion determinista)."""
    if modo_demo:
        return "DEMOSTRACION_TODOS"
    if contexto.get("en_kev") is True:
        return "KEV"
    if piso_final <= 2:
        return "PRIORIDAD_ALTA"
    if resultado.get("estado_aplicabilidad") != "confirmed" or contexto.get("metodo_deteccion") == "cruce_ambiguo_agente":
        return "APLICABILIDAD_AMBIGUA"
    return None


def construir_entrada(motor: dict, evaluacion: dict, modelo_negocio: dict, *, tenant_id: str,
                      precedentes: list[dict] | None = None, modo_demo: bool = False) -> dict | None:
    """`motor` = archivo completo del motor v1.3.3; `evaluacion` = un elemento de motor['evaluaciones']."""
    r, ctx, cruce = evaluacion["resultado"], evaluacion.get("contexto_agente"), evaluacion.get("cruce")
    if motor.get("tenant_id") != tenant_id or r.get("tenant_id") != tenant_id:
        raise DatoFaltante("tenant del motor distinto del tenant del servicio")
    if modelo_negocio.get("tenant_id") != tenant_id:
        raise DatoFaltante("el modelo de negocio pertenece a otro tenant")
    if ctx is None:
        raise DatoFaltante("falta contexto_agente: se requiere el motor v1.3.3 (M4)")
    if r.get("accion_automatica_autorizada") is not False:
        raise DatoFaltante("el motor no declaro accion_automatica_autorizada=false")
    if r.get("estado_aplicabilidad") not in ESTADOS_ENVIABLES or r.get("estado_evaluacion") in ("excluded", "planned_asset"):
        return None
    if cruce is None:
        # Sin el ANTES no se conoce el piso KEV/EPSS del cruce: enviar sin piso podria permitir una baja indebida.
        raise DatoFaltante("falta el bloque cruce (ANTES y piso); revisar GRANT SELECT ON evaluaciones (M1)")

    cve, codigo = r["cve"], r["asset_code"]
    if not RE_CVE.match(cve or ""):
        raise DatoFaltante("CVE con formato invalido")
    adv = list(dict.fromkeys(r.get("advertencias", [])))
    fnl = set(motor.get("fuentes_no_lectura", []))
    hoy = (motor.get("assessed_at") or "")[:10] or None

    motor_p = int(str(r["prioridad_operativa"]).lstrip("P"))
    base, piso = cruce.get("prioridad_final"), cruce.get("prioridad_piso")
    if base is None:
        raise DatoFaltante("cruce sin prioridad_final")
    final = motor_p if piso is None else min(motor_p, piso)
    motivo = motivo_envio(r, ctx, final, modo_demo=modo_demo)
    if motivo is None:
        return None

    # --- Estados de verificacion (solo codigo) -------------------------------------------------------
    expuesto = ctx.get("expuesto_internet")
    valor_exp = None if expuesto is None else ("internet" if expuesto else "interna")
    ref_exp = (evaluacion.get("evidencia_autenticada") or {}).get("exposicion")
    if valor_exp is None:
        exposicion = _dato(None, "desconocido", "inventario_manual")
    elif ref_exp and "EXPOSICION_SIN_EVIDENCIA" not in adv:
        exposicion = _dato(valor_exp, "verificado", "recertificaciones", metodo="atestacion_dueno",
                           fecha_verificacion=None)
    else:
        exposicion = _dato(valor_exp, "declarado_sin_evidencia", "inventario_manual")

    deps = ctx.get("dependientes_directos")
    if deps is None:
        estado = "no_consultable" if "despliegue_dependencias" in fnl else "desconocido"
        dependencias = _dato(None, estado, "despliegue_dependencias",
                             metodo="sin_permiso_o_desactivado" if estado == "no_consultable" else None)
        if "DEPENDENCIAS_NO_VERIFICADAS" not in adv:
            adv.append("DEPENDENCIAS_NO_VERIFICADAS")
    else:
        dependencias = _dato([{k: d[k] for k in ("activo_codigo", "criticidad", "ambiente", "tipo_dependencia")}
                              for d in deps], "verificado", "despliegue_dependencias", metodo="consulta_bd")

    if "INVENTARIO_NO_VIGENTE" in adv:
        inventario = _dato("no_vigente", "declarado_sin_evidencia", "recertificaciones")
    elif "INVENTARIO_SIN_CONCILIAR" in adv:
        inventario = _dato("vigente_sin_conciliar", "declarado_sin_evidencia", "recertificaciones")
    else:
        inventario = _dato("vigente_conciliado", "verificado", "recertificaciones")

    cvss_valor = [{"version": m["version"], "vector": str(m["vector"])[:200], "puntaje_base": float(m["score"]),
                   "fuente": str(m.get("source", ""))[:30]} for m in r.get("metricas_cvss_disponibles", [])]
    cvss_estado = ("declarado_sin_evidencia" if {"CVSS_NO_VERIFICADO_DIARIAMENTE", "ESTADO_NVD_NO_VALIDADO"} & set(adv)
                   else "verificado")
    ref_nvd = f"https://nvd.nist.gov/vuln/detail/{cve}"
    cvss = _dato(cvss_valor or None, cvss_estado if cvss_valor else "desconocido", "nvd", referencia=ref_nvd)

    en_kev = ctx.get("en_kev")
    kev_valor = None if en_kev is None else {"en_kev": bool(en_kev), "fecha_limite": ctx.get("kev_fecha_limite"),
                                             "uso_ransomware": ctx.get("uso_ransomware")}
    if en_kev is None:
        kev = _dato(None, "desconocido", "cisa_kev")
    elif "KEV_NO_VERIFICADO" in adv:
        kev = (_dato(kev_valor, "declarado_sin_evidencia", "cisa_kev") if en_kev
               else _dato(None, "desconocido", "cisa_kev", metodo="kev_no_verificado"))
    else:
        kev = _dato(kev_valor, "verificado", "cisa_kev", fecha_verificacion=hoy)

    if ctx.get("epss") is None:
        epss = _dato(None, "desconocido", "first_epss")
    else:
        ev_epss = {"puntaje": float(ctx["epss"]), "percentil": float(ctx.get("epss_percentil") or 0.0),
                   "fecha": str(ctx.get("epss_fecha"))[:10]}
        dias = _dias(ev_epss["fecha"], hoy)
        epss = _dato(ev_epss, "verificado" if dias is not None and dias <= MAX_DIAS_EPSS else "desconocido",
                     "first_epss", fecha_verificacion=ev_epss["fecha"])

    # --- Evaluacion determinista y antes/despues --------------------------------------------------------
    riesgo_res = r.get("riesgo_residual")
    razones = [{"codigo": x["regla"], "explicacion": str(x.get("explicacion", ""))[:500]} for x in r.get("razones", [])]
    razones.append({"codigo": "PRIORIDAD_CRUCE_A_MOTOR",
                    "explicacion": f"Antes (cruce): P{base}. Despues (motor): P{motor_p} de tipo {r.get('prioridad_tipo')}."})
    if final != motor_p:
        razones.append({"codigo": "PISO_CRUCE_RESPETADO",
                        "explicacion": f"El motor propuso P{motor_p}; el piso del cruce exige P{piso}."})

    # --- Evidencias numeradas (lo unico que el agente puede citar) --------------------------------------
    ev: list[dict] = []

    def add(tipo, descripcion, referencia=None):
        x = {"id": f"ev-{len(ev) + 1:02d}", "tipo": tipo, "descripcion": sanear(descripcion, 500)}
        if referencia:
            x["referencia"] = referencia
        ev.append(x)

    for m in cvss_valor:
        add("cvss", f"CVSS {m['version']} = {m['puntaje_base']} ({m['fuente']}), vector {m['vector']} "
                    f"[{cvss['estado_verificacion']}]", ref_nvd)
    cwe = [c for c in (ctx.get("cwe") or []) if RE_CWE.match(c)][:10]
    if cwe:
        add("cwe", ", ".join(cwe))
    if en_kev:
        texto_kev = "En CISA KEV" + (f", fecha limite {kev_valor['fecha_limite']}" if kev_valor["fecha_limite"] else "")
    elif kev["estado_verificacion"] == "verificado":
        texto_kev = "Fuera de CISA KEV"
    else:
        texto_kev = "KEV sin verificar: no se puede afirmar que este fuera de KEV"
    add("kev", f"{texto_kev} [{kev['estado_verificacion']}]")
    if epss["valor"]:
        add("epss", f"EPSS {epss['valor']['puntaje']:.5f}, percentil {epss['valor']['percentil']}, fecha "
                    f"{epss['valor']['fecha']} (senal poblacional a 30 dias) [{epss['estado_verificacion']}]")
    add("activo", f"Activo {codigo}: tipo {ctx.get('activo_tipo')}, criticidad {ctx.get('criticidad')}/5, "
                  f"informacion {ctx.get('clasificacion_informacion')}, dominio {ctx.get('dominio_negocio')}")
    add("exposicion", f"Exposicion {valor_exp or 'desconocida'} [{exposicion['estado_verificacion']}]")
    add("despliegue", f"Ambiente {ctx.get('ambiente')}, RTO {ctx.get('rto_minutes')} min, RPO {ctx.get('rpo_minutes')} min")
    add("dependencia", (f"{len(deps)} dependientes directos verificados" if deps is not None
                        else f"Dependencias {dependencias['estado_verificacion']}: no afirmar que hay cero dependientes"))
    add("inventario", f"Inventario {inventario['valor']} [{inventario['estado_verificacion']}]")
    add("componente", f"{ctx.get('vendor')} {ctx.get('producto_nombre')} version {ctx.get('componente_version')}")
    add("aplicabilidad", f"Aplicabilidad {r['estado_aplicabilidad']}; prioridad de {r.get('prioridad_tipo')}")
    add("comparacion_previa", f"Antes (cruce): P{base}" + (f", piso P{piso}" if piso else "") + f"; motor: P{motor_p}")

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
                         "snapshot_id": str((motor.get("snapshot") or {}).get("s3_clave") or "desconocido")[:120]},
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
                       "versiones_afectadas": None, "version_corregida": None},
        "vulnerabilidad": {"descripcion_no_confiable": sanear(ctx.get("descripcion"), 4000), "cwe": cwe,
                           "cvss": cvss, "kev": kev, "epss": epss},
        "evaluacion_determinista": {
            "origen": "filtro", "prioridad_base": base, "prioridad_piso": piso, "prioridad_final": final,
            "prioridad_tipo": r["prioridad_tipo"], "estado_aplicabilidad": r["estado_aplicabilidad"],
            # El motor usa R ordinal 1-9 y prohibe convertirlo a la escala 0-100 del cruce: no se reinterpreta.
            # El 0-100 del cruce viaja en comparacion_previa.
            "puntaje_riesgo": None, "estado_puntaje": "no_calculado",
            "riesgo_inherente": r.get("riesgo_inherente"), "riesgo_residual": riesgo_res,
            "probabilidad_tamizaje": None, "impacto_tamizaje": None,
            "advertencias": adv[:30], "razones": razones[:30]},
        "comparacion_previa": {"disponible": True, "prioridad": base, "puntaje_riesgo": cruce.get("puntaje_riesgo"),
                               "fecha": None, "origen": "cruce", "motivo": None},
        "contexto_negocio": {"version": str(modelo_negocio["version"])[:40], "sha256": sha256_json(modelo_negocio),
                             "aprobado": modelo_negocio.get("aprobado") is True},
        "evidencias": ev,
    }
