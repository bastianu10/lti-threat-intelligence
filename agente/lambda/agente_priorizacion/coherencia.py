"""Coherencia determinista de la recomendacion de urgencia (regla 7 del prompt v2.6), comun a la Lambda y a las pruebas.

El modelo puede citar mal la regla (p. ej. "se cumple la condicion b con P>=1"). Por eso, despues del output guard, la
Lambda comprueba las condiciones con los DATOS de la entrada y con la P/I que el propio agente propuso:

  a. KEV declarado            b. P >= 2 e I = 3           c. exposicion a internet declarada con vector de red
  d. dependientes criticos (criticidad 4-5) verificados    e. comparacion previa mas urgente que la prioridad final

Si la recomendacion efectiva es "escalar" y no se cumple ninguna, se registra "mantener" y el motivo
"escalar_sin_condicion" (la propuesta original del agente se conserva para el dueno). Nunca cambia la prioridad,
nunca convierte nada en "escalar" ni en "revisar_a_la_baja": solo puede volver la recomendacion mas conservadora.
"""
from __future__ import annotations

import copy

VERSION = "coherencia-v1"


def condiciones_escalar(entrada: dict, p: int, i: int) -> list[str]:
    ed, vul, dep = entrada["evaluacion_determinista"], entrada["vulnerabilidad"], entrada["despliegue"]
    kev = ((vul.get("kev") or {}).get("valor") or {}).get("en_kev") is True
    red = any("/AV:N" in str(m.get("vector", "")) for m in ((vul.get("cvss") or {}).get("valor") or []))
    internet = (dep.get("exposicion") or {}).get("valor") == "internet"
    deps = dep.get("dependencias") or {}
    criticos = deps.get("estado_verificacion") == "verificado" and any(
        (d.get("criticidad") or 0) >= 4 for d in (deps.get("valor") or []))
    cp = entrada.get("comparacion_previa") or {}
    previa = bool(cp.get("disponible")) and isinstance(cp.get("prioridad"), int) and cp["prioridad"] < ed["prioridad_final"]
    return [codigo for codigo, ok in (("a_kev", kev), ("b_p2_i3", p >= 2 and i == 3), ("c_internet_red", internet and red),
                                      ("d_dependientes_criticos", criticos), ("e_previa_mas_urgente", previa)) if ok]


def normalizar_escalar(entrada: dict, res: dict) -> dict:
    """Devuelve una copia de la resolucion del guard con la recomendacion coherente con la regla 7."""
    if res.get("estado") != "aceptada":
        return res
    s = res["salida_validada"]
    p, i = s["valoracion_negocio"]["probabilidad"]["valor"], s["valoracion_negocio"]["impacto"]["valor"]
    condiciones = condiciones_escalar(entrada, p, i)
    out = copy.deepcopy(res)
    out["coherencia"] = {"version": VERSION, "condiciones_escalar": condiciones, "normalizada": False}
    if out["recomendacion"]["efectiva"] == "escalar" and not condiciones:
        out["recomendacion"]["efectiva"] = "mantener"
        out["coherencia"]["normalizada"] = True
        out["revision"]["motivos"] = list(out["revision"]["motivos"]) + ["escalar_sin_condicion"]
        out["revision"]["requerida"] = True
    return out
