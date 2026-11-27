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
import re

VERSION = "coherencia-v3"


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


def marcar_dominio(entrada: dict, res: dict, modelo_negocio: dict) -> dict:
    """Si el dominio del activo no esta en el modelo de negocio, lo deja visible en la revision (motivo determinista).

    El adaptador ya entrega la evidencia "el dominio no esta definido"; esto garantiza que el dueno lo vea aunque el
    modelo de lenguaje no lo mencione. No cambia la prioridad ni la recomendacion.
    """
    if res.get("estado") != "aceptada":
        return res
    dominio = entrada["activo"].get("dominio_negocio")
    definidos = {d.get("codigo") for d in modelo_negocio.get("dominios", [])}
    out = copy.deepcopy(res)
    out.setdefault("coherencia", {"version": VERSION})["dominio_en_modelo"] = dominio in definidos
    if dominio not in definidos:
        out["revision"]["motivos"] = list(out["revision"]["motivos"]) + ["dominio_sin_modelo_negocio"]
        out["revision"]["requerida"] = True
    return out


# El texto del dashboard EXPLICA la prioridad del motor (es parte de la funcion del agente), pero no puede contradecirla
# ni asignar un nivel de riesgo propio: R = P x I solo lo calcula el motor despues de la aprobacion del dueno.
PATRON_PRIORIDAD = re.compile(r"\bP([1-4])\b")
PATRON_NIVEL = re.compile(r"\briesgo (alto|medio|bajo|inaceptable|cr[ií]tico)\b", re.I)


def revisar_texto(entrada: dict, texto: str) -> list[str]:
    """Motivos de revision por el texto del dashboard (lista vacia = coherente)."""
    final = entrada["evaluacion_determinista"]["prioridad_final"]
    motivos = []
    if any(int(m.group(1)) != final for m in PATRON_PRIORIDAD.finditer(texto)):
        motivos.append("texto_contradice_prioridad_motor")
    if PATRON_NIVEL.search(texto):
        motivos.append("texto_asigna_nivel_riesgo")
    return motivos


def marcar_texto(entrada: dict, res: dict) -> dict:
    """Deja visible en la revision un texto que contradice al motor. No reescribe el texto del modelo."""
    if res.get("estado") != "aceptada":
        return res
    out = copy.deepcopy(res)
    motivos = revisar_texto(entrada, out["salida_validada"].get("explicacion_dashboard", ""))
    out.setdefault("coherencia", {"version": VERSION})["texto"] = motivos
    if motivos:
        out["revision"]["motivos"] = list(out["revision"]["motivos"]) + motivos
        out["revision"]["requerida"] = True
    return out
