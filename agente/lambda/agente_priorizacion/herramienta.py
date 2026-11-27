"""Configuracion de la herramienta registrar_evaluacion (salida estructurada forzada), comun a la Lambda y a las pruebas.

La salida sigue validandose contra el contrato agente-salida-v2 completo en el output guard. Aqui solo se ACOTA, por
caso, el enum de recomendacion_urgencia.direccion a los valores con sentido para esa evaluacion determinista:
  - prioridad_final 1                       -> solo "mantener" (escalar no tiene efecto; regla 1 del prompt v2.6)
  - aplicabilidad no confirmada             -> "escalar" o "mantener" (modo investigacion: nunca baja)
  - en otro caso                            -> el enum completo del contrato
Es una restriccion determinista que no depende de que el modelo obedezca el prompt. El guard conserva sus propias
reglas (por ejemplo, normaliza escalar en P1 y bloquea bajas sin evidencia), como segunda linea de defensa.
"""
from __future__ import annotations

import copy
import json
import pathlib

HERRAMIENTA = "registrar_evaluacion"
_ESQUEMA = json.loads((pathlib.Path(__file__).resolve().parent / "contrato" / "salida.v2.schema.json").read_text("utf-8"))


def _sin_refs(nodo, raiz):
    """Esquema autocontenido para la herramienta: resuelve $ref locales y quita $schema/$id/$defs."""
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


_BASE = _sin_refs(_ESQUEMA, _ESQUEMA)
DIRECCIONES = tuple(_BASE["properties"]["recomendacion_urgencia"]["properties"]["direccion"]["enum"])


def direcciones_permitidas(entrada: dict) -> list[str]:
    ed = entrada["evaluacion_determinista"]
    if ed.get("prioridad_final") == 1:
        return ["mantener"]
    if ed.get("estado_aplicabilidad") != "confirmed":
        return [d for d in DIRECCIONES if d != "revisar_a_la_baja"]
    return list(DIRECCIONES)


def config_herramienta(entrada: dict, descripcion: str = "Registra la evaluacion asesora del hallazgo (contrato agente-salida-v2).") -> dict:
    esquema = copy.deepcopy(_BASE)
    esquema["properties"]["recomendacion_urgencia"]["properties"]["direccion"]["enum"] = direcciones_permitidas(entrada)
    return {"tools": [{"toolSpec": {"name": HERRAMIENTA, "description": descripcion, "inputSchema": {"json": esquema}}}],
            "toolChoice": {"tool": {"name": HERRAMIENTA}}}
