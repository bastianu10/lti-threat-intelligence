"""Validador de JSON Schema (subconjunto de draft 2020-12), solo con la biblioteca estandar.

Por que existe: el guard corre en una Lambda sin dependencias y los esquemas del contrato deben ser la
UNICA fuente de verdad (si el codigo duplicara las reglas, ambos divergirian). Soporta exactamente lo que
usan los esquemas del contrato: type, const, enum, pattern, minLength/maxLength, minimum/maximum,
required, properties, additionalProperties=false, items, minItems/maxItems, uniqueItems, $ref local,
allOf y oneOf. Un booleano nunca cuenta como entero ni como numero (en Python, True == 1).
"""
from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from typing import Any

_TIPOS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


@lru_cache(maxsize=256)
def _re(patron: str):
    return re.compile(patron)


def _igual(a: Any, b: Any) -> bool:
    """Igualdad estricta: True no es 1, y 1.0 no es 1 (un enum de enteros no acepta flotantes)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return type(a) is type(b) and a == b
    return a == b and (a is None) == (b is None)


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


class Validador:
    def __init__(self, esquema: dict):
        self.raiz = esquema

    def _resolver(self, ref: str) -> dict:
        if not ref.startswith("#/"):
            raise ValueError(f"solo se admiten $ref locales: {ref}")
        nodo: Any = self.raiz
        for parte in ref[2:].split("/"):
            nodo = nodo[parte]
        return nodo

    def errores(self, dato: Any, esquema: dict | None = None, ruta: str = "$", limite: int = 50) -> list[str]:
        salida: list[str] = []
        self._validar(dato, self.raiz if esquema is None else esquema, ruta, salida)
        return salida[:limite]

    def _validar(self, v: Any, s: dict, ruta: str, err: list[str]) -> None:
        if "$ref" in s:
            self._validar(v, self._resolver(s["$ref"]), ruta, err)
        for sub in s.get("allOf", []):
            self._validar(v, sub, ruta, err)
        if "oneOf" in s:
            validos = sum(1 for sub in s["oneOf"] if not self._sub(v, sub, ruta))
            if validos != 1:
                err.append(f"{ruta}: debe cumplir exactamente una alternativa (cumple {validos})")
        if "const" in s and not _igual(v, s["const"]):
            err.append(f"{ruta}: se esperaba {s['const']!r}")
        if "enum" in s and not any(_igual(v, x) for x in s["enum"]):
            err.append(f"{ruta}: valor no permitido {v!r}")
        if "type" in s:
            tipos = s["type"] if isinstance(s["type"], list) else [s["type"]]
            if not any(_TIPOS[t](v) for t in tipos):
                err.append(f"{ruta}: se esperaba {'|'.join(tipos)}")
                return
        if isinstance(v, str):
            if "minLength" in s and len(v) < s["minLength"]:
                err.append(f"{ruta}: longitud menor a {s['minLength']}")
            if "maxLength" in s and len(v) > s["maxLength"]:
                err.append(f"{ruta}: longitud mayor a {s['maxLength']}")
            if "pattern" in s and not _re(s["pattern"]).search(v):
                err.append(f"{ruta}: no cumple el patron")
        if _TIPOS["number"](v):
            if "minimum" in s and v < s["minimum"]:
                err.append(f"{ruta}: menor que {s['minimum']}")
            if "maximum" in s and v > s["maximum"]:
                err.append(f"{ruta}: mayor que {s['maximum']}")
        if isinstance(v, dict):
            for k in s.get("required", []):
                if k not in v:
                    err.append(f"{ruta}: falta '{k}'")
            props = s.get("properties", {})
            if s.get("additionalProperties") is False:
                for k in v:
                    if k not in props:
                        err.append(f"{ruta}: campo no permitido '{k}'")
            for k, sub in props.items():
                if k in v:
                    self._validar(v[k], sub, f"{ruta}.{k}", err)
        if isinstance(v, list):
            if "minItems" in s and len(v) < s["minItems"]:
                err.append(f"{ruta}: menos de {s['minItems']} elementos")
            if "maxItems" in s and len(v) > s["maxItems"]:
                err.append(f"{ruta}: mas de {s['maxItems']} elementos")
            if s.get("uniqueItems") and len({_canon(x) for x in v}) != len(v):
                err.append(f"{ruta}: elementos repetidos")
            if "items" in s:
                for i, x in enumerate(v):
                    self._validar(x, s["items"], f"{ruta}[{i}]", err)

    def _sub(self, v: Any, s: dict, ruta: str) -> list[str]:
        e: list[str] = []
        self._validar(v, s, ruta, e)
        return e
