"""Genera un archivo con la FORMA EXACTA de la salida del motor v1.3.3 (etapa A) a partir de la salida REAL
v1.3.2.1 de la corrida 2f9ed42d.

Real: hallazgo_id, CVE, activo, CVSS, prioridad y tipo del motor, aplicabilidad, advertencias, razones, hashes.
SIMULADO (hasta que el equipo del motor despliegue v1.3.3): bloques `contexto_agente`, `cruce` y
dependencias, estimados del diagrama de arquitectura. El archivo lo declara en `_simulado`.

Cuando exista la salida real v1.3.3, se reemplaza insumos/motor-v1.3.3.json y NADA mas cambia.
"""
import copy
import json
import pathlib
import sys

RAIZ = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(RAIZ / "lambda"))
from agente_priorizacion.adaptador_v2_1 import cargar_politica, sha256_json  # noqa: E402
POLITICA = cargar_politica()
real = json.loads((RAIZ / "insumos" / "motor-v1.3.2.1-real.json").read_text())

ACTIVOS = {  # tipo, capa, dominio, criticidad, clasificacion, expuesto, rto, rpo
    "auth-oidc": ("servicio", "aplicacion", "ti", 5, "restringida", True, 30, 5),
    "alb-envoy": ("red", "red", "ti", 5, "confidencial", True, 15, 0),
    "notifications": ("servicio", "aplicacion", "finanzas_y_negocios", 3, "confidencial", False, 240, 60),
    "lock-orchestrator": ("servicio", "aplicacion", "ti", 5, "confidencial", False, 15, 5),
    "trip-service": ("servicio", "aplicacion", "ti", 4, "confidencial", False, 30, 5),
}
DEPENDIENTES = {
    "auth-oidc": [("trip-service", 4, "autenticacion"), ("lock-orchestrator", 5, "autenticacion"),
                  ("notifications", 3, "autenticacion")],
    "alb-envoy": [("auth-oidc", 5, "red"), ("trip-service", 4, "red")],
    "notifications": [],
    "lock-orchestrator": [("trip-service", 4, "ejecucion")],
    "trip-service": [("notifications", 3, "datos")],
}
VULN = {
    "CVE-2026-111497": ("envoyproxy", "envoy", "1.30.2", ["CWE-287"], True, "2026-12-09",
                        "Improper authentication in the JWT authentication filter allows a remote unauthenticated "
                        "attacker to bypass token validation when a specific provider configuration is present.",
                        0.0123, 0.871),
    "CVE-2026-42501": ("golang", "go", "1.22", ["CWE-787"], False, None,
                       "A crafted response processed by the HTTP client may lead to memory corruption when a "
                       "user-initiated request reaches an attacker-controlled endpoint.", 0.0041, 0.62),
    "CVE-2026-39817": ("golang", "go", "1.22", ["CWE-269"], False, None,
                       "A local user with low privileges may escalate privileges through a crafted configuration "
                       "file processed by the runtime, affecting resources beyond the vulnerable component.",
                       0.0011, 0.31),
    "CVE-2026-39819": ("golang", "go", "1.22", ["CWE-367"], False, None,
                       "A local user with low privileges may tamper with temporary files created by the runtime "
                       "under a race condition.", 0.0009, 0.25),
}
CRUCE = {"CVE-2026-111497": (1, 1, 100.0), "CVE-2026-42501": (2, None, 70.0),
         "CVE-2026-39817": (3, None, 45.0), "CVE-2026-39819": (3, None, 40.0)}

salida = copy.deepcopy(real)
salida["schema_version"] = "risk-engine-aws-v1.3.3"
salida["politica_verificacion"] = {"version": POLITICA["version"], "sha256": sha256_json(POLITICA)}
salida["_simulado"] = ("contexto_agente, cruce y dependencias ESTIMADOS desde la arquitectura; el resto es la "
                       "salida real v1.3.2.1 de la corrida 2f9ed42d")
salida["fuentes_no_lectura"] = []                     # etapa A: lee historial y dependencias
salida["evidencia_bd_habilitada"] = False             # etapa B aun no
salida["assessed_at"] = salida.get("assessed_at") or "2026-11-19T00:00:00+00:00"
for ev in salida["evaluaciones"]:
    r = ev["resultado"]
    t, capa, dom, crit, clas, exp, rto, rpo = ACTIVOS[r["asset_code"]]
    vendor, prod, ver, cwe, kev, limite, desc, epss, pct = VULN[r["cve"]]
    base, piso, puntaje = CRUCE[r["cve"]]
    ev["contexto_agente"] = {
        "metodo_deteccion": "cruce_exacto", "hallazgo_estado": "pendiente_aprobacion_dueno", "activo_tipo": t,
        "capa": capa, "dominio_negocio": dom, "criticidad": crit, "clasificacion_informacion": clas,
        "ambiente": "produccion", "expuesto_internet": exp, "rto_minutes": rto, "rpo_minutes": rpo,
        "vendor": vendor, "producto_nombre": prod, "componente_version": ver, "descripcion": desc, "cwe": cwe,
        "en_kev": kev, "kev_fecha_limite": limite, "uso_ransomware": False if kev else None,
        "epss": epss, "epss_percentil": pct, "epss_fecha": "2026-11-18",
        "dependientes_directos": [{"activo_codigo": c, "criticidad": k, "ambiente": "produccion", "tipo_dependencia": d}
                                  for c, k, d in DEPENDIENTES[r["asset_code"]]],
    }
    ev["cruce"] = {"prioridad_base": base, "prioridad_piso": piso, "prioridad_final": base, "puntaje_riesgo": puntaje,
                   "corrida_id_origen": salida["corrida_id"], "fecha": "2026-11-19T12:04:00+00:00", "misma_corrida": True}
    ev["evidencia_autenticada"] = {"aplicabilidad": [], "exposicion": None}
    r.setdefault("accion_automatica_autorizada", False)
    # --- Contrato v2.1: el motor es la autoridad de la prioridad y de los estados de verificacion ---
    motor_p = int(str(r["prioridad_operativa"]).lstrip("P"))
    piso_kev = 1 if kev else None
    pisos = [p for p in (piso_kev, piso) if p is not None]
    r["prioridad_piso_efectivo"] = min(pisos) if pisos else None
    r["origen_piso"] = ("kev" if piso_kev == r["prioridad_piso_efectivo"] else "cruce") if pisos else None
    r["prioridad_final"] = min([motor_p] + pisos)
    r["probabilidad_tamizaje"], r["impacto_tamizaje"] = None, None
    hoy = salida["assessed_at"][:10]
    c = ev["contexto_agente"]
    c["inventario_estado"] = "vigente_sin_conciliar"
    c["verificacion"] = {
        "exposicion": {"estado": "declarado_sin_evidencia", "fuente": "inventario_manual", "referencia": None,
                       "fecha_verificacion": None, "metodo": None},
        "dependencias": {"estado": "verificado", "fuente": "despliegue_dependencias", "referencia": None,
                         "fecha_verificacion": hoy, "metodo": "consulta_bd"},
        "inventario": {"estado": "declarado_sin_evidencia", "fuente": "recertificaciones", "referencia": None,
                       "fecha_verificacion": "2026-10-01", "metodo": "recertificacion"},
        "cvss": {"estado": "declarado_sin_evidencia", "fuente": "nvd", "referencia": None,
                 "fecha_verificacion": None, "metodo": None},
        "kev": ({"estado": "declarado_sin_evidencia", "fuente": "cisa_kev", "referencia": None,
                 "fecha_verificacion": None, "metodo": None} if kev else
                {"estado": "desconocido", "fuente": "cisa_kev", "referencia": None, "fecha_verificacion": None, "metodo": None}),
        "epss": {"estado": "verificado", "fuente": "first_epss", "referencia": None,
                 "fecha_verificacion": "2026-11-18", "metodo": "api_first"},
    }
(RAIZ / "insumos" / "motor-v1.3.3.json").write_text(json.dumps(salida, ensure_ascii=False, indent=1))
print(f"OK insumos/motor-v1.3.3.json ({len(salida['evaluaciones'])} evaluaciones, SIMULADO)")
