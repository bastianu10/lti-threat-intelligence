"""Fixtures v2.1: la entrada se construye con el ADAPTADOR REAL desde la salida (simulada) del motor v1.3.3,
caso CVE-2026-111497 en auth-oidc (KEV, P1). La salida es una respuesta valida del agente para ese caso."""
import copy
import json
import pathlib
import sys

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
from agente_priorizacion.adaptador_v2_1 import construir_entrada  # noqa: E402

MOTOR = json.loads((RAIZ / "insumos" / "motor-v1.3.3.json").read_text())
MODELO = json.loads((RAIZ / "contexto" / "modelo_negocio_lyft.json").read_text())
AUTH = "25cab4bf-0cb7-4085-a22c-34dd8649b22b"
_EV = next(e for e in MOTOR["evaluaciones"] if e["resultado"]["case_id"] == AUTH)
ENTRADA = construir_entrada(MOTOR, copy.deepcopy(_EV), MODELO, tenant_id=MOTOR["tenant_id"], modo_demo=True)

SALIDA = {
    "schema_version": "agente-salida-v2",
    "hallazgo_id": AUTH,
    "escenario_riesgo": {
        "amenaza": "Actor externo no autenticado con capacidad de explotar fallas de autenticacion",
        "vector_ataque": "Peticiones de red al filtro JWT del servicio de autenticacion expuesto",
        "proceso_negocio_afectado": "Inicio de sesion de usuarios y autorizacion de viajes y pagos",
        "consecuencia_negocio": "Suplantacion de usuarios, viajes y cobros no autorizados, y perdida de confianza.",
        "tecnicas_attack": ["T1190", "T1078"]},
    "valoracion_negocio": {
        "probabilidad": {"valor": 3, "horizonte": "12m", "justificacion": "Esta en KEV y el vector es de red.",
                         "evidencias": ["ev-01", "ev-02"]},
        "impacto": {"valor": 3, "dimensiones": ["C", "I"], "justificacion": "Criticidad 5 y proceso critico.",
                    "evidencias": ["ev-03", "ev-06"]}},
    "recomendacion_urgencia": {"direccion": "mantener", "justificacion": "Ya tiene la maxima urgencia.",
                               "evidencias": ["ev-02"]},
    "datos_a_verificar": [{"ruta_campo": "componente.version", "motivo": "Confirmar la version desplegada"},
                          {"ruta_campo": "despliegue.exposicion", "motivo": "Confirmar la exposicion real"}],
    "observaciones_para_revision": [],
    "controles_sugeridos": [{"tipo": "detectivo", "descripcion": "Alertar validaciones JWT fallidas anomalas"}],
    "plan_accion": [{"orden": 1, "tipo": "verificacion", "descripcion": "Verificar la version exacta de Envoy"},
                    {"orden": 2, "tipo": "correccion", "descripcion": "Actualizar segun el aviso oficial del fabricante"},
                    {"orden": 3, "tipo": "validacion", "descripcion": "Validar que el filtro rechace tokens invalidos"}],
    "mitigacion_temporal": "Restringir y monitorear el acceso al endpoint de autenticacion.",
    "explicacion_dashboard": "Si se confirma la version afectada, un atacante podria suplantar usuarios.",
    "senales": ["aplicabilidad_dudosa", "exposicion_no_verificada", "inventario_no_vigente", "requiere_validacion_dueno"],
    "confianza": 0.6,
}


def entrada():
    return copy.deepcopy(ENTRADA)


def salida():
    return copy.deepcopy(SALIDA)
