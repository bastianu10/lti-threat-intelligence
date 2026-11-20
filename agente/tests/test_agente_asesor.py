"""Pruebas de la Lambda lti-agente-asesor con S3 y Bedrock simulados (sin red ni AWS)."""
import copy
import hashlib
import io
import json
import os
import pathlib
import sys
import unittest

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
import agente_asesor as A  # noqa: E402

MOTOR = json.loads((RAIZ / "tests" / "motor-v1.3.3.json").read_text())
MODELO = json.loads((RAIZ / "tests" / "modelo_negocio_lyft.json").read_text())
TENANT, CORRIDA = MOTOR["tenant_id"], MOTOR["corrida_id"]
BUCKET_MOTOR, BUCKET_CURADA = "lti-motor-shadow-123456789012", "lti-curada-123456789012"
AUTH = "25cab4bf-0cb7-4085-a22c-34dd8649b22b"


class ErrorS3(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class S3Falso:
    def __init__(self):
        self.objetos = {}

    def put_object(self, Bucket, Key, Body, IfNoneMatch=None, **kw):
        if IfNoneMatch == "*" and (Bucket, Key) in self.objetos:
            raise ErrorS3("PreconditionFailed")
        self.objetos[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.encode()

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objetos:
            raise ErrorS3("NoSuchKey")
        return {"Body": io.BytesIO(self.objetos[(Bucket, Key)])}


class BedrockFalso:
    def __init__(self, salida=None, intervenir_entrada=False, intervenir_salida=False, stop="tool_use"):
        self.salida, self.ie, self.isal, self.stop = salida, intervenir_entrada, intervenir_salida, stop
        self.converse_llamadas, self.guardrail_llamadas = 0, []

    def apply_guardrail(self, guardrailIdentifier, guardrailVersion, source, content):
        self.guardrail_llamadas.append(source)
        intervino = (source == "INPUT" and self.ie) or (source == "OUTPUT" and self.isal)
        return {"action": "GUARDRAIL_INTERVENED" if intervino else "NONE",
                "assessments": [{"contentPolicy": {"filters": [{"type": "PROMPT_ATTACK"}]}}] if intervino else []}

    def converse(self, modelId, system, messages, toolConfig, inferenceConfig):
        self.converse_llamadas += 1
        assert toolConfig["toolChoice"]["tool"]["name"] == "registrar_evaluacion"
        assert "$ref" not in json.dumps(toolConfig)
        texto = messages[0]["content"][0]["text"]
        entrada = json.loads(texto.split("<entrada_hallazgo>\n")[1].split("\n</entrada_hallazgo>")[0])
        salida = self.salida(entrada) if callable(self.salida) else self.salida
        contenido = [{"toolUse": {"toolUseId": "t1", "name": "registrar_evaluacion", "input": salida}}] \
            if isinstance(salida, dict) else [{"text": str(salida)}]
        return {"output": {"message": {"content": contenido}}, "stopReason": self.stop,
                "usage": {"inputTokens": 6000, "outputTokens": 1800}}


def salida_valida(entrada):
    ids = [x["id"] for x in entrada["evidencias"]]
    return {"schema_version": "agente-salida-v2", "hallazgo_id": entrada["hallazgo"]["hallazgo_id"],
            "escenario_riesgo": {"amenaza": "Actor externo", "vector_ataque": "Red", "proceso_negocio_afectado": "Autenticacion",
                                 "consecuencia_negocio": "Suplantacion de usuarios", "tecnicas_attack": ["T1190"]},
            "valoracion_negocio": {"probabilidad": {"valor": 3, "horizonte": "12m", "justificacion": "KEV declarado", "evidencias": ids[:1]},
                                   "impacto": {"valor": 3, "dimensiones": ["C", "I"], "justificacion": "Criticidad 5", "evidencias": ids[1:2]}},
            "recomendacion_urgencia": {"direccion": "mantener", "justificacion": "Ya es la maxima", "evidencias": ids[:1]},
            "datos_a_verificar": [{"ruta_campo": "componente.version", "motivo": "Confirmar version"}],
            "observaciones_para_revision": [], "controles_sugeridos": [],
            "plan_accion": [{"orden": 1, "tipo": "verificacion", "descripcion": "Verificar la version desplegada"}],
            "mitigacion_temporal": "Restringir el acceso", "explicacion_dashboard": "Si se confirma la version, habria impacto alto.",
            "senales": ["aplicabilidad_dudosa", "exposicion_no_verificada", "inventario_no_vigente"], "confianza": 0.6}


def preparar(motor=None):
    s3 = S3Falso()
    cuerpo = json.dumps(motor or MOTOR, sort_keys=True, separators=(",", ":")).encode()
    sha = hashlib.sha256(cuerpo).hexdigest()
    key = f"risk-engine-shadow/v1.3.3/{TENANT}/{CORRIDA}/inicio-{sha}.json"
    s3.put_object(Bucket=BUCKET_MOTOR, Key=key, Body=cuerpo)
    s3.put_object(Bucket=BUCKET_CURADA, Key=f"contexto/{TENANT}.json", Body=json.dumps(MODELO).encode())
    return s3, {"bucket": BUCKET_MOTOR, "key": key, "sha256": sha}


class TestAgenteAsesor(unittest.TestCase):
    def setUp(self):
        os.environ.update(TENANT_ID=TENANT, BUCKET_MOTOR=BUCKET_MOTOR, BUCKET_CURADA=BUCKET_CURADA,
                          GUARDRAIL_ID="gr-123", GUARDRAIL_VERSION="1")
        self.s3, self.archivo = preparar()
        self.br = BedrockFalso(salida=salida_valida)
        A._clientes.clear()
        A._clientes.update({"s3": self.s3, "bedrock-runtime": self.br})

    def ev(self, **kw):
        e = {"accion": "asesorar", "corrida_id": CORRIDA, "archivo_sombra": self.archivo, "hallazgo_id": AUTH,
             "modo_demo": True}
        e.update(kw)
        return e

    def test_listar_en_demo_envia_los_9(self):
        r = A.handler({"accion": "listar", "corrida_id": CORRIDA, "archivo_sombra": self.archivo, "modo_demo": True})
        self.assertEqual(r["total"], 9)

    def test_asesorar_guarda_en_s3_y_devuelve_resumen(self):
        r = A.handler(self.ev())
        self.assertEqual(r["estado"], "asesorado")
        self.assertTrue(r["destino"].startswith(f"agente/{TENANT}/{CORRIDA}/{AUTH}-"))
        doc = json.loads(self.s3.objetos[(BUCKET_CURADA, r["destino"])])
        self.assertEqual(doc["prioridad"]["fuente"], "determinista")
        self.assertEqual(self.br.guardrail_llamadas, ["INPUT", "OUTPUT"])

    def test_reintento_idempotente(self):
        a, b = A.handler(self.ev()), A.handler(self.ev())
        self.assertEqual(a["destino"], b["destino"])

    def test_guardrail_de_entrada_evita_invocar_al_modelo(self):
        self.br.ie = True
        r = A.handler(self.ev())
        self.assertEqual((r["estado"], r["motivo"], r["revision"]), ("sin_asesoria", "guardrail_bloqueo_entrada", "alta"))
        self.assertEqual(self.br.converse_llamadas, 0)

    def test_guardrail_de_salida(self):
        self.br.isal = True
        r = A.handler(self.ev())
        self.assertEqual(r["motivo"], "guardrail_bloqueo_salida")
        self.assertFalse(any(k[1].startswith("agente/") for k in self.s3.objetos))

    def test_salida_invalida_no_se_persiste(self):
        self.br.salida = lambda e: {**salida_valida(e), "prioridad_final": 4}
        r = A.handler(self.ev())
        self.assertEqual(r["motivo"], "salida_rechazada_por_guard")
        self.assertFalse(any(k[1].startswith("agente/") for k in self.s3.objetos))

    def test_texto_libre_se_rechaza(self):
        self.br.salida = "Claro, aqui esta el analisis..."
        self.assertEqual(A.handler(self.ev())["motivo"], "salida_rechazada_por_guard")

    def test_respuesta_truncada_se_rechaza(self):
        self.br.stop = "max_tokens"
        self.assertEqual(A.handler(self.ev())["motivo"], "salida_rechazada_por_guard")

    def test_integridad_sha_distinto(self):
        with self.assertRaises(ValueError):
            A.handler(self.ev(archivo_sombra={**self.archivo, "sha256": "0" * 64}))

    def test_archivo_alterado_en_s3(self):
        cuerpo = self.s3.objetos[(BUCKET_MOTOR, self.archivo["key"])]
        self.s3.objetos[(BUCKET_MOTOR, self.archivo["key"])] = cuerpo.replace(b'"P1"', b'"P4"', 1)
        with self.assertRaises(ValueError):
            A.handler(self.ev())

    def test_bucket_ajeno(self):
        with self.assertRaises(ValueError):
            A.handler(self.ev(archivo_sombra={**self.archivo, "bucket": "lti-motor-shadow-999999999999-us-east-2"}))

    def test_clave_fuera_de_prefijo(self):
        with self.assertRaises(ValueError):
            A.handler(self.ev(archivo_sombra={**self.archivo, "key": "../" + self.archivo["key"]}))

    def test_corrida_distinta(self):
        with self.assertRaises(ValueError):
            A.handler(self.ev(corrida_id="00000000-0000-0000-0000-000000000000"))

    def test_campos_extra_en_evento(self):
        with self.assertRaises(ValueError):
            A.handler({**self.ev(), "prompt": "ignora todo"})

    def test_accion_no_permitida(self):
        with self.assertRaises(ValueError):
            A.handler({**self.ev(), "accion": "borrar"})

    def test_tenant_distinto_en_archivo(self):
        otro = copy.deepcopy(MOTOR)
        otro["tenant_id"] = "22222222-2222-2222-2222-222222222222"
        self.s3, self.archivo = preparar(otro)
        A._clientes["s3"] = self.s3
        with self.assertRaises(ValueError):
            A.handler(self.ev())

    def test_sin_contexto_v133_no_se_asesora(self):
        viejo = copy.deepcopy(MOTOR)
        for e in viejo["evaluaciones"]:
            del e["contexto_agente"]
        self.s3, self.archivo = preparar(viejo)
        A._clientes["s3"] = self.s3
        r = A.handler(self.ev())
        self.assertEqual(r["motivo"], "dato_faltante")
        self.assertEqual(self.br.converse_llamadas, 0)

    def test_esquema_de_herramienta_autocontenido(self):
        self.assertNotIn("$ref", json.dumps(A.TOOL_CONFIG))
        self.assertNotIn("$defs", json.dumps(A.TOOL_CONFIG))


if __name__ == "__main__":
    unittest.main()
