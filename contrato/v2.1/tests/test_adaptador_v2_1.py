"""Pruebas del adaptador v2.1 (motor v1.3.3 acordado -> agente-entrada-v2.1)."""
import copy
import json
import pathlib
import sys
import unittest

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
from agente_priorizacion.adaptador_v2_1 import (DatoFaltante, InconsistenciaMotor, cargar_politica,  # noqa: E402
                                                construir_entrada, sanear)
from agente_priorizacion.output_guard_v2_1 import validar_entrada  # noqa: E402

MOTOR = json.loads((RAIZ / "insumos" / "motor-v1.3.3.json").read_text())
MODELO = json.loads((RAIZ / "contexto" / "modelo_negocio_lyft.json").read_text())
TENANT = MOTOR["tenant_id"]
AUTH = "25cab4bf-0cb7-4085-a22c-34dd8649b22b"     # CVE-2026-111497 en auth-oidc (KEV, P1)
NOTIF = "c2eacbd1-d337-4711-8f19-4987472b06d8"    # notifications: motor P2, piso KEV P1
TRIP = "53616cce-e721-4f80-a4e1-0df03349b980"     # CVE-2026-39819 en trip-service, P3


def ev(case_id):
    return copy.deepcopy(next(e for e in MOTOR["evaluaciones"] if e["resultado"]["case_id"] == case_id))


def construir(e, motor=None, **kw):
    kw.setdefault("modo_demo", True)
    return construir_entrada(motor or MOTOR, e, MODELO, tenant_id=TENANT, **kw)


def ver(e, campo, **cambios):
    e["contexto_agente"]["verificacion"][campo].update(cambios)
    return e


class TestContratoYAutoridad(unittest.TestCase):
    def test_los_9_casos_cumplen_el_contrato_v21(self):
        for x in MOTOR["evaluaciones"]:
            self.assertEqual(validar_entrada(construir(copy.deepcopy(x))), [], x["resultado"]["case_id"])

    def test_usa_la_prioridad_final_del_motor_sin_recalcular(self):
        e = ev(TRIP)
        e["resultado"]["prioridad_operativa"] = "P4"        # el adaptador ya no lee este campo
        e["resultado"]["prioridad_final"] = 2
        self.assertEqual(construir(e)["evaluacion_determinista"]["prioridad_final"], 2)

    def test_sin_prioridad_final_del_motor_no_se_envia(self):
        e = ev(TRIP)
        del e["resultado"]["prioridad_final"]
        with self.assertRaises(DatoFaltante):
            construir(e)

    def test_prioridad_booleana_no_es_entero(self):
        e = ev(TRIP)
        e["resultado"]["prioridad_final"] = True
        with self.assertRaises(DatoFaltante):
            construir(e)

    def test_motor_que_perfora_su_piso_es_inconsistente(self):
        e = ev(NOTIF)
        e["resultado"]["prioridad_final"] = 2               # piso efectivo P1 (KEV)
        with self.assertRaises(InconsistenciaMotor):
            construir(e)

    def test_motor_que_perfora_el_piso_del_cruce_es_inconsistente(self):
        e = ev(TRIP)
        e["cruce"]["prioridad_piso"] = 2                    # motor entrega P3
        with self.assertRaises(InconsistenciaMotor):
            construir(e)

    def test_piso_efectivo_y_origen_viajan_del_motor(self):
        d = construir(ev(NOTIF))["evaluacion_determinista"]
        self.assertEqual((d["prioridad_final"], d["prioridad_piso_efectivo"], d["origen_piso"], d["origen"]),
                         (1, 1, "kev", "motor"))

    def test_p_e_i_de_tamizaje_se_copian_y_se_validan(self):
        e = ev(TRIP)
        e["resultado"].update(probabilidad_tamizaje=2, impacto_tamizaje=3)
        d = construir(e)["evaluacion_determinista"]
        self.assertEqual((d["probabilidad_tamizaje"], d["impacto_tamizaje"]), (2, 3))
        e["resultado"]["impacto_tamizaje"] = 5
        with self.assertRaises(DatoFaltante):
            construir(e)

    def test_politica_distinta_o_ausente(self):
        for valor in ({"version": "x", "sha256": "0" * 64}, None):
            motor = copy.deepcopy(MOTOR)
            motor["politica_verificacion"] = valor
            with self.assertRaises(DatoFaltante):
                construir(ev(AUTH), motor=motor)

    def test_escalas_no_se_mezclan(self):
        x = construir(ev(AUTH))
        self.assertNotIn("puntaje_riesgo", x["evaluacion_determinista"])
        self.assertEqual(x["evaluacion_determinista"]["escala_riesgo"], "ordinal_1_9")
        self.assertEqual(x["comparacion_previa"]["escala_puntaje"], "cruce_0_100")


class TestCruce(unittest.TestCase):
    def test_cruce_con_trazabilidad_temporal(self):
        cp = construir(ev(AUTH))["comparacion_previa"]
        self.assertEqual((cp["disponible"], cp["prioridad"], cp["misma_corrida"], cp["corrida_id_origen"]),
                         (True, 1, True, MOTOR["corrida_id"]))

    def test_sin_cruce_el_caso_si_se_envia(self):
        e = ev(TRIP)
        e["cruce"] = None
        x = construir(e)
        self.assertEqual((x["comparacion_previa"]["disponible"], x["comparacion_previa"]["motivo"]), (False, "sin_historial"))
        self.assertIsNone(x["evaluacion_determinista"]["prioridad_base"])
        self.assertEqual(validar_entrada(x), [])

    def test_sin_cruce_por_permisos(self):
        e = ev(TRIP)
        e["cruce"] = None
        motor = copy.deepcopy(MOTOR)
        motor["fuentes_no_lectura"] = ["evaluaciones"]
        self.assertEqual(construir(e, motor=motor)["comparacion_previa"]["motivo"], "sin_permiso")


class TestVerificacion(unittest.TestCase):
    def estado(self, e, ruta):
        x = construir(e)
        for parte in ruta.split("."):
            x = x[parte]
        return x["estado_verificacion"], x["valor"]

    def test_sin_bloque_de_verificacion_nada_es_verificado(self):
        e = ev(TRIP)
        del e["contexto_agente"]["verificacion"]
        e["resultado"]["advertencias"] = []                 # sin advertencias tampoco prueba nada
        x = construir(e)
        estados = [x["despliegue"]["exposicion"], x["despliegue"]["dependencias"], x["inventario"],
                   x["vulnerabilidad"]["cvss"], x["vulnerabilidad"]["kev"], x["vulnerabilidad"]["epss"]]
        self.assertNotIn("verificado", [d["estado_verificacion"] for d in estados])

    def test_inventario_por_recertificacion_nunca_es_verificado(self):
        e = ver(ev(TRIP), "inventario", estado="verificado", metodo="recertificacion", fecha_verificacion="2026-11-01")
        x = construir(e)
        self.assertEqual(x["inventario"]["estado_verificacion"], "declarado_sin_evidencia")
        self.assertIn("VERIFICACION_DEGRADADA_INVENTARIO", x["evaluacion_determinista"]["advertencias"])

    def test_conciliado_exige_cmdb(self):
        e = ev(TRIP)
        e["contexto_agente"]["inventario_estado"] = "vigente_conciliado"
        ver(e, "inventario", estado="verificado", metodo="consulta_bd", fecha_verificacion="2026-11-18")
        self.assertEqual(self.estado(e, "inventario")[0], "declarado_sin_evidencia")
        ver(e, "inventario", metodo="conciliacion_cmdb")
        self.assertEqual(self.estado(e, "inventario")[0], "verificado")

    def test_cvss_verificado_sin_fecha_se_degrada(self):
        e = ver(ev(TRIP), "cvss", estado="verificado", metodo="consulta_nvd", fecha_verificacion=None)
        self.assertEqual(self.estado(e, "vulnerabilidad.cvss")[0], "declarado_sin_evidencia")

    def test_kev_false_sin_evidencia_no_es_fuera_de_kev(self):
        self.assertEqual(self.estado(ev(TRIP), "vulnerabilidad.kev"), ("desconocido", None))

    def test_kev_false_con_evidencia_es_fuera_de_kev(self):
        e = ver(ev(TRIP), "kev", estado="verificado", metodo="catalogo_cisa", fecha_verificacion="2026-11-18")
        estado, valor = self.estado(e, "vulnerabilidad.kev")
        self.assertEqual((estado, valor["en_kev"]), ("verificado", False))

    def test_epss_sin_percentil_no_se_rellena_con_cero(self):
        e = ev(TRIP)
        e["contexto_agente"]["epss_percentil"] = None
        self.assertEqual(self.estado(e, "vulnerabilidad.epss"), ("desconocido", None))

    def test_epss_con_fecha_futura(self):
        e = ev(TRIP)
        e["contexto_agente"]["epss_fecha"] = "2026-11-25"
        x = construir(e)
        self.assertEqual(x["vulnerabilidad"]["epss"]["estado_verificacion"], "desconocido")
        self.assertIn("EPSS_FECHA_POSTERIOR_A_EVALUACION", x["evaluacion_determinista"]["advertencias"])

    def test_exposicion_con_referencia_sin_fecha(self):
        e = ver(ev(AUTH), "exposicion", estado="verificado", metodo="observacion_cmdb",
                referencia="https://nvd.nist.gov/x", fecha_verificacion=None)
        self.assertEqual(self.estado(e, "despliegue.exposicion")[0], "declarado_sin_evidencia")

    def test_ventanas_por_metodo(self):
        e = ver(ev(AUTH), "exposicion", estado="verificado", metodo="observacion_cmdb", fecha_verificacion="2026-10-01")
        self.assertEqual(self.estado(e, "despliegue.exposicion")[0], "declarado_sin_evidencia")   # 49 dias > 30
        ver(e, "exposicion", metodo="atestacion_dueno")
        self.assertEqual(self.estado(e, "despliegue.exposicion")[0], "verificado")                 # 49 dias <= 90

    def test_fecha_de_verificacion_futura(self):
        e = ver(ev(AUTH), "exposicion", estado="verificado", metodo="observacion_cmdb", fecha_verificacion="2026-12-01")
        self.assertEqual(self.estado(e, "despliegue.exposicion")[0], "declarado_sin_evidencia")

    def test_metodo_no_admitido_para_el_campo(self):
        e = ver(ev(AUTH), "exposicion", estado="verificado", metodo="consulta_nvd", fecha_verificacion="2026-11-18")
        self.assertEqual(self.estado(e, "despliegue.exposicion")[0], "declarado_sin_evidencia")

    def test_el_adaptador_nunca_sube_un_estado(self):
        e = ver(ev(AUTH), "exposicion", estado="declarado_sin_evidencia", metodo="observacion_cmdb",
                fecha_verificacion="2026-11-18")
        self.assertEqual(self.estado(e, "despliegue.exposicion")[0], "declarado_sin_evidencia")

    def test_dependencias_null_no_son_cero(self):
        e = ev(AUTH)
        e["contexto_agente"]["dependientes_directos"] = None
        motor = copy.deepcopy(MOTOR)
        motor["fuentes_no_lectura"] = ["despliegue_dependencias"]
        x = construir(e, motor=motor)
        self.assertEqual((x["despliegue"]["dependencias"]["estado_verificacion"], x["despliegue"]["dependencias"]["valor"]),
                         ("no_consultable", None))

    def test_lista_vacia_leida_es_cero_verificado(self):
        e = ev("c2eacbd1-d337-4711-8f19-4987472b06d8")
        self.assertEqual(self.estado(e, "despliegue.dependencias"), ("verificado", []))


class TestEnrutamientoEHigiene(unittest.TestCase):
    def test_enrutamiento_en_produccion(self):
        self.assertEqual(construir(ev(AUTH), modo_demo=False)["motivo_envio"]["codigo"], "KEV")
        self.assertEqual(construir(ev(TRIP), modo_demo=False)["motivo_envio"]["codigo"], "APLICABILIDAD_AMBIGUA")

    def test_p3_confirmado_sin_kev_no_se_envia(self):
        e = ev(TRIP)
        e["resultado"].update(estado_aplicabilidad="confirmed", prioridad_tipo="tratamiento")
        self.assertIsNone(construir(e, modo_demo=False))

    def test_descripcion_saneada(self):
        e = ev(AUTH)
        e["contexto_agente"]["descripcion"] += " ver https://evil.example/x o a@b.com ‮"
        d = construir(e)["vulnerabilidad"]["descripcion_no_confiable"]
        for x in ("evil.example", "a@b.com", "‮"):
            self.assertNotIn(x, d)

    def test_maximo_3_precedentes(self):
        p = {"fecha": "2026-11-10", "cve": "CVE-2026-39819", "activo_codigo": "trip-service", "dominio": "ti",
             "decision": "confirmado", "probabilidad": 1, "impacto": 3, "justificacion": "ok"}
        evs = [x for x in construir(ev(TRIP), precedentes=[p] * 5)["evidencias"] if x["tipo"] == "precedente"]
        self.assertEqual(len(evs), 3)

    def test_politica_cargada(self):
        self.assertEqual(cargar_politica()["schema_version"], "politica-verificacion-v1")

    def test_sanear(self):
        self.assertEqual(sanear("a\x00b  https://x.y/z", 50), "a b [url-retirada]")


if __name__ == "__main__":
    unittest.main()
