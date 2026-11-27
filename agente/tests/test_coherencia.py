"""Capa de coherencia de la regla 7: solo puede volver mas conservadora la recomendacion."""
import copy
import json
import pathlib
import sys
import unittest

RAIZ = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "lambda"))
from agente_priorizacion.coherencia import condiciones_escalar, marcar_dominio, marcar_texto, normalizar_escalar  # noqa: E402


def entrada(pf=3, kev=None, vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N", exp="interna",
            deps=None, deps_estado="verificado", previa=None):
    return {"evaluacion_determinista": {"prioridad_final": pf},
            "vulnerabilidad": {"kev": {"valor": None if kev is None else {"en_kev": kev}},
                               "cvss": {"valor": [{"vector": vector}]}},
            "despliegue": {"exposicion": {"valor": exp},
                           "dependencias": {"valor": deps or [], "estado_verificacion": deps_estado}},
            "comparacion_previa": {"disponible": previa is not None, "prioridad": previa}}


def res(direccion, p=1, i=3, estado="aceptada"):
    return {"estado": estado, "recomendacion": {"propuesta": direccion, "efectiva": direccion},
            "revision": {"requerida": True, "prioridad": "alta", "motivos": []},
            "prioridad": {"final": 3},
            "salida_validada": {"valoracion_negocio": {"probabilidad": {"valor": p}, "impacto": {"valor": i}}}}


class TestCoherencia(unittest.TestCase):
    def test_sin_condiciones_escalar_se_registra_mantener(self):
        r = normalizar_escalar(entrada(), res("escalar", p=1, i=3))
        self.assertEqual((r["recomendacion"]["propuesta"], r["recomendacion"]["efectiva"]), ("escalar", "mantener"))
        self.assertIn("escalar_sin_condicion", r["revision"]["motivos"])
        self.assertTrue(r["coherencia"]["normalizada"])

    def test_cada_condicion_permite_escalar(self):
        casos = {"a_kev": entrada(kev=True),
                 "b_p2_i3": entrada(),
                 "c_internet_red": entrada(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", exp="internet"),
                 "d_dependientes_criticos": entrada(deps=[{"activo_codigo": "x", "criticidad": 5}]),
                 "e_previa_mas_urgente": entrada(previa=2)}
        for codigo, e in casos.items():
            p = 2 if codigo == "b_p2_i3" else 1
            r = normalizar_escalar(e, res("escalar", p=p, i=3))
            self.assertEqual(r["recomendacion"]["efectiva"], "escalar", codigo)
            self.assertIn(codigo, r["coherencia"]["condiciones_escalar"])

    def test_condiciones_que_no_cuentan(self):
        self.assertEqual(condiciones_escalar(entrada(kev=False), 1, 3), [])                  # KEV falso
        self.assertEqual(condiciones_escalar(entrada(exp="internet"), 1, 3), [])             # internet sin AV:N
        self.assertEqual(condiciones_escalar(entrada(deps=[{"criticidad": 5}], deps_estado="declarado_sin_evidencia"), 1, 3), [])
        self.assertEqual(condiciones_escalar(entrada(deps=[{"criticidad": 3}]), 1, 3), [])   # dependiente no critico
        self.assertEqual(condiciones_escalar(entrada(previa=3), 1, 3), [])                   # previa igual
        self.assertEqual(condiciones_escalar(entrada(), 2, 2), [])                           # I no es 3

    def test_nunca_vuelve_menos_conservadora(self):
        for d in ("mantener", "revisar_a_la_baja"):
            r = normalizar_escalar(entrada(kev=True), res(d))
            self.assertEqual(r["recomendacion"]["efectiva"], d)
            self.assertFalse(r["coherencia"]["normalizada"])

    def test_no_toca_prioridad_ni_salida_ni_rechazadas(self):
        original = res("escalar")
        r = normalizar_escalar(entrada(), original)
        self.assertEqual(r["prioridad"], original["prioridad"])
        self.assertEqual(r["salida_validada"], original["salida_validada"])
        self.assertEqual(original["recomendacion"]["efectiva"], "escalar")   # sin mutar la entrada
        rechazada = res("escalar", estado="rechazada")
        self.assertIs(normalizar_escalar(entrada(), rechazada), rechazada)


class TestDominio(unittest.TestCase):
    MODELO = json.loads((RAIZ / "contexto" / "modelo_negocio_lyft.json").read_text())

    def _entrada(self, dominio):
        e = entrada()
        e["activo"] = {"dominio_negocio": dominio}
        return e

    def test_los_cuatro_dominios_reales_estan_definidos(self):
        self.assertEqual({d["codigo"] for d in self.MODELO["dominios"]}, {"ecobici", "propuesta-lti", "crm", "erp"})

    def test_dominio_desconocido_queda_en_la_revision(self):
        r = marcar_dominio(self._entrada("logistica-flota"), res("mantener"), self.MODELO)
        self.assertIn("dominio_sin_modelo_negocio", r["revision"]["motivos"])
        self.assertFalse(r["coherencia"]["dominio_en_modelo"])
        self.assertEqual(r["recomendacion"]["efectiva"], "mantener")     # no toca la recomendacion

    def test_dominio_conocido_no_agrega_motivo(self):
        for d in ("ecobici", "crm", "erp", "propuesta-lti"):
            r = marcar_dominio(self._entrada(d), res("escalar"), self.MODELO)
            self.assertNotIn("dominio_sin_modelo_negocio", r["revision"]["motivos"], d)
            self.assertTrue(r["coherencia"]["dominio_en_modelo"])

    def test_dominio_nulo_es_desconocido(self):
        r = marcar_dominio(self._entrada(None), res("mantener"), self.MODELO)
        self.assertIn("dominio_sin_modelo_negocio", r["revision"]["motivos"])


class TestTexto(unittest.TestCase):
    def _caso(self, texto, pf=1):
        r = res("mantener")
        r["salida_validada"]["explicacion_dashboard"] = texto
        return marcar_texto(entrada(pf=pf), r)

    def test_explicar_la_prioridad_del_motor_es_valido(self):
        r = self._caso("La prioridad maxima (P1) fue asignada por el motor; el paso inmediato es confirmar la version.")
        self.assertEqual(r["coherencia"]["texto"], [])
        self.assertEqual(r["revision"]["motivos"], [])

    def test_contradecir_al_motor_se_marca(self):
        r = self._caso("Deberia tratarse como P2 aunque el motor diga otra cosa.", pf=1)
        self.assertIn("texto_contradice_prioridad_motor", r["revision"]["motivos"])
        self.assertTrue(r["salida_validada"]["explicacion_dashboard"].startswith("Deberia"))   # no reescribe

    def test_nivel_de_riesgo_propio_se_marca(self):
        self.assertIn("texto_asigna_nivel_riesgo", self._caso("Es un riesgo alto para la flota.")["revision"]["motivos"])
        self.assertIn("texto_asigna_nivel_riesgo", self._caso("un riesgo inaceptable")["revision"]["motivos"])

    def test_sin_falsos_positivos(self):
        r = self._caso("Tiene una puntuacion P10 de un benchmark y un riesgo de interrupcion del servicio.", pf=3)
        self.assertEqual(r["coherencia"]["texto"], [])


if __name__ == "__main__":
    unittest.main()
