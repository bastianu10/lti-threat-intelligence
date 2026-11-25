"""O-3: reutilizacion de asesorias. Un caso sin cambios no vuelve a llamar a Bedrock; cualquier cambio relevante si."""
import copy, json, re, time, unittest, uuid
import test_agente_asesor as T
A = T.A



class Reuso(unittest.TestCase):
    setUp = T.TestAgenteAsesor.setUp

    def ev(self, archivo=None, corrida=T.CORRIDA):
        return {"accion": "asesorar", "corrida_id": corrida, "archivo_sombra": archivo or self.archivo,
                "hallazgo_id": T.AUTH, "modo_demo": True}

    def otra_corrida(self):
        """La misma evaluacion publicada por una corrida nueva (otro id de corrida y otro archivo del motor)."""
        nueva = str(uuid.uuid4())
        m = copy.deepcopy(T.MOTOR); m["corrida_id"] = nueva
        cuerpo = json.dumps(m, sort_keys=True, separators=(",", ":")).encode()
        import hashlib
        sha = hashlib.sha256(cuerpo).hexdigest()
        key = f"risk-engine-shadow/v1.3.3/{T.TENANT}/{nueva}/inicio-{sha}.json"
        self.s3.put_object(Bucket=T.BUCKET_MOTOR, Key=key, Body=cuerpo)
        return nueva, {"bucket": T.BUCKET_MOTOR, "key": key, "sha256": sha}

    def test_misma_evaluacion_en_otra_corrida_no_llama_a_bedrock(self):
        r1 = A.handler(self.ev())
        self.assertEqual((r1["estado"], self.br.converse_llamadas), ("asesorado", 1))
        nueva, archivo = self.otra_corrida()
        r2 = A.handler(self.ev(archivo, nueva))
        self.assertEqual((r2["estado"], self.br.converse_llamadas), ("reutilizado", 1))
        self.assertTrue(r2["destino"].startswith(f"agente/{T.TENANT}/{nueva}/{T.AUTH}-"))
        patron_panel = re.compile(r"^agente/[0-9a-f-]{36}/([0-9a-f-]{36})/([0-9a-f-]{36})-[0-9a-f]{16}\.json$")
        self.assertTrue(patron_panel.match(r2["destino"]), "el panel y el notificador deben reconocer la clave")
        doc = json.loads(self.s3.objetos[(T.BUCKET_CURADA, r2["destino"])])
        self.assertEqual(doc["reutilizada"]["de"], r1["destino"])
        self.assertEqual(doc["prioridad"]["fuente"], "motor")
        self.assertEqual(r2["recomendacion"], r1["recomendacion"])

    def test_indice_vencido_vuelve_a_asesorar(self):
        A.handler(self.ev())
        for (b, k), v in list(self.s3.objetos.items()):
            if "/reuso/" in k:
                d = json.loads(v); d["creado_epoch"] = time.time() - (A.REUSO_DIAS + 1) * 86400
                self.s3.objetos[(b, k)] = json.dumps(d).encode()
        nueva, archivo = self.otra_corrida()
        self.assertEqual(A.handler(self.ev(archivo, nueva))["estado"], "asesorado")
        self.assertEqual(self.br.converse_llamadas, 2)

    def test_indice_manipulado_se_ignora(self):
        A.handler(self.ev())
        for (b, k), v in list(self.s3.objetos.items()):
            if "/reuso/" in k:
                d = json.loads(v); d["destino"] = "contexto/" + T.TENANT + ".json"
                self.s3.objetos[(b, k)] = json.dumps(d).encode()
        nueva, archivo = self.otra_corrida()
        self.assertEqual(A.handler(self.ev(archivo, nueva))["estado"], "asesorado")

    def test_sin_permiso_de_lectura_asesora_normalmente(self):
        original = self.s3.get_object
        def get(Bucket, Key):
            if "/reuso/" in Key: raise T.ErrorS3("AccessDenied")
            return original(Bucket=Bucket, Key=Key)
        self.s3.get_object = get
        A.handler(self.ev()); nueva, archivo = self.otra_corrida()
        self.assertEqual(A.handler(self.ev(archivo, nueva))["estado"], "asesorado")


class Huella(unittest.TestCase):
    CFG = {"modelo": "m", "guardrail_id": "g", "guardrail_version": "1"}

    def entrada(self):
        from fixtures import ENTRADA
        return copy.deepcopy(ENTRADA)

    def test_ignora_lo_volatil(self):
        e1, e2 = self.entrada(), self.entrada()
        e2["corrida_id"] = str(uuid.uuid4()); e2["trazabilidad"]["evaluacion_sha256"] = "f" * 64
        e2["trazabilidad"]["snapshot_id"] = "curada-v3/2026/11/24/150000/manifest.json"
        e2["comparacion_previa"]["fecha"] = "2026-11-24T15:00:00+00:00"; e2["comparacion_previa"]["misma_corrida"] = False
        self.assertEqual(A.clave_reuso(self.CFG, e1, "p"), A.clave_reuso(self.CFG, e2, "p"))

    def test_cambia_con_datos_y_configuracion(self):
        base = A.clave_reuso(self.CFG, self.entrada(), "p")
        e = self.entrada(); e["vulnerabilidad"]["epss"]["valor"]["puntaje"] = 0.5
        self.assertNotEqual(base, A.clave_reuso(self.CFG, e, "p"))
        e = self.entrada(); e["evaluacion_determinista"]["prioridad_final"] = 2
        self.assertNotEqual(base, A.clave_reuso(self.CFG, e, "p"))
        e = self.entrada(); e["contexto_negocio"]["sha256"] = "0" * 64
        self.assertNotEqual(base, A.clave_reuso(self.CFG, e, "p"))
        self.assertNotEqual(base, A.clave_reuso(self.CFG, self.entrada(), "otro-prompt"))
        self.assertNotEqual(base, A.clave_reuso({**self.CFG, "guardrail_version": "2"}, self.entrada(), "p"))


if __name__ == "__main__":
    unittest.main()
