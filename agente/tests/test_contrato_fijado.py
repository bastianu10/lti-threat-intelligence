"""El agente debe llevar EXACTAMENTE los archivos del contrato acordado con el equipo del motor (contrato/v2.1/).

Si alguien cambia el adaptador, el guard, los esquemas, la politica o los casos de aceptacion en un solo lado,
esta prueba falla. Fuera del repositorio (paquete suelto sin ../contrato/v2.1) se omite.
"""
import hashlib
import pathlib
import unittest

AGENTE = pathlib.Path(__file__).resolve().parents[1]
CONTRATO = AGENTE.parent / "contrato" / "v2.1"
ARCHIVOS = [
    "lambda/agente_priorizacion/adaptador_v2_1.py",
    "lambda/agente_priorizacion/output_guard_v2_1.py",
    "lambda/agente_priorizacion/esquema.py",
    "lambda/agente_priorizacion/contrato/entrada.v2_1.schema.json",
    "lambda/agente_priorizacion/contrato/salida.v2.schema.json",
    "lambda/agente_priorizacion/contrato/politica-verificacion-v1.json",
    "contrato/ejecutar_aceptacion.py",
] + [f"contrato/casos_aceptacion/CA-{n:02d}.json" for n in range(1, 15)]


def sha(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@unittest.skipUnless(CONTRATO.is_dir(), "fuera del repositorio: no hay contrato/v2.1 para comparar")
class TestContratoFijado(unittest.TestCase):
    def test_archivos_identicos_al_contrato_acordado(self):
        distintos = [a for a in ARCHIVOS if sha(AGENTE / a) != sha(CONTRATO / a)]
        self.assertEqual(distintos, [], "difieren del contrato acordado (contrato/v2.1/): " + ", ".join(distintos))


if __name__ == "__main__":
    unittest.main()
