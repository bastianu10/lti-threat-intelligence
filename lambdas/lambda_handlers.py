"""
Puntos de entrada de las Lambdas del nucleo. Reutilizan exactamente los mismos scripts que se corren a mano
(rds_cargar_vulnerabilidades.py y rds_cruce.py); la configuracion llega por variables de entorno.

  normalizacion          : lee lo CRUDO de S3 Raw y escribe la instantanea CURADA en S3 Curada (no toca la base)
  carga_vulnerabilidades : lee la instantanea curada mas reciente y llena el catalogo de la base
  cruce                  : cruza el inventario contra el catalogo y crea hallazgos y evaluaciones

El evento admite {"argv_extra": [...]} para pasar opciones adicionales a mano (pruebas, recargas puntuales).
"""
import contextlib
import io
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))


class _Tee:
    def __init__(self, *flujos):
        self.flujos = flujos

    def write(self, s):
        for f in self.flujos:
            f.write(s)
        return len(s)

    def flush(self):
        for f in self.flujos:
            f.flush()


def _base():
    argv = ["--host", os.environ["DB_HOST"], "--password", os.environ["DB_PASSWORD"]]
    if os.environ.get("LTI_SIN_SSL"):                       # solo para pruebas locales
        argv.append("--sin-ssl")
    return argv


def _correr(modulo, argv):
    """Ejecuta main() del script con esos argumentos; lo que imprime va a CloudWatch y se devuelve."""
    buf, antes = io.StringIO(), sys.argv
    sys.argv = ["lambda"] + argv
    try:
        with contextlib.redirect_stdout(_Tee(sys.__stdout__, buf)):
            modulo.main()
    except SystemExit as e:                                  # los scripts usan sys.exit("mensaje") para avisar
        if e.code not in (0, None):
            raise RuntimeError(f"{modulo.__name__}: {e.code}")
    finally:
        sys.argv = antes
    return {"salida": buf.getvalue()[-3000:]}


def normalizacion(event, context):
    import normalizacion_lti as m
    resumen = m.ejecutar_s3(os.environ["RAW_BUCKET"], os.environ["CURADA_BUCKET"])
    print(resumen)
    return resumen


def carga_vulnerabilidades(event, context):
    import rds_cargar_vulnerabilidades as m
    argv = _base() + ["--inventario", os.path.join(AQUI, "activos.csv")]
    if os.environ.get("BUCKET_CURADA"):
        argv += ["--bucket-curada", os.environ["BUCKET_CURADA"]]
    return _correr(m, argv + list((event or {}).get("argv_extra", [])))


def cruce(event, context):
    import rds_cruce as m
    return _correr(m, _base() + list((event or {}).get("argv_extra", [])))
