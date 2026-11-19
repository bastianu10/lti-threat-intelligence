"""
Crea la tabla metricas_diarias y da a u_dashboard los permisos que usa la API del panel.
Se corre UNA vez con el usuario maestro; es seguro repetirlo.

Uso:
  python3 rds_migracion_api.py --host TU-ENDPOINT --password CLAVE_MAESTRA
"""
import argparse
import sys
from lti_db import agregar_argumentos, conectar, separar_sql


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "lti_app")
    ap.add_argument("--sql", default="api.sql")
    args = ap.parse_args()
    con = conectar(args)
    if not con.run("SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='activos'"):
        sys.exit("Falta el esquema v3: corre primero rds_crear_esquema.py")
    for s in separar_sql(open(args.sql, encoding="utf-8").read()):
        con.run(s)          # el archivo trae BEGIN ... COMMIT: todo o nada
    n = con.run("SELECT count(*) FROM metricas_diarias")[0][0]
    print(f"Listo: tabla metricas_diarias ({n} filas) y permisos de u_dashboard")
    con.close()


if __name__ == "__main__":
    main()
