"""
Crea la tabla de recursos descubiertos y el usuario u_descubrimiento (el que usa la CMDB para escribir en ella).
Se corre UNA vez con el usuario maestro; es seguro repetirlo.

Uso:
  python3 rds_migracion_descubrimiento.py --host TU-ENDPOINT --password CLAVE_MAESTRA --clave-usuarios CLAVE_USUARIOS
"""
import argparse
import sys
from lti_db import agregar_argumentos, conectar, separar_sql


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "lti_app")
    ap.add_argument("--sql", default="bd/descubrimiento.sql")
    ap.add_argument("--clave-usuarios", required=True)
    args = ap.parse_args()
    if len(args.clave_usuarios) < 8 or "'" in args.clave_usuarios:
        sys.exit("--clave-usuarios: minimo 8 caracteres y sin comillas simples")
    con = conectar(args)
    if not con.run("SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='activos'"):
        sys.exit("Falta el esquema v3: corre primero rds_crear_esquema.py")
    for s in separar_sql(open(args.sql, encoding="utf-8").read()):
        con.run(s)          # el archivo trae BEGIN ... COMMIT: todo o nada
    existe = con.run("SELECT 1 FROM pg_roles WHERE rolname = 'u_descubrimiento'")
    con.run(f"{'ALTER ROLE' if existe else 'CREATE ROLE'} u_descubrimiento LOGIN PASSWORD '{args.clave_usuarios}'")
    con.run("GRANT ti_descubrimiento TO u_descubrimiento")
    n = con.run("SELECT count(*) FROM recursos_descubiertos")[0][0]
    print(f"Listo: tabla recursos_descubiertos ({n} filas) y usuario u_descubrimiento")
    con.close()


if __name__ == "__main__":
    main()
