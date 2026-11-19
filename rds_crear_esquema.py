"""
Crea el esquema v3 en RDS PostgreSQL y los usuarios de conexion por componente.
Se corre UNA vez, con el usuario maestro (lti_app).

Uso:
  python3 rds_crear_esquema.py --host TU-ENDPOINT --password CLAVE_MAESTRA --clave-usuarios OTRA_CLAVE
"""
import argparse
import sys
from lti_db import agregar_argumentos, conectar, separar_sql

# usuario de conexion -> rol de minimo privilegio que hereda
USUARIOS = {
    "u_ingesta": "ti_ingesta",
    "u_inventario": "ti_inventario",
    "u_cruce": "ti_cruce",
    "u_dashboard": "ti_dashboard",
}


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "lti_app")
    ap.add_argument("--sql", default="esquema.sql")
    ap.add_argument("--clave-usuarios", required=True,
                    help="clave de los usuarios u_ingesta, u_inventario, u_cruce y u_dashboard (min. 8, sin comillas)")
    args = ap.parse_args()
    if len(args.clave_usuarios) < 8 or "'" in args.clave_usuarios:
        sys.exit("--clave-usuarios: minimo 8 caracteres y sin comillas simples")

    con = conectar(args)
    version = int(con.run("SHOW server_version_num")[0][0])
    print(f"PostgreSQL {version // 10000}.{version % 10000}")
    if version < 150000:
        sys.exit("Este esquema necesita PostgreSQL 15 o mas (vistas security_invoker).")

    existentes = con.run("SELECT count(*) FROM pg_tables WHERE schemaname='public'")[0][0]
    if existentes:
        sys.exit(f"La base ya tiene {existentes} tablas. Borra el esquema anterior antes de crear v3:\n"
                 "  DROP SCHEMA public CASCADE; CREATE SCHEMA public;")

    sentencias = separar_sql(open(args.sql, encoding="utf-8").read())
    print(f"Ejecutando {len(sentencias)} sentencias de {args.sql} ...")
    for s in sentencias:
        con.run(s)          # el script trae BEGIN ... COMMIT: es todo o nada

    for usuario, rol in USUARIOS.items():
        existe = con.run("SELECT 1 FROM pg_roles WHERE rolname = :u", u=usuario)
        accion = "ALTER ROLE" if existe else "CREATE ROLE"
        con.run(f"{accion} {usuario} LOGIN PASSWORD '{args.clave_usuarios}'")
        con.run(f"GRANT {rol} TO {usuario}")
    tablas = con.run("SELECT count(*) FROM pg_tables WHERE schemaname='public'")[0][0]
    fks = con.run("SELECT count(*) FROM pg_constraint WHERE contype='f'")[0][0]
    print(f"Listo: {tablas} tablas, {fks} llaves foraneas, usuarios: {', '.join(USUARIOS)}")
    con.close()


if __name__ == "__main__":
    main()
