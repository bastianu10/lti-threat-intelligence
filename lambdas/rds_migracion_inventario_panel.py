"""
Alta de activos desde el panel (P2.1): crea el rol de MINIMO PRIVILEGIO ti_panel_alta y el usuario
de conexion u_panel_alta (autenticacion IAM), que la API del panel usa SOLO para insertar activos.
El camino de lectura del panel sigue siendo u_dashboard (solo lectura); este usuario no lo toca.

Se corre UNA vez con el usuario maestro (lti_app); es seguro repetirlo.

Uso:
  python3 lambdas/rds_migracion_inventario_panel.py --host TU-ENDPOINT --password CLAVE_MAESTRA

Permisos que concede:
  - INSERT en activos (la RLS p_tenant ya restringe al tenant de la sesion; WITH CHECK).
  - SELECT en usuarios, equipos, activos (para validar dueno/equipo y mostrar opciones en el formulario).
Nada mas: no puede leer hallazgos, ni escribir en otras tablas, ni actualizar/borrar activos.
"""
import argparse
import sys

from lti_db import agregar_argumentos, conectar

SENTENCIAS = [
    # Rol de minimo privilegio (NOLOGIN): solo alta de activos.
    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ti_panel_alta') "
    "THEN CREATE ROLE ti_panel_alta NOLOGIN; END IF; END $$",
    "GRANT SELECT ON fuentes, niveles_prioridad TO ti_panel_alta",          # catalogos de solo lectura usados por FKs/CHECKs
    "GRANT SELECT ON usuarios, equipos, activos TO ti_panel_alta",          # validar dueno/equipo y evitar codigos duplicados
    "GRANT INSERT ON activos TO ti_panel_alta",                             # la unica escritura; RLS p_tenant aplica WITH CHECK
    # Usuario de conexion con autenticacion IAM (sin contrasena en la Lambda; token de 15 min).
    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='u_panel_alta') "
    "THEN CREATE ROLE u_panel_alta LOGIN; END IF; END $$",
    "GRANT rds_iam TO u_panel_alta",
    "GRANT ti_panel_alta TO u_panel_alta",
]


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "lti_app")
    args = ap.parse_args()
    con = conectar(args)
    if not con.run("SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='activos'"):
        sys.exit("Falta el esquema v3: corre primero rds_crear_esquema.py")
    for s in SENTENCIAS:
        con.run(s)
    puede = con.run("""
        SELECT has_table_privilege('ti_panel_alta','activos','INSERT') AS ins,
               has_table_privilege('ti_panel_alta','activos','UPDATE') AS upd,
               has_table_privilege('ti_panel_alta','hallazgos','SELECT') AS lee_hallazgos""")[0]
    print(f"Listo: ti_panel_alta y u_panel_alta creados. "
          f"INSERT activos={puede[0]} (debe ser True), UPDATE activos={puede[1]} (debe ser False), "
          f"SELECT hallazgos={puede[2]} (debe ser False).")
    print("Siguiente: desplegar.sh (IAM rds-db:connect para u_panel_alta) y subir_panel.sh.")
    con.close()


if __name__ == "__main__":
    main()
