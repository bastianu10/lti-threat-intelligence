"""
Muestra los recursos de AWS que Cartography descubrio y su relacion con el inventario. Solo lee (u_dashboard).

Uso:  python3 ver_descubiertos.py --host TU-ENDPOINT --password CLAVE_USUARIOS
"""
import argparse
from lti_db import TENANT_LYFT, agregar_argumentos, conectar


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "u_dashboard")
    ap.add_argument("--tenant", default=TENANT_LYFT)
    args = ap.parse_args()
    con = conectar(args, tenant=args.tenant)
    resumen = dict(con.run("SELECT estado, count(*) FROM recursos_descubiertos WHERE desaparecido_en IS NULL GROUP BY 1"))
    print("Recursos descubiertos:", resumen or "ninguno todavia (la primera sincronizacion tarda ~20 min)")
    filas = con.run("SELECT tipo, nombre, region, primera_vez::date, etiqueta_activo FROM v_recursos_sin_registrar ORDER BY tipo, nombre")
    print(f"\nSIN REGISTRAR ({len(filas)}): existen en AWS pero no estan en el inventario")
    for tipo, nombre, region, desde, etiqueta in filas:
        extra = f"  [la etiqueta activo={etiqueta} no existe en el inventario]" if etiqueta else ""
        print(f"  {tipo:10s} {nombre}  ({region}, desde {desde}){extra}")
    filas = con.run("SELECT r.tipo, r.nombre, a.codigo, a.nombre FROM recursos_descubiertos r JOIN activos a "
                    "ON a.tenant_id = r.tenant_id AND a.id = r.activo_id WHERE r.estado = 'registrado' AND r.desaparecido_en IS NULL "
                    "ORDER BY a.codigo, r.nombre")
    print(f"\nREGISTRADOS ({len(filas)}): coinciden con un activo del inventario")
    for tipo, nombre, codigo, nombre_activo in filas:
        print(f"  {tipo:10s} {nombre}  ->  {codigo} ({nombre_activo})")
    filas = con.run("SELECT tipo, nombre, estado, desaparecido_en::date FROM recursos_descubiertos WHERE desaparecido_en IS NOT NULL ORDER BY desaparecido_en DESC")
    if filas:
        print(f"\nDESAPARECIDOS ({len(filas)}): ya no existen en AWS")
        for tipo, nombre, estado, cuando in filas:
            print(f"  {tipo:10s} {nombre}  (era {estado}, desde {cuando})")
    con.close()


if __name__ == "__main__":
    main()
