"""
Muestra los hallazgos abiertos con la evidencia: el rango de version del CVE que coincidio con el componente.
Solo lee. Se conecta como u_dashboard.

Uso:  python3 ver_hallazgos.py --host TU-ENDPOINT --password CLAVE_USUARIOS
"""
import argparse
from lti_db import TENANT_LYFT, agregar_argumentos, conectar
from rds_cruce import coincide, version_de   # misma comparacion que usa el cruce

GLOBAL = "00000000-0000-0000-0000-000000000000"
PRIO = {1: "CRITICA", 2: "ALTA", 3: "MEDIA", 4: "BAJA"}


def texto_rango(exacta, desde, d_inc, hasta, h_inc):
    if exacta:
        return f"version exacta {exacta}"
    if not desde and not hasta:
        return "TODAS las versiones"
    izq = f"{desde} ({'incluida' if d_inc else 'excluida'})" if desde else "sin limite inferior"
    der = f"{hasta} ({'incluida' if h_inc else 'excluida'})" if hasta else "sin limite superior"
    return f"desde {izq} hasta {der}"


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "u_dashboard")
    ap.add_argument("--tenant", default=TENANT_LYFT)
    args = ap.parse_args()
    con = conectar(args, tenant=args.tenant)
    filas = con.run(
        "SELECT t.cve, t.activo_codigo, t.vendor, t.producto, t.version, t.estado, t.prioridad_final, t.puntaje_riesgo, "
        "t.en_kev, t.epss, t.fecha_limite, left(v.descripcion, 110) "
        "FROM v_hallazgos_tablero t JOIN vulnerabilidades v ON v.cve = t.cve "
        "WHERE NOT t.es_cerrado ORDER BY t.prioridad_final, t.puntaje_riesgo DESC, t.cve")
    print(f"{len(filas)} hallazgos abiertos\n")
    for cve, activo, vendor, prod, ver, estado, prio, pts, kev, epss, limite, desc in filas:
        print(f"[{PRIO.get(prio, '?')}] {cve}  ->  {activo}  ({vendor}/{prod} {ver})")
        print(f"    puntaje {pts} | KEV: {'SI' if kev else 'no'} | EPSS: {epss if epss is not None else '-'} | fecha limite: {limite} | {estado}")
        print(f"    {desc}")
        rangos = con.run(
            "SELECT r.version_exacta, r.version_desde, r.desde_incluye, r.version_hasta, r.hasta_incluye "
            "FROM vulnerabilidad_rangos r JOIN productos p ON p.id = r.producto_id "
            "WHERE r.cve = :c AND p.tenant_id = :g AND p.vendor = :v AND p.nombre = :n", c=cve, g=GLOBAL, v=vendor, n=prod)
        v = version_de(ver)
        for r in rangos:
            ok = v is not None and coincide(v, *r)
            print(f"    {'[COINCIDE]  ' if ok else '[no aplica] '}{texto_rango(*r)}")
        print()
    con.close()


if __name__ == "__main__":
    main()
