"""
Carga activos.csv en el esquema v3: usuarios, equipos, activos, despliegues, componentes y dependencias.
Se conecta como u_inventario (seguridad por fila activa: solo toca la organizacion indicada).

Uso:
  python3 rds_cargar_inventario.py --host TU-ENDPOINT --password CLAVE_USUARIOS
"""
import argparse, csv, uuid
from lti_db import TENANT_LYFT, agregar_argumentos, conectar

GLOBAL = "00000000-0000-0000-0000-000000000000"


def producto_privado(con, t, vendor, nombre):
    """Crea (si no existe) un producto privado de la organizacion. ti_inventario solo puede INSERTAR, no actualizar."""
    con.run("INSERT INTO productos (tenant_id, vendor, nombre) VALUES (:t,:v,:n) ON CONFLICT DO NOTHING", t=t, v=vendor, n=nombre)
    return con.run("SELECT id FROM productos WHERE tenant_id=:t AND vendor=:v AND nombre=:n", t=t, v=vendor, n=nombre)[0][0]


def intervalo(minutos):
    return f"{int(minutos)} minutes" if minutos else None


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "u_inventario")
    ap.add_argument("--csv", default="datos/activos.csv")
    ap.add_argument("--tenant", default=TENANT_LYFT)
    args = ap.parse_args()
    t = args.tenant
    filas = list(csv.DictReader(open(args.csv, encoding="utf-8")))
    print(f"Leidos {len(filas)} activos de {args.csv}")
    con = conectar(args, tenant=t)
    con.run("BEGIN")        # todo o nada: si algo falla, no queda nada a medias

    # Usuarios (un responsable por equipo, SUPUESTO del prototipo) y equipos
    dueno_id, equipo_id = {}, {}
    for r in filas:
        if r["dueno_correo"] not in dueno_id:
            sub = str(uuid.uuid5(uuid.NAMESPACE_DNS, r["dueno_correo"]))   # estable entre corridas
            dueno_id[r["dueno_correo"]] = con.run(
                "INSERT INTO usuarios (tenant_id, cognito_sub, nombre, correo) VALUES (:t, :s, :n, :c) "
                "ON CONFLICT (tenant_id, lower(correo)) DO UPDATE SET nombre = EXCLUDED.nombre RETURNING id",
                t=t, s=sub, n=r["dueno_nombre"], c=r["dueno_correo"])[0][0]
        if r["equipo"] not in equipo_id:
            equipo_id[r["equipo"]] = con.run(
                "INSERT INTO equipos (tenant_id, nombre) VALUES (:t, :n) "
                "ON CONFLICT (tenant_id, nombre) DO UPDATE SET nombre = EXCLUDED.nombre RETURNING id",
                t=t, n=r["equipo"])[0][0]
    print(f"Usuarios: {len(dueno_id)} | Equipos: {len(equipo_id)}")

    # Activos, despliegues y componentes
    desp_de, privados, sin_global = {}, 0, []
    for r in filas:
        activo = con.run(
            "INSERT INTO activos (tenant_id, codigo, nombre, tipo, capa, dominio_negocio, criticidad, "
            "clasificacion_informacion, dueno_id, equipo_id, descripcion) "
            "VALUES (:t,:cod,:nom,:tipo,:capa,:dom,:crit,:clas,:due,:eq,:desc) "
            "ON CONFLICT (tenant_id, codigo) DO UPDATE SET nombre=EXCLUDED.nombre, tipo=EXCLUDED.tipo, "
            "capa=EXCLUDED.capa, dominio_negocio=EXCLUDED.dominio_negocio, criticidad=EXCLUDED.criticidad, "
            "clasificacion_informacion=EXCLUDED.clasificacion_informacion, dueno_id=EXCLUDED.dueno_id, "
            "equipo_id=EXCLUDED.equipo_id, descripcion=EXCLUDED.descripcion, dado_de_baja_en=NULL RETURNING id",
            t=t, cod=r["codigo"], nom=r["nombre"], tipo=r["tipo"], capa=r["capa"] or None, dom=r["dominio_negocio"],
            crit=int(r["criticidad"]), clas=r["clasificacion_informacion"], due=dueno_id[r["dueno_correo"]],
            eq=equipo_id[r["equipo"]], desc=r["descripcion"] or None)[0][0]
        desp = con.run(
            "INSERT INTO despliegues (tenant_id, activo_id, ambiente, region, arquitectura, expuesto_internet, "
            "disponibilidad_objetivo, rto, rpo) VALUES (:t,:a,:amb,:reg,:arq,:exp,:disp,CAST(:rto AS interval),CAST(:rpo AS interval)) "
            "ON CONFLICT (tenant_id, activo_id, ambiente, region) DO UPDATE SET arquitectura=EXCLUDED.arquitectura, "
            "expuesto_internet=EXCLUDED.expuesto_internet, disponibilidad_objetivo=EXCLUDED.disponibilidad_objetivo, "
            "rto=EXCLUDED.rto, rpo=EXCLUDED.rpo, dado_de_baja_en=NULL RETURNING id",
            t=t, a=activo, amb=r["ambiente"], reg=r["region"], arq=r["arquitectura"],
            exp=r["expuesto_internet"] == "true", disp=float(r["disponibilidad_objetivo"]) if r["disponibilidad_objetivo"] else None,
            rto=intervalo(r["rto_minutos"]), rpo=intervalo(r["rpo_minutos"]))[0][0]
        desp_de[r["codigo"]] = desp

        if r["vendor"]:                                              # producto publico (catalogo global)
            hallado = con.run("SELECT id FROM productos WHERE tenant_id=:g AND vendor=:v AND nombre=:n",
                              g=GLOBAL, v=r["vendor"], n=r["producto"])
            if hallado:
                prod_t, prod = GLOBAL, hallado[0][0]
            else:                                                    # aun no esta en el catalogo: queda privado
                sin_global.append(f"{r['vendor']}/{r['producto']}")
                prod_t = t
                prod = producto_privado(con, t, r["vendor"], r["producto"])
        else:                                                        # software sin CPE: producto privado
            privados += 1
            prod_t = t
            prod = producto_privado(con, t, "interno", r["codigo"])
        con.run("INSERT INTO componentes (tenant_id, despliegue_id, producto_tenant_id, producto_id, version, origen) "
                "VALUES (:t,:d,:pt,:p,:v,'csv') ON CONFLICT DO NOTHING",
                t=t, d=desp, pt=prod_t, p=prod, v=r["version"])
        con.run("UPDATE componentes SET retirado_en = now() WHERE tenant_id=:t AND despliegue_id=:d "
                "AND retirado_en IS NULL AND NOT (producto_id=:p AND version=:v)", t=t, d=desp, p=prod, v=r["version"])

    # Dependencias entre despliegues
    con.run("DELETE FROM despliegue_dependencias WHERE tenant_id = :t", t=t)
    deps = 0
    for r in filas:
        for destino in [d.strip() for d in (r["depende_de"] or "").split(";") if d.strip()]:
            if destino in desp_de:
                con.run("INSERT INTO despliegue_dependencias (tenant_id, despliegue_id, depende_de_id) "
                        "VALUES (:t,:a,:b) ON CONFLICT DO NOTHING", t=t, a=desp_de[r["codigo"]], b=desp_de[destino])
                deps += 1

    # Activos que ya no vienen en el CSV: baja logica (no se borra el historial)
    codigos = [r["codigo"] for r in filas]
    bajas = con.run("UPDATE activos SET dado_de_baja_en = now() WHERE tenant_id=:t AND dado_de_baja_en IS NULL "
                    "AND NOT (codigo = ANY(:c)) RETURNING codigo", t=t, c=codigos)

    n = lambda tabla: con.run(f"SELECT count(*) FROM {tabla}")[0][0]
    print(f"activos={n('activos')} despliegues={n('despliegues')} componentes={n('componentes')} dependencias={deps}")
    print(f"componentes con producto privado (sin CPE): {privados} | dados de baja: {len(bajas)}")
    if sin_global:
        print("AVISO: estos productos aun no estan en el catalogo global, quedaron privados y NO cruzaran con CVEs.\n"
              "       Corre primero rds_cargar_vulnerabilidades.py y vuelve a cargar el inventario:",
              ", ".join(sorted(set(sin_global))))
    con.run("COMMIT")
    con.close()


if __name__ == "__main__":
    main()
