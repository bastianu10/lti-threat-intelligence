"""
Carga a la base (v3) la instantanea CURADA mas reciente: lo que dejo la Lambda de normalizacion en S3 Curada
(NVD, KEV, EPSS y OSV/GHSA ya limpios). Verifica la huella de cada archivo, crea en el catalogo global los
productos del inventario y registra en `corridas` la instantanea usada. Se conecta como u_ingesta.

Uso (desde S3):
  python3 rds_cargar_vulnerabilidades.py --host ENDPOINT --password CLAVE --bucket-curada lti-curada-CUENTA --profile lti
Uso (carpeta local generada con normalizacion_lti.py --salida-dir):
  python3 rds_cargar_vulnerabilidades.py --host ENDPOINT --password CLAVE --curada-dir curada/
"""
import argparse, csv, hashlib, json, os, sys
from datetime import datetime, timezone
from lti_db import agregar_argumentos, conectar, insertar_lote

GLOBAL = "00000000-0000-0000-0000-000000000000"
PREFIJO = "curada-v3/"


def leer_instantanea(args):
    """-> (manifest, partes {nombre: objeto}, clave_del_manifest, version_id, sha256_del_manifest). Verifica huellas."""
    if args.curada_dir:
        ruta = os.path.join(args.curada_dir, "manifest.json")
        mb, clave, version = open(ruta, "rb").read(), ruta, "sin-versionado"
        leer = lambda meta: open(os.path.join(args.curada_dir, os.path.basename(meta["clave"])), "rb").read()
    else:
        if not args.bucket_curada:
            sys.exit("Indica --bucket-curada (S3) o --curada-dir (carpeta local).")
        import boto3
        sesion = boto3.Session(profile_name=args.profile, region_name=args.region) if args.profile else boto3.Session(region_name=args.region)
        s3 = sesion.client("s3")
        claves = []
        for pag in s3.get_paginator("list_objects_v2").paginate(Bucket=args.bucket_curada, Prefix=PREFIJO):
            claves += [o["Key"] for o in pag.get("Contents", []) if o["Key"].endswith("/manifest.json")]
        if not claves:
            sys.exit(f"No hay ninguna instantanea curada en s3://{args.bucket_curada}/{PREFIJO}. Corre primero la normalizacion.")
        clave = sorted(claves)[-1]
        obj = s3.get_object(Bucket=args.bucket_curada, Key=clave)
        mb, version = obj["Body"].read(), obj.get("VersionId") or "sin-versionado"
        leer = lambda meta: s3.get_object(Bucket=args.bucket_curada, Key=meta["clave"])["Body"].read()
    manifest = json.loads(mb)
    partes = {}
    for nombre, meta in manifest["partes"].items():
        b = leer(meta)
        if hashlib.sha256(b).hexdigest() != meta["sha256"]:
            sys.exit(f"La parte '{nombre}' no coincide con su huella: el archivo curado esta alterado o incompleto.")
        partes[nombre] = json.loads(b)
    return manifest, partes, clave, version, hashlib.sha256(mb).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "u_ingesta")
    ap.add_argument("--bucket-curada", help="bucket con curada-v3/")
    ap.add_argument("--curada-dir", help="carpeta local con manifest.json y las partes")
    ap.add_argument("--profile")
    ap.add_argument("--region", default="us-east-2")
    ap.add_argument("--inventario", default="activos_v3.csv", help="para crear en el catalogo los productos del inventario")
    ap.add_argument("--tipo", default="semanal_completa", choices=["semanal_completa", "diaria_kev_criticos"])
    args = ap.parse_args()

    manifest, partes, clave, version, sha = leer_instantanea(args)
    print("Instantanea:", clave, "| fuentes crudas:", {n: f["clave"] for n, f in manifest["fuentes"].items()})

    con = conectar(args)
    con.run("BEGIN")        # todo o nada
    ahora = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    corrida = con.run(
        "INSERT INTO corridas (tipo, sfn_ejecucion_arn, s3_clave, s3_version_id, s3_sha256, iniciada_en) "
        "VALUES (:tipo, :arn, :clave, :ver, :sha, now()) RETURNING id",
        tipo=args.tipo, arn=f"arn:aws:states:us-east-2:000000000000:execution:lti-manual:{ahora}",
        clave=clave, ver=version, sha=sha)[0][0]

    cves = {c["cve"]: c for c in partes.get("nvd", {}).get("cves", [])}
    ghsa = {a["cve"]: a for a in partes.get("osv", {}).get("avisos", [])}

    # --- productos del catalogo global: CPE (NVD), PURL (GitHub) y los del inventario ---
    productos, purl_a_producto = {}, {}                  # (vendor, nombre) -> {"cpe": str|None, "purls": set()}

    def producto(k):
        return productos.setdefault(k, {"cpe": None, "purls": set()})
    for v in cves.values():
        for tipo, vendor, prod, *_ in v["rangos"]:
            producto((vendor, prod))["cpe"] = producto((vendor, prod))["cpe"] or f"cpe:2.3:{tipo}:{vendor}:{prod}"
    try:
        for r in csv.DictReader(open(args.inventario, encoding="utf-8")):
            if r["vendor"]:
                p = producto((r["vendor"], r["producto"]))
                p["cpe"] = p["cpe"] or f"cpe:2.3:a:{r['vendor']}:{r['producto']}"
                if r.get("purl"):                        # el mismo producto tambien se conoce por su PURL
                    p["purls"].add(r["purl"])
                    purl_a_producto[r["purl"]] = (r["vendor"], r["producto"])
    except FileNotFoundError:
        print(f"(sin {args.inventario}: no se crean los productos del inventario)")
    for v in ghsa.values():
        for tipo, nombre, purl, *_ in v["rangos"]:
            producto(purl_a_producto.get(purl, (tipo, nombre)))["purls"].add(purl)

    ids = {}
    if productos:
        lista = sorted(productos)
        insertar_lote(con, "productos", ["tenant_id", "vendor", "nombre"], [(GLOBAL, v, p) for v, p in lista],
                      "ON CONFLICT (tenant_id, vendor, nombre) DO NOTHING")
        ids = {(v, n): i for i, v, n in con.run("SELECT id, vendor, nombre FROM productos WHERE tenant_id = :g", g=GLOBAL)}
        filas = [(GLOBAL, ids[k], "cpe", d["cpe"]) for k, d in productos.items() if d["cpe"]]
        filas += [(GLOBAL, ids[k], "purl", purl) for k, d in productos.items() for purl in sorted(d["purls"])]
        insertar_lote(con, "producto_identificadores", ["tenant_id", "producto_id", "esquema", "valor"], filas, "ON CONFLICT DO NOTHING")

    def cargar_fuente(datos, fuente, filas_rango):
        """Vulnerabilidades, CWE, CVSS y rangos de UNA fuente; no toca lo que cargaron las demas."""
        lista = list(datos)
        insertar_lote(con, "vulnerabilidades", ["cve", "descripcion", "publicado_en", "modificado_en"],
                      [(k, datos[k]["descripcion"], datos[k]["pub"], datos[k]["mod"]) for k in lista],
                      ("ON CONFLICT (cve) DO UPDATE SET descripcion=EXCLUDED.descripcion, publicado_en=EXCLUDED.publicado_en, "
                       "modificado_en=EXCLUDED.modificado_en, normalizado_en=now()") if fuente == "nvd" else "ON CONFLICT (cve) DO NOTHING")
        for tabla in ("cvss_metricas", "vulnerabilidad_rangos"):
            con.run(f"DELETE FROM {tabla} WHERE fuente = :f AND cve = ANY(:l)", f=fuente, l=lista)
        insertar_lote(con, "vulnerabilidad_cwe", ["cve", "cwe"], [(k, w) for k in lista for w in datos[k]["cwes"]],
                      "ON CONFLICT DO NOTHING")
        insertar_lote(con, "cvss_metricas", ["cve", "fuente", "version", "vector", "puntaje_base"],
                      [(k, fuente, ver, vec, base) for k in lista for ver, (vec, base) in datos[k]["metricas"].items()])
        vistos, filas = set(), []
        for k in lista:
            for clave_producto, exacta, desde, d_inc, hasta, h_inc in filas_rango(k):
                u = (k, ids[clave_producto], exacta or "", desde or "", hasta or "", d_inc, h_inc)
                if u not in vistos:
                    vistos.add(u)
                    filas.append((k, fuente, ids[clave_producto], exacta, desde, d_inc, hasta, h_inc))
        insertar_lote(con, "vulnerabilidad_rangos", ["cve", "fuente", "producto_id", "version_exacta", "version_desde",
                                                    "desde_incluye", "version_hasta", "hasta_incluye"], filas)
        return len(lista), len(filas)

    if cves:
        n, r = cargar_fuente(cves, "nvd", lambda k: [((v, p), e, d, di, h, hi) for _, v, p, e, d, di, h, hi in cves[k]["rangos"]])
        print(f"NVD: {n} CVEs, {r} rangos de version (CPE)")
    if "osv" in partes:
        o = partes["osv"]
        n, r = cargar_fuente(ghsa, "ghsa", lambda k: [(purl_a_producto.get(purl, (t, nom)), e, d, di, h, hi)
                                                     for t, nom, purl, e, d, di, h, hi in ghsa[k]["rangos"]]) if ghsa else (0, 0)
        c = o["omitidos"]
        print(f"OSV/GHSA: {o['total_avisos']} avisos recibidos -> {n} con CVE cargados, {r} rangos de version (PURL)")
        print(f"          omitidos: {c['sin_cve']} sin CVE (v3 se identifica por CVE), {c['retirado_o_no_revisado']} retirados o no revisados, "
              f"{c['ecosistema_no_soportado']} paquetes de ecosistema no soportado, {c['rango_no_interpretable']} rangos no interpretables")

    # --- KEV ---
    if "kev" in partes:
        kev = partes["kev"]["entradas"]
        insertar_lote(con, "vulnerabilidades", ["cve", "descripcion"], [(e["cve"], e["descripcion"]) for e in kev],
                      "ON CONFLICT (cve) DO NOTHING")
        insertar_lote(con, "kev_entradas", ["cve", "agregado_en", "fecha_limite", "uso_ransomware"],
                      [(e["cve"], e["agregado_en"], e["fecha_limite"], e["ransomware"]) for e in kev],
                      "ON CONFLICT (cve) DO UPDATE SET agregado_en=EXCLUDED.agregado_en, fecha_limite=EXCLUDED.fecha_limite, "
                      "uso_ransomware=EXCLUDED.uso_ransomware")
        print(f"KEV: {len(kev)} entradas")

    # --- EPSS (solo CVEs que ya estan en el catalogo) ---
    if "epss" in partes:
        e = partes["epss"]
        presentes = {r[0] for r in con.run("SELECT cve FROM vulnerabilidades")}
        filas = [(c, p, pc, e["fecha"]) for c, p, pc in e["puntajes"] if c in presentes]
        insertar_lote(con, "epss_vigente", ["cve", "puntaje", "percentil", "fecha"], filas,
                      "ON CONFLICT (cve) DO UPDATE SET puntaje=EXCLUDED.puntaje, percentil=EXCLUDED.percentil, fecha=EXCLUDED.fecha")
        print(f"EPSS: {len(filas)} puntajes (de {len(e['puntajes'])} publicados, solo los CVEs del catalogo)")

    con.run("UPDATE corridas SET finalizada_en = now(), resultado = 'exito' WHERE id = :i", i=corrida)
    con.run("COMMIT")
    print("Catalogo:", {t: con.run(f"SELECT count(*) FROM {t}")[0][0] for t in
                        ("vulnerabilidades", "cvss_metricas", "vulnerabilidad_rangos", "kev_entradas", "epss_vigente",
                         "productos", "producto_identificadores")})
    print("Rangos por fuente:", {f: n for f, n in con.run("SELECT fuente, count(*) FROM vulnerabilidad_rangos GROUP BY 1 ORDER BY 1")})
    con.close()


if __name__ == "__main__":
    main()
