"""
Corre EN LA INSTANCIA de la CMDB, despues de cada sincronizacion de Cartography.
Compara los recursos reales de AWS que Cartography encontro (en Neo4j) contra el inventario (en RDS)
y deja el resultado en la tabla recursos_descubiertos:

  registrado     el recurso lleva la etiqueta  activo=<codigo>  y ese codigo existe en el inventario
  sin_registrar  no tiene la etiqueta, o apunta a un codigo que no existe
  ignorado       una persona decidio que no hace falta registrarlo (esta decision NO se pisa)

Variables de entorno: NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, DB_HOST, DB_PASSWORD
(opcionales: DB_USER, DB_NAME, TENANT_ID, DB_SIN_SSL=1 solo para pruebas locales).
"""
import os
import ssl
import sys

TENANT_LYFT = "11111111-1111-1111-1111-111111111111"
# etiqueta (label) de Cartography -> tipo legible
TIPOS = {"AWSLambda": "lambda", "AWSEC2Instance": "ec2", "AWSRDSInstance": "rds", "AWSS3Bucket": "s3",
         "AWSDynamoDBTable": "dynamodb", "AWSEKSCluster": "eks", "AWSECSCluster": "ecs",
         "AWSElasticacheCluster": "elasticache"}
CONSULTA = """
MATCH (cta:AWSAccount)-[:RESOURCE]->(r:%s)
OPTIONAL MATCH (r)-[:TAGGED]->(t:AWSTag)
WITH cta, r, collect(DISTINCT {k: t.key, v: t.value}) AS etiquetas
RETURN cta.id AS cuenta, coalesce(r.arn, r.id) AS arn,
       coalesce(r.name, r.db_instance_identifier, r.instanceid, r.id) AS nombre,
       r.region AS region, etiquetas
"""


def clasificar(recursos, codigos):
    """recursos: lista de dicts (tipo, arn, nombre, region, cuenta, etiquetas) ; codigos: {codigo: activo_id}.
    Devuelve los mismos recursos con 'etiqueta_activo', 'activo_id' y 'estado'."""
    salida = {}
    for r in recursos:
        etiquetas = {e["k"]: e["v"] for e in (r.get("etiquetas") or []) if e.get("k")}
        valor = (etiquetas.get("activo") or "").strip().lower() or None
        activo_id = codigos.get(valor) if valor else None
        salida[r["arn"]] = {**r, "etiqueta_activo": valor, "activo_id": activo_id,
                            "estado": "registrado" if activo_id else "sin_registrar"}
    return list(salida.values())


def leer_neo4j():
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                                  auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
    recursos = []
    with driver.session() as s:
        for etiqueta, tipo in TIPOS.items():
            for fila in s.run(CONSULTA % etiqueta):
                recursos.append({"tipo": tipo, "arn": fila["arn"], "nombre": fila["nombre"], "region": fila["region"],
                                 "cuenta": fila["cuenta"], "etiquetas": fila["etiquetas"]})
    driver.close()
    return [r for r in recursos if r["arn"]]


def conectar_db():
    import pg8000.native as pg
    ctx = None
    if not os.environ.get("DB_SIN_SSL"):
        # P0.2: validar CA y hostname. Configurar DB_CA_BUNDLE con la ruta al PEM de RDS
        # (https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem).
        ctx = ssl.create_default_context(cafile=os.environ.get("DB_CA_BUNDLE") or None)
        # check_hostname y CERT_REQUIRED son el default; no se sobreescriben.
    return pg.Connection(os.environ.get("DB_USER", "u_descubrimiento"), host=os.environ["DB_HOST"],
                         database=os.environ.get("DB_NAME", "lti"), password=os.environ["DB_PASSWORD"], ssl_context=ctx)


def guardar(con, tenant, recursos):
    con.run("BEGIN")
    con.run("SELECT set_config('app.tenant_id', :t, false)", t=tenant)
    codigos = {codigo: activo_id for codigo, activo_id in con.run("SELECT codigo, id FROM activos WHERE dado_de_baja_en IS NULL")}
    clasificados = clasificar(recursos, codigos)
    for r in clasificados:
        con.run(
            "INSERT INTO recursos_descubiertos (tenant_id, arn, tipo, nombre, region, cuenta, etiqueta_activo, activo_id, estado) "
            "VALUES (:t, :arn, :tipo, :nombre, :region, :cuenta, :etq, :aid, :estado) "
            "ON CONFLICT (tenant_id, arn) DO UPDATE SET tipo=EXCLUDED.tipo, nombre=EXCLUDED.nombre, region=EXCLUDED.region, "
            "cuenta=EXCLUDED.cuenta, etiqueta_activo=EXCLUDED.etiqueta_activo, activo_id=EXCLUDED.activo_id, "
            "estado = CASE WHEN EXCLUDED.estado = 'registrado' THEN 'registrado' "
            "              WHEN recursos_descubiertos.estado = 'ignorado' THEN 'ignorado' ELSE EXCLUDED.estado END, "
            "ultima_vez = now(), desaparecido_en = NULL",
            t=tenant, arn=r["arn"], tipo=r["tipo"], nombre=r["nombre"], region=r["region"], cuenta=r["cuenta"],
            etq=r["etiqueta_activo"], aid=r["activo_id"], estado=r["estado"])
    desaparecidos = 0
    if clasificados:                     # si Cartography devolvio vacio no se marca nada: seria un falso "todo desaparecio"
        desaparecidos = len(con.run(
            "UPDATE recursos_descubiertos SET desaparecido_en = now() WHERE tenant_id = :t AND desaparecido_en IS NULL "
            "AND NOT (arn = ANY(:v)) RETURNING arn", t=tenant, v=[r["arn"] for r in clasificados]))
    resumen = dict(con.run("SELECT estado, count(*) FROM recursos_descubiertos WHERE desaparecido_en IS NULL GROUP BY 1"))
    nuevos = con.run("SELECT count(*) FROM recursos_descubiertos WHERE estado='sin_registrar' AND desaparecido_en IS NULL "
                     "AND primera_vez >= now() - interval '1 minute'")[0][0]
    con.run("COMMIT")
    return {"descubiertos": len(clasificados), "por_estado": resumen, "sin_registrar_nuevos": nuevos, "desaparecidos": desaparecidos}


def main():
    recursos = leer_neo4j()
    if not recursos:
        print("Cartography no devolvio recursos (aun no termino su primera sincronizacion?). No se cambia nada.")
        return
    con = conectar_db()
    print("Descubrimiento:", guardar(con, os.environ.get("TENANT_ID", TENANT_LYFT), recursos))
    con.close()


if __name__ == "__main__":
    try:
        main()
    except KeyError as e:
        sys.exit(f"Falta la variable de entorno {e}")
