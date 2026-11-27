"""
Carga en la CMDB (Neo4j) los activos de las 4 arquitecturas de Lyft
y las relaciones de dependencia entre ellos.

Uso:  python cargar_cmdb.py [ruta/a/activos.csv]
"""

import csv
import os
import sys
from neo4j import GraphDatabase

# Configuracion: sin variables de entorno usa la CMDB local de siempre (sin contrasena, en tu Mac).
# En AWS la instancia define NEO4J_URI, NEO4J_USER y NEO4J_PASSWORD.
ARCHIVO = sys.argv[1] if len(sys.argv) > 1 else "activos.csv"
URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USUARIO = os.environ.get("NEO4J_USER", "neo4j")
CLAVE = os.environ.get("NEO4J_PASSWORD")

# Campos de contexto que pide la actividad
CAMPOS = [
    "nombre", "tipo", "arquitectura", "capa", "ambiente", "dueno",
    "producto_version", "criticidad", "clasificacion_informacion",
    "expuesto_internet", "disponibilidad_objetivo", "rto", "rpo", "descripcion",
]


def _a_cmdb(f):
    """activos.csv (esquema v3) -> propiedades que guarda la CMDB."""
    prod = " ".join(x for x in (f.get("producto"), f.get("version")) if x and x != "n/d")
    return {
        "id": f["codigo"], "nombre": f["nombre"], "tipo": f["tipo"], "arquitectura": f["arquitectura"],
        "capa": f["capa"], "ambiente": f["ambiente"], "dueno": f["equipo"], "producto_version": prod,
        "criticidad": f["criticidad"], "clasificacion_informacion": f["clasificacion_informacion"],
        "expuesto_internet": "Si" if f["expuesto_internet"] == "true" else "No",
        "disponibilidad_objetivo": f["disponibilidad_objetivo"], "rto": f["rto_minutos"],
        "rpo": f["rpo_minutos"], "depende_de": f["depende_de"], "descripcion": f["descripcion"],
    }


def leer_csv(ruta):
    with open(ruta, newline="", encoding="utf-8") as f:
        return [_a_cmdb(fila) for fila in csv.DictReader(f) if fila.get("codigo")]


def cargar(tx, filas):
    # 1. Crear o actualizar cada activo
    for fila in filas:
        props = {c: (fila.get(c) or "").strip() for c in CAMPOS}
        props["id"] = fila["id"].strip()
        tx.run(
            """
            MERGE (a:Activo {id: $id})
            SET a += $props, a.origen = 'inventario manual'
            """,
            id=props["id"],
            props=props,
        )

    # 2. Crear las arquitecturas y colgar de ellas sus activos
    for fila in filas:
        if fila.get("arquitectura"):
            tx.run(
                """
                MERGE (arq:Arquitectura {nombre: $arq})
                WITH arq
                MATCH (a:Activo {id: $id})
                MERGE (a)-[:PERTENECE_A]->(arq)
                """,
                arq=fila["arquitectura"].strip(),
                id=fila["id"].strip(),
            )

    # 3. Crear las dependencias entre activos
    faltantes = []
    ids = {f["id"].strip() for f in filas}
    for fila in filas:
        for destino in (fila.get("depende_de") or "").split(";"):
            destino = destino.strip()
            if not destino:
                continue
            if destino not in ids:
                faltantes.append(f"{fila['id']} -> {destino}")
                continue
            tx.run(
                """
                MATCH (a:Activo {id: $origen}), (b:Activo {id: $destino})
                MERGE (a)-[:DEPENDE_DE]->(b)
                """,
                origen=fila["id"].strip(),
                destino=destino,
            )
    return faltantes


def enlazar_buckets(tx):
    """Conecta los buckets reales que descubrio Cartography con su arquitectura."""
    mapa = {
        "propuesta-lti": "Propuesta LTI",
        "ecobici": "Ecobici",
        "erp-sap": "ERP",
        "crm-salesforce": "CRM",
    }
    total = 0
    for etiqueta, arquitectura in mapa.items():
        res = tx.run(
            """
            MATCH (b:S3Bucket)-[:TAGGED]->(t:AWSTag {key: 'arquitectura', value: $etiqueta})
            MERGE (arq:Arquitectura {nombre: $arq})
            MERGE (b)-[:PERTENECE_A]->(arq)
            SET b.origen = 'descubierto por Cartography'
            RETURN count(b) AS n
            """,
            etiqueta=etiqueta,
            arq=arquitectura,
        )
        total += res.single()["n"]
    return total


def main():
    filas = leer_csv(ARCHIVO)
    print(f"Leidos {len(filas)} activos de {ARCHIVO}")

    driver = GraphDatabase.driver(URI, auth=(USUARIO, CLAVE) if CLAVE else None)
    with driver.session() as s:
        faltantes = s.execute_write(cargar, filas)
        try:
            n = s.execute_write(enlazar_buckets)
            if n:
                print(f"Enlazados {n} buckets descubiertos por Cartography")
        except Exception:
            pass  # todavia no se ha corrido Cartography

        arqs = s.run(
            "MATCH (a:Activo)-[:PERTENECE_A]->(arq:Arquitectura) "
            "RETURN arq.nombre AS arq, count(a) AS n ORDER BY n DESC"
        ).data()
        deps = s.run("MATCH ()-[r:DEPENDE_DE]->() RETURN count(r) AS n").single()["n"]
    driver.close()

    print("\nActivos por arquitectura:")
    for r in arqs:
        print(f"  {r['arq']}: {r['n']}")
    print(f"\nDependencias creadas: {deps}")
    if faltantes:
        print("\nAviso, dependencias a activos que no estan en el CSV:")
        for f in faltantes:
            print("  " + f)
    print("\nListo. Abre http://localhost:7474 para ver la CMDB.")


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        print(f"No encontre {ARCHIVO}. Guardalo en la misma carpeta que este script.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        print("Revisa que Neo4j este encendido (docker start neo4j).")
        sys.exit(1)
