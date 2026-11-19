"""
Carga los 80 activos de activos.csv en la tabla DynamoDB lti-activos.

Uso:
  python3 cargar_inventario.py --profile lti --region us-east-2
"""
import argparse
import csv
import boto3

CAMPOS = [
    "nombre", "tipo", "arquitectura", "capa", "ambiente", "dueno",
    "producto_version", "criticidad", "clasificacion_informacion",
    "expuesto_internet", "disponibilidad_objetivo", "rto", "rpo", "descripcion",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="activos.csv")
    ap.add_argument("--tabla", default="lti-activos")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--region", default="us-east-2")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    tabla = session.resource("dynamodb").Table(args.tabla)

    with open(args.csv, newline="", encoding="utf-8") as f:
        filas = [r for r in csv.DictReader(f) if r.get("id")]

    print(f"Leidos {len(filas)} activos de {args.csv}")

    with tabla.batch_writer() as lote:
        for fila in filas:
            item = {"id": fila["id"].strip()}
            for c in CAMPOS:
                v = (fila.get(c) or "").strip()
                if v:
                    item[c] = v
            # Dependencias como lista, no como texto con punto y coma
            deps = [d.strip() for d in (fila.get("depende_de") or "").split(";") if d.strip()]
            if deps:
                item["depende_de"] = deps
            lote.put_item(Item=item)

    print(f"Cargados {len(filas)} activos en la tabla '{args.tabla}'")

    # Verificacion rapida: contar lo que realmente quedo en la tabla
    total = tabla.scan(Select="COUNT")["Count"]
    print(f"La tabla '{args.tabla}' ahora tiene {total} items")


if __name__ == "__main__":
    main()
