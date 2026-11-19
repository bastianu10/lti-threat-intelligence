"""
Convierte activos.csv (formato original) a activos_v3.csv (campos que exige el esquema v3).
Revisa y edita activos_v3.csv a mano ANTES de cargarlo: varios valores son supuestos del equipo.

Uso:  python3 preparar_activos_v3.py --entrada activos.csv --salida activos_v3.csv
"""
import argparse, csv, re, unicodedata

TIPO = {
    "Base de datos": "base_datos", "Cache": "base_datos", "Almacen de datos": "base_datos",
    "Base de datos de grafos": "base_datos", "Aplicacion cliente": "aplicacion_movil",
    "CDN / DNS": "red", "Balanceador": "red", "Seguridad perimetral": "red", "Red": "red",
    "Orquestador de contenedores": "contenedor", "Conector": "funcion_serverless",
    "CRM": "saas", "Dispositivo IoT": "otro", "Almacenamiento": "otro", "Extension": "otro",
    "Fuente de datos": "otro",
}  # cualquier otro tipo del CSV original se vuelve "servicio"
CAPA_POR_TIPO = {"base_datos": "datos", "red": "red", "aplicacion_movil": "presentacion",
                 "contenedor": "infraestructura", "funcion_serverless": "aplicacion",
                 "servicio": "aplicacion", "saas": "aplicacion", "otro": ""}
CRITICIDAD = {"Critica": 5, "Alta": 4, "Media": 3, "Baja": 2}
CLASIFICACION = {"Publica": "publica", "Interna": "interna", "Confidencial": "confidencial",
                 "Confidencial - datos personales": "restringida", "Confidencial - financiera": "restringida"}
# SUPUESTO: producto publico equivalente en el diccionario CPE de NVD (vendor, producto, version).
# Verificar cada uno contra NVD antes de confiar en los hallazgos que genere.
# SUPUESTO: el mismo producto tambien se conoce por su PURL en los avisos de GitHub (ecosistema -> tipo de PURL).
PURL = {
    "trip-service": "pkg:golang/stdlib", "lock-orchestrator": "pkg:golang/stdlib",
    "pricing-billing": "pkg:pypi/django", "station-inventory": "pkg:maven/org.springframework.boot/spring-boot",
    "eks-ecobici": "pkg:golang/k8s.io/kubernetes",
}
CPE = {
    "alb-envoy": ("envoyproxy", "envoy", "1.30.2"), "eks-ecobici": ("kubernetes", "kubernetes", "1.29"),
    "msk-ecobici": ("apache", "kafka", "3.7.1"), "aurora-ecobici": ("postgresql", "postgresql", "16.4"),
    "elasticache": ("redis", "redis", "7.4"), "spark": ("apache", "spark", "3.5.1"),
    "flink": ("apache", "flink", "1.19"), "auth-oidc": ("nodejs", "node.js", "20"),
    "notifications": ("nodejs", "node.js", "20"), "trip-service": ("golang", "go", "1.22"),
    "lock-orchestrator": ("golang", "go", "1.22"), "pricing-billing": ("djangoproject", "django", "5"),
    "station-inventory": ("vmware", "spring_boot", "3.2"),
}


def slug(t):
    t = unicodedata.normalize("NFKD", t).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")


def minutos(t):
    m = re.match(r"\s*(\d+)\s*(min|h)", t or "")
    return "" if not m else str(int(m.group(1)) * (60 if m.group(2) == "h" else 1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--entrada", default="activos.csv")
    ap.add_argument("--salida", default="activos_v3.csv")
    a = ap.parse_args()
    filas = list(csv.DictReader(open(a.entrada, encoding="utf-8")))
    cols = ["codigo", "nombre", "tipo", "capa", "dominio_negocio", "criticidad", "clasificacion_informacion",
            "equipo", "dueno_nombre", "dueno_correo", "ambiente", "region", "arquitectura", "expuesto_internet",
            "disponibilidad_objetivo", "rto_minutos", "rpo_minutos", "vendor", "producto", "version", "purl",
            "depende_de", "descripcion"]
    with open(a.salida, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in filas:
            tipo = TIPO.get(r["tipo"], "servicio")
            if r["producto_version"] == "AWS Lambda":
                tipo = "funcion_serverless"
            capa = "presentacion" if r["capa"] == "dashboard" else CAPA_POR_TIPO[tipo]
            vendor, prod, ver = CPE.get(r["id"], ("", "", ""))
            if not vendor:                                  # sin producto publico: version del texto, si trae una
                m = re.search(r"\d+(?:\.\d+)*", r["producto_version"])
                ver = m.group(0) if m else "n/d"
            w.writerow({
                "codigo": r["id"], "nombre": r["nombre"], "tipo": tipo, "capa": capa,
                "dominio_negocio": slug(r["arquitectura"]), "criticidad": CRITICIDAD[r["criticidad"]],
                "clasificacion_informacion": CLASIFICACION[r["clasificacion_informacion"]],
                "equipo": r["dueno"], "dueno_nombre": "Responsable de " + r["dueno"],
                "dueno_correo": slug(r["dueno"]) + "@lyft-prototipo.example",
                "ambiente": r["ambiente"] or "produccion", "region": "global", "arquitectura": r["arquitectura"],
                "expuesto_internet": "true" if r["expuesto_internet"] == "Si" else "false",
                "disponibilidad_objetivo": (r["disponibilidad_objetivo"] or "").rstrip("%"),
                "rto_minutos": minutos(r["rto"]), "rpo_minutos": minutos(r["rpo"]),
                "vendor": vendor, "producto": prod, "version": ver, "purl": PURL.get(r["id"], ""),
                "depende_de": r["depende_de"], "descripcion": r["descripcion"],
            })
    print(f"Generado {a.salida}: {len(filas)} activos, {len(CPE)} con producto publico (CPE) asignado")


if __name__ == "__main__":
    main()
