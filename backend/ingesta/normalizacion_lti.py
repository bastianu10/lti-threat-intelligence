"""
Normalizacion: archivos CRUDOS (S3 Raw) -> archivos CURADOS (S3 Curada). No toca la base de datos.

Cada corrida escribe, bajo curada-v3/AAAA/MM/DD/HHMMSS/ :
    nvd.json, kev.json, epss.json, osv.json   (solo las fuentes que haya)
    manifest.json                             (se escribe AL FINAL: define la instantanea y la huella de cada parte)
El manifest guarda de que archivos crudos salio cada parte y el SHA-256 de cada una, para poder reproducir y
verificar cualquier evaluacion posterior.

Uso local (archivos o carpeta):
  python3 normalizacion_lti.py --nvd-archivo nvd.json --kev-archivo kev.json --epss-archivo epss.json \
      --osv-archivo osv.json --salida-dir curada/
Uso con S3:
  python3 normalizacion_lti.py --bucket-raw lti-raw-CUENTA --bucket-curada lti-curada-CUENTA --profile lti
"""
import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone

RE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
RE_CWE = re.compile(r"^(CWE-[0-9]+|NVD-CWE-(Other|noinfo))$")
RE_PURL = re.compile(r"^pkg:[a-z0-9.+-]+/[^@?#]+$")
RE_RESTRICCION = re.compile(r"^(<=|>=|<|>|=)\s*(\S+)$")
CLAVES_CVSS = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}
# ecosistema de GitHub -> tipo de PURL
ECO_A_PURL = {"npm": "npm", "pip": "pypi", "maven": "maven", "go": "golang", "rubygems": "gem", "rust": "cargo",
              "nuget": "nuget", "composer": "composer", "erlang": "hex", "pub": "pub", "swift": "swift",
              "actions": "githubactions"}
PREFIJO = "curada-v3/"


def parsear_cve(c):
    """Un CVE del NVD -> descripcion, fechas, cwe, metricas (con vector) y rangos por producto (CPE)."""
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), None)
    cwes = {d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if RE_CWE.match(d.get("value", ""))}
    metricas = {}
    for clave, version in CLAVES_CVSS.items():
        for m in sorted(c.get("metrics", {}).get(clave, []), key=lambda x: x.get("type") != "Primary"):
            d = m.get("cvssData", {})
            if d.get("vectorString") and d.get("baseScore") is not None:
                metricas.setdefault(version, [d["vectorString"], d["baseScore"]])
    rangos = []
    for cfg in c.get("configurations", []):
        for nodo in cfg.get("nodes", []):
            for m in nodo.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                p = re.split(r"(?<!\\):", m.get("criteria", ""))
                if len(p) < 6 or p[0] != "cpe" or p[2] not in ("a", "o", "h"):
                    continue
                vendor, prod, ver = p[3].lower(), p[4].lower(), p[5]
                if vendor in ("*", "-", "") or prod in ("*", "-", "") or ":" in vendor or ":" in prod:
                    continue
                desde = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                hasta = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                exacta = None if (desde or hasta or ver in ("*", "-")) else ver
                rangos.append([p[2], vendor, prod, exacta, desde, "versionStartExcluding" not in m or bool(m.get("versionStartIncluding")),
                               hasta, bool(m.get("versionEndIncluding"))])
    return {"cve": c["id"], "descripcion": desc, "pub": c.get("published"), "mod": c.get("lastModified"),
            "cwes": sorted(cwes), "metricas": metricas, "rangos": rangos}


def construir_purl(ecosistema, nombre):
    """(ecosistema de GitHub, nombre del paquete) -> (tipo, nombre normalizado, purl) o None."""
    tipo = ECO_A_PURL.get((ecosistema or "").lower())
    n = (nombre or "").strip()
    if not tipo or not n or "?" in n or "#" in n:
        return None
    if tipo == "maven":
        n = n.replace(":", "/")                 # grupo:artefacto -> grupo/artefacto
    if tipo == "pypi":
        n = n.replace("_", "-")
    n = n.lower().replace("@", "%40")
    purl = f"pkg:{tipo}/{n}"
    return (tipo, n, purl) if RE_PURL.match(purl) else None


def parsear_rango_ghsa(texto):
    """'>= 1.0.0, < 1.4.0' -> [exacta, desde, desde_incluye, hasta, hasta_incluye]; None si no se entiende."""
    exacta = desde = hasta = None
    d_inc, h_inc = True, False
    for parte in [p.strip() for p in (texto or "").split(",") if p.strip()]:
        m = RE_RESTRICCION.match(parte)
        if not m:
            return None
        op, ver = m.groups()
        if op == "=" and exacta is None:
            exacta = ver
        elif op in (">=", ">") and desde is None:
            desde, d_inc = ver, op == ">="
        elif op in ("<=", "<") and hasta is None:
            hasta, h_inc = ver, op == "<="
        else:
            return None
    if exacta and (desde or hasta):
        return None
    return None if not (exacta or desde or hasta) else [exacta, desde, d_inc, hasta, h_inc]


def parsear_ghsa(a, cont):
    """Un aviso de GitHub -> dict como parsear_cve, o None. 'cont' acumula por que se omiten avisos."""
    if a.get("type") not in (None, "reviewed") or a.get("withdrawn_at"):
        cont["retirado_o_no_revisado"] += 1
        return None
    cve = a.get("cve_id")
    if not cve or not RE_CVE.match(cve):
        cont["sin_cve"] += 1                    # v3 identifica cada vulnerabilidad por su CVE
        return None
    metricas = {}
    candidatos = [v for v in (a.get("cvss_severities") or {}).values() if v] + ([a["cvss"]] if a.get("cvss") else [])
    for c in candidatos:
        m = re.match(r"^CVSS:(\d\.\d)/", c.get("vector_string") or "")
        if m and m.group(1) in ("3.0", "3.1", "4.0") and c.get("score") is not None:
            metricas.setdefault(m.group(1), [c["vector_string"], c["score"]])
    rangos = []
    for v in a.get("vulnerabilities") or []:
        p = construir_purl((v.get("package") or {}).get("ecosystem"), (v.get("package") or {}).get("name"))
        if not p:
            cont["ecosistema_no_soportado"] += 1
            continue
        r = parsear_rango_ghsa(v.get("vulnerable_version_range"))
        if not r:
            cont["rango_no_interpretable"] += 1
            continue
        rangos.append(list(p) + r)              # [tipo, nombre, purl, exacta, desde, d_inc, hasta, h_inc]
    cwes = sorted({c["cwe_id"] for c in a.get("cwes") or [] if RE_CWE.match(c.get("cwe_id") or "")})
    return {"cve": cve, "descripcion": a.get("summary"), "pub": a.get("published_at"), "mod": a.get("updated_at"),
            "cwes": cwes, "metricas": metricas, "rangos": rangos}


def normalizar(nvd_b, kev_b, epss_b, osv_b):
    """Bytes crudos -> {nombre_de_parte: objeto JSON}. Solo incluye las fuentes que llegaron."""
    partes = {}
    if nvd_b:
        cves = {}
        for c in json.loads(nvd_b).get("cves", []):
            if RE_CVE.match(c.get("id", "")):
                cves[c["id"]] = parsear_cve(c)
        partes["nvd"] = {"cves": [cves[k] for k in sorted(cves)]}
    if kev_b:
        kev = {v["cveID"]: v for v in json.loads(kev_b).get("vulnerabilities", []) if RE_CVE.match(v.get("cveID", ""))}
        partes["kev"] = {"entradas": [{"cve": k, "agregado_en": v["dateAdded"], "fecha_limite": v.get("dueDate") or None,
                                       "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                                       "descripcion": v.get("shortDescription")} for k, v in sorted(kev.items())]}
    if epss_b:
        d = json.loads(epss_b)
        fecha = (d.get("descargado") or datetime.now(timezone.utc).isoformat())[:10]
        partes["epss"] = {"fecha": fecha, "puntajes": sorted([p["cve"], p["epss"], p["percentil"]] for p in d.get("puntajes", []))}
    if osv_b:
        cont = {"sin_cve": 0, "retirado_o_no_revisado": 0, "ecosistema_no_soportado": 0, "rango_no_interpretable": 0}
        avisos = json.loads(osv_b).get("avisos", [])
        por_cve = {}
        for a in avisos:
            p = parsear_ghsa(a, cont)
            if not p:
                continue
            if p["cve"] in por_cve:             # el mismo CVE en varios avisos: se juntan los rangos
                x = por_cve[p["cve"]]
                x["rangos"] += p["rangos"]
                x["cwes"] = sorted(set(x["cwes"]) | set(p["cwes"]))
                for k, v in p["metricas"].items():
                    x["metricas"].setdefault(k, v)
            else:
                por_cve[p["cve"]] = p
        partes["osv"] = {"total_avisos": len(avisos), "omitidos": cont, "avisos": [por_cve[k] for k in sorted(por_cve)]}
    return partes


def _bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _registros(nombre, parte):
    return len(parte.get({"nvd": "cves", "kev": "entradas", "epss": "puntajes", "osv": "avisos"}[nombre], []))


def construir_salida(crudos, prefijo):
    """crudos: {nombre: (bytes, clave)} -> ({nombre_de_archivo: bytes}, resumen). El manifest va al final."""
    partes = normalizar(*(crudos.get(n, (None, None))[0] for n in ("nvd", "kev", "epss", "osv")))
    archivos, manifest = {}, {"version_formato": 1, "generado": datetime.now(timezone.utc).isoformat(),
                              "fuentes": {}, "partes": {}}
    for nombre, parte in partes.items():
        b = _bytes(parte)
        archivos[f"{nombre}.json"] = b
        manifest["partes"][nombre] = {"clave": f"{prefijo}{nombre}.json", "sha256": _sha(b), "registros": _registros(nombre, parte)}
        manifest["fuentes"][nombre] = {"clave": crudos[nombre][1], "sha256": _sha(crudos[nombre][0])}
    archivos["manifest.json"] = _bytes(manifest)
    return archivos, manifest


def leer_ultimo(s3, bucket, tipo):
    """Archivo crudo mas reciente de raw/<tipo>/ -> (bytes, clave) o (None, None)."""
    claves = []
    for pag in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"raw/{tipo}/"):
        claves += [o["Key"] for o in pag.get("Contents", [])]
    if not claves:
        return None, None
    k = sorted(claves)[-1]
    return s3.get_object(Bucket=bucket, Key=k)["Body"].read(), k


def ejecutar_s3(bucket_raw, bucket_curada, s3=None):
    """Lee lo crudo mas reciente, normaliza y escribe la instantanea curada. Devuelve un resumen."""
    if s3 is None:
        import boto3
        s3 = boto3.client("s3")
    crudos = {t: leer_ultimo(s3, bucket_raw, t) for t in ("nvd", "kev", "epss", "osv")}
    crudos = {t: v for t, v in crudos.items() if v[0]}
    if not crudos:
        raise RuntimeError("No hay archivos crudos en raw/ para normalizar")
    prefijo = f"{PREFIJO}{datetime.now(timezone.utc).strftime('%Y/%m/%d/%H%M%S')}/"
    archivos, manifest = construir_salida(crudos, prefijo)
    for nombre, b in archivos.items():
        if nombre != "manifest.json":
            s3.put_object(Bucket=bucket_curada, Key=prefijo + nombre, Body=b, ContentType="application/json")
    s3.put_object(Bucket=bucket_curada, Key=prefijo + "manifest.json", Body=archivos["manifest.json"],
                  ContentType="application/json")                      # al final: la instantanea queda completa
    return {"manifest": prefijo + "manifest.json",
            "partes": {n: p["registros"] for n, p in manifest["partes"].items()},
            "fuentes": {n: f["clave"] for n, f in manifest["fuentes"].items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket-raw")
    ap.add_argument("--bucket-curada")
    ap.add_argument("--profile")
    ap.add_argument("--region", default="us-east-2")
    for f in ("nvd", "kev", "epss", "osv"):
        ap.add_argument(f"--{f}-archivo")
    ap.add_argument("--salida-dir", help="escribe la instantanea en una carpeta local en vez de S3")
    a = ap.parse_args()
    if a.bucket_raw and a.bucket_curada and not a.salida_dir:
        import boto3
        s = boto3.Session(profile_name=a.profile, region_name=a.region) if a.profile else boto3.Session(region_name=a.region)
        print(json.dumps(ejecutar_s3(a.bucket_raw, a.bucket_curada, s.client("s3")), indent=1))
        return
    crudos = {n: (open(getattr(a, f"{n}_archivo"), "rb").read(), getattr(a, f"{n}_archivo"))
              for n in ("nvd", "kev", "epss", "osv") if getattr(a, f"{n}_archivo")}
    if not crudos or not a.salida_dir:
        raise SystemExit("Indica --bucket-raw y --bucket-curada, o archivos locales con --salida-dir")
    archivos, manifest = construir_salida(crudos, "")
    os.makedirs(a.salida_dir, exist_ok=True)
    for nombre, b in archivos.items():
        open(os.path.join(a.salida_dir, nombre), "wb").write(b)
    print("Escrito en", a.salida_dir, {n: p["registros"] for n, p in manifest["partes"].items()})


if __name__ == "__main__":
    main()
