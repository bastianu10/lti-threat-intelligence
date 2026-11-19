import gzip, io, json, csv, os, datetime, urllib.request, boto3
s3 = boto3.client("s3")
BUCKET = os.environ["RAW_BUCKET"]
URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
def handler(event, context):
    req = urllib.request.Request(URL, headers={"User-Agent": "lti-prototipo"})
    with urllib.request.urlopen(req, timeout=60) as r:
        crudo = r.read()
    texto = gzip.decompress(crudo).decode("utf-8")
    lineas = [l for l in texto.splitlines() if l and not l.startswith("#")]
    filas = list(csv.DictReader(lineas))
    puntajes = [{"cve": f["cve"], "epss": float(f["epss"]), "percentil": float(f["percentile"])} for f in filas]
    ahora = datetime.datetime.now(datetime.timezone.utc)
    tag = ahora.strftime("%Y/%m/%d/%H%M%S")
    s3.put_object(
        Bucket=BUCKET,
        Key=f"raw/epss/{tag}.json",
        Body=json.dumps({"descargado": ahora.isoformat(), "puntajes": puntajes}).encode(),
        ContentType="application/json",
    )
    return {"cves_epss": len(puntajes), "raw": tag}
