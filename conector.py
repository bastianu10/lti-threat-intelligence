import json, os, time, datetime, urllib.request, urllib.parse, boto3
s3 = boto3.client("s3")
sm = boto3.client("secretsmanager")
BUCKET = os.environ["RAW_BUCKET"]
SECRETO = os.environ["NVD_SECRET"]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
def get(url, headers=None):
    for intento in range(4):
        try:
            req = urllib.request.Request(url, headers=headers or {"User-Agent": "lti-prototipo"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and intento < 3:
                time.sleep(8 * (intento + 1)); continue
            raise
def handler(event, context):
    ahora = datetime.datetime.now(datetime.timezone.utc)
    desde = ahora - datetime.timedelta(hours=26)
    clave = json.loads(sm.get_secret_value(SecretId=SECRETO)["SecretString"]).get("api_key", "")
    hdr = {"User-Agent": "lti-prototipo"}
    if clave and clave != "PENDIENTE":
        hdr["apiKey"] = clave
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    cves, inicio, total = [], 0, None
    while total is None or inicio < total:
        q = urllib.parse.urlencode({"lastModStartDate": desde.strftime(fmt),
                                    "lastModEndDate": ahora.strftime(fmt),
                                    "startIndex": inicio, "resultsPerPage": 2000})
        datos = json.loads(get("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, hdr))
        total = datos.get("totalResults", 0)
        cves += [v["cve"] for v in datos.get("vulnerabilities", [])]
        inicio += 2000
        time.sleep(1 if clave else 6)
    tag = ahora.strftime("%Y/%m/%d/%H%M%S")
    s3.put_object(Bucket=BUCKET, Key=f"raw/nvd/{tag}.json",
                  Body=json.dumps({"descargado": ahora.isoformat(), "cves": cves}).encode(),
                  ContentType="application/json")
    kev = get(KEV_URL)
    s3.put_object(Bucket=BUCKET, Key=f"raw/kev/{tag}.json", Body=kev, ContentType="application/json")
    return {"cves_nvd": len(cves), "kev_bytes": len(kev), "raw": tag}
