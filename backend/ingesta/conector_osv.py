import json, os, re, datetime, urllib.request, boto3
s3 = boto3.client("s3")
BUCKET = os.environ["RAW_BUCKET"]
BASE = "https://api.github.com/advisories"
def sig_pagina(encabezado):
    if not encabezado:
        return None
    for parte in encabezado.split(","):
        if 'rel="next"' in parte:
            return parte[parte.find("<") + 1 : parte.find(">")]
    return None
def handler(event, context):
    ahora = datetime.datetime.now(datetime.timezone.utc)
    desde = (ahora - datetime.timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%S")
    url = f"{BASE}?per_page=100&updated=%3E%3D{desde}"
    hdr = {"User-Agent": "lti-prototipo", "Accept": "application/vnd.github+json"}
    avisos, paginas = [], 0
    while url and paginas < 5:
        req = urllib.request.Request(url, headers=hdr)
        with urllib.request.urlopen(req, timeout=30) as r:
            avisos += json.loads(r.read())
            url = sig_pagina(r.headers.get("Link"))
        paginas += 1
    ghsa = [a for a in avisos if a.get("type") != "malware"]
    tag = ahora.strftime("%Y/%m/%d/%H%M%S")
    s3.put_object(
        Bucket=BUCKET,
        Key=f"raw/osv/{tag}.json",
        Body=json.dumps({"descargado": ahora.isoformat(), "avisos": ghsa}).encode(),
        ContentType="application/json",
    )
    return {"avisos_osv": len(ghsa), "paginas": paginas, "raw": tag}
