"""Comprueba que el hash del <script> en linea coincide con el de la CSP del panel (F-4). Uso: python3 csp_hash.py index.html"""
import base64, hashlib, re, sys
t = open(sys.argv[1], encoding="utf-8").read()
scripts = re.findall(r"<script>(.*?)</script>", t, re.S)
real = {"sha256-" + base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode() for s in scripts}
csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', t).group(1)
declarados = set(re.findall(r"'(sha256-[A-Za-z0-9+/=]+)'", csp))
ok = real == declarados and len(scripts) == 1
print("OK: el hash de la CSP coincide con el script en linea" if ok else f"DISTINTO: real={real} csp={declarados}")
sys.exit(0 if ok else 1)
