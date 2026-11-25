#!/usr/bin/env bash
# C1 (H1 + H1b): arma lti-nucleo-v<N+1>.zip = paquete DESPLEGADO (v9) + api_datos.py v10 + rds-ca-bundle.pem.
# Uso (desde la raiz del repo): bash scripts/armar_paquete_c1.sh <carpeta_del_zip>/backend
# Exige que las 5 Lambdas del nucleo tengan el mismo codigo que el zip local, que el api_datos.py desplegado sea la
# base esperada (v9) y que solo cambie api_datos.py y se agregue rds-ca-bundle.pem. Solo lectura en AWS.
set -euo pipefail
cd "$(dirname "$0")/.."
ORIGEN=${1:?Indica la carpeta backend del paquete C1}
BASE_SHA="95ecd0520c5f56e3adba9986fcae59a877f5fe2a5c1efa28e15ba224638ca2f2"   # api_datos.py de v9 (reporte ejecutivo)
CA_SHA="90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b"     # mismo bundle que usa el notificador
PERFIL=${AWS_PROFILE:-lti}; REGION=${AWS_REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}

[ "$(openssl dgst -sha256 "$ORIGEN/rds-ca-bundle.pem" | awk '{print $NF}')" = "$CA_SHA" ] || { echo "DETENIDO: bundle de CA distinto"; exit 1; }
ACTUAL=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PERFIL" \
  --query "Stacks[0].Parameters[?ParameterKey=='VersionNucleo'].ParameterValue" --output text)
ZIP_ACTUAL="paquetes/lti-nucleo-$ACTUAL.zip"
[ -f "$ZIP_ACTUAL" ] || { echo "No existe $ZIP_ACTUAL"; exit 1; }
SHA_LOCAL=$(openssl dgst -sha256 -binary "$ZIP_ACTUAL" | base64)
echo "Version desplegada: $ACTUAL   sha256 local: $SHA_LOCAL"
DIFERENTES=0
for f in lti-normalizacion-curada lti-carga-vulnerabilidades lti-cruce-rds lti-api-datos lti-api-sistema; do
  SHA=$(aws lambda get-function-configuration --function-name "$f" --region "$REGION" --profile "$PERFIL" --query CodeSha256 --output text)
  if [ "$SHA" = "$SHA_LOCAL" ]; then echo "  igual     $f"; else echo "  DISTINTO  $f"; DIFERENTES=$((DIFERENTES + 1)); fi
done
[ "$DIFERENTES" -eq 0 ] || { echo "DETENIDO: hay Lambdas con codigo distinto al paquete local."; exit 1; }
SHA_API=$(unzip -p "$ZIP_ACTUAL" api_datos.py | openssl dgst -sha256 | awk '{print $NF}')
[ "$SHA_API" = "$BASE_SHA" ] || { echo "DETENIDO: el api_datos.py desplegado no es la base esperada ($SHA_API)."; exit 1; }
echo "  api_datos.py desplegado = base esperada (v9)"

N=$(( ${ACTUAL#v} + 1 )); NUEVO="paquetes/lti-nucleo-v$N.zip"
[ ! -e "$NUEVO" ] || { echo "DETENIDO: $NUEVO ya existe"; exit 1; }
cp "$ZIP_ACTUAL" "$NUEVO"
TMP=$(mktemp -d); cp "$ORIGEN/api_datos.py" "$ORIGEN/rds-ca-bundle.pem" "$TMP/"
( cd "$TMP" && zip -q "$OLDPWD/$NUEVO" api_datos.py rds-ca-bundle.pem )
rm -rf "$TMP"
python3 - "$ZIP_ACTUAL" "$NUEVO" <<'PY'
import sys, zipfile, hashlib
a, b = (zipfile.ZipFile(x) for x in sys.argv[1:3])
h = lambda z, n: hashlib.sha256(z.read(n)).digest()
cambiados = [n for n in a.namelist() if h(a, n) != h(b, n)]
nuevos = sorted(set(b.namelist()) - set(a.namelist()))
quitados = sorted(set(a.namelist()) - set(b.namelist()))
print("Cambiados:", cambiados, "| Nuevos:", nuevos, "| Quitados:", quitados)
sys.exit(0 if cambiados == ["api_datos.py"] and nuevos == ["rds-ca-bundle.pem"] and not quitados else 1)
PY
echo "sha256 (base64, CodeSha256 esperado): $(openssl dgst -sha256 -binary "$NUEVO" | base64)"
echo "Listo: $NUEVO. Siguiente: copiar la plantilla C1 a infra/ y bash scripts/desplegar.sh"
