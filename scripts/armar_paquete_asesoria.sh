#!/usr/bin/env bash
# Arma lti-nucleo-v<N+1>.zip = paquete DESPLEGADO hoy + api_datos.py con la ruta /api/asesoria. Nada mas cambia.
# Uso (desde la raiz del repo):  bash scripts/armar_paquete_asesoria.sh backend/api_panel/api_datos.py
#
# Mismo criterio que armar_paquete_l5.sh: las 5 Lambdas del nucleo comparten el paquete, asi que se exige que el zip
# local sea identico al desplegado y que solo cambie api_datos.py. Ademas se exige que el api_datos.py desplegado
# sea exactamente la base sobre la que se escribio el cambio (sha256 de abajo). Solo lectura en AWS.
set -euo pipefail
cd "$(dirname "$0")/.."
NUEVO_API=${1:?Indica la ruta del api_datos.py con la ruta de asesoria}
BASE_SHA="54dce77ad90888a938286129abd983e00cbd5040fe151e0546e15ecbe44222fe"   # api_datos.py de v6/v7 sin cambios
PERFIL=${AWS_PROFILE:-lti}; REGION=${AWS_REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}

ACTUAL=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PERFIL" \
  --query "Stacks[0].Parameters[?ParameterKey=='VersionNucleo'].ParameterValue" --output text)
ZIP_ACTUAL="paquetes/lti-nucleo-$ACTUAL.zip"
[ -f "$ZIP_ACTUAL" ] || { echo "No existe $ZIP_ACTUAL"; exit 1; }
SHA_LOCAL=$(openssl dgst -sha256 -binary "$ZIP_ACTUAL" | base64)
echo "Version desplegada: $ACTUAL   sha256 local: $SHA_LOCAL"

DIFERENTES=0
for f in lti-normalizacion-curada lti-carga-vulnerabilidades lti-cruce-rds lti-api-datos lti-api-sistema; do
  SHA=$(aws lambda get-function-configuration --function-name "$f" --region "$REGION" --profile "$PERFIL" \
        --query CodeSha256 --output text)
  if [ "$SHA" = "$SHA_LOCAL" ]; then echo "  igual     $f"; else echo "  DISTINTO  $f"; DIFERENTES=$((DIFERENTES + 1)); fi
done
[ "$DIFERENTES" -eq 0 ] || { echo "DETENIDO: hay Lambdas con codigo distinto al paquete local."; exit 1; }

SHA_API=$(unzip -p "$ZIP_ACTUAL" api_datos.py | openssl dgst -sha256 | awk '{print $NF}')
[ "$SHA_API" = "$BASE_SHA" ] || { echo "DETENIDO: el api_datos.py desplegado no es la base esperada ($SHA_API)."; exit 1; }
echo "  api_datos.py desplegado = base esperada"

N=$(( ${ACTUAL#v} + 1 )); NUEVO="paquetes/lti-nucleo-v$N.zip"
[ ! -e "$NUEVO" ] || { echo "DETENIDO: $NUEVO ya existe"; exit 1; }
cp "$ZIP_ACTUAL" "$NUEVO"
TMP=$(mktemp -d); cp "$NUEVO_API" "$TMP/api_datos.py"
( cd "$TMP" && zip -q "$OLDPWD/$NUEVO" api_datos.py )
rm -rf "$TMP"
diff <(unzip -Z1 "$ZIP_ACTUAL" | sort) <(unzip -Z1 "$NUEVO" | sort) && echo "Misma lista de archivos: OK"
python3 - "$ZIP_ACTUAL" "$NUEVO" <<'PY'
import sys, zipfile, hashlib
a, b = (zipfile.ZipFile(x) for x in sys.argv[1:3])
cambiados = [n for n in a.namelist() if hashlib.sha256(a.read(n)).digest() != hashlib.sha256(b.read(n)).digest()]
print("Archivos con contenido distinto:", cambiados)
sys.exit(0 if cambiados == ["api_datos.py"] else 1)
PY
echo "sha256 (base64, CodeSha256 esperado): $(openssl dgst -sha256 -binary "$NUEVO" | base64)"
echo "Listo: $NUEVO (solo cambia api_datos.py). Siguiente: bash scripts/desplegar.sh"
