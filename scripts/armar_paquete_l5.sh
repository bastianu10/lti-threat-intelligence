#!/usr/bin/env bash
# Arma lti-nucleo-v<N+1>.zip = paquete DESPLEGADO hoy + api_sistema.py parcheado (L5). Nada mas cambia.
# Uso (desde la raiz del repo):  bash scripts/armar_paquete_l5.sh ruta/al/api_sistema.py
#
# Por que asi: las 5 Lambdas del stack (normalizacion, carga v1, cruce v1, api-datos, api-sistema) usan el MISMO
# paquete. Si el zip local no es identico al desplegado, el deploy revertiria en silencio el codigo de las otras.
# Este script se niega a continuar si detecta esa diferencia.  Solo lectura en AWS.
set -euo pipefail
cd "$(dirname "$0")/.."
NUEVO_API=${1:?Indica la ruta del api_sistema.py parcheado}
PERFIL=${AWS_PROFILE:-lti}; REGION=${AWS_REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}

ACTUAL=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PERFIL" \
  --query "Stacks[0].Parameters[?ParameterKey=='VersionNucleo'].ParameterValue" --output text)
ZIP_ACTUAL="paquetes/lti-nucleo-$ACTUAL.zip"
if [ ! -f "$ZIP_ACTUAL" ]; then      # se baja el paquete DESPLEGADO desde S3 (el mismo que usa CloudFormation)
  mkdir -p paquetes
  CUENTA=$(aws sts get-caller-identity --query Account --output text --profile "$PERFIL")
  aws s3 cp "s3://lti-curada-$CUENTA/artefactos/lti-nucleo-$ACTUAL.zip" "$ZIP_ACTUAL" --region "$REGION" --profile "$PERFIL"
fi
SHA_LOCAL=$(openssl dgst -sha256 -binary "$ZIP_ACTUAL" | base64)
echo "Version desplegada: $ACTUAL   sha256 local: $SHA_LOCAL"

DIFERENTES=0
for f in lti-normalizacion-curada lti-carga-vulnerabilidades lti-cruce-rds lti-api-datos lti-api-sistema; do
  SHA=$(aws lambda get-function-configuration --function-name "$f" --region "$REGION" --profile "$PERFIL" \
        --query CodeSha256 --output text)
  if [ "$SHA" = "$SHA_LOCAL" ]; then echo "  igual     $f"
  else echo "  DISTINTO  $f  (desplegado: $SHA)"; DIFERENTES=$((DIFERENTES + 1)); fi
done
if [ "$DIFERENTES" -gt 0 ]; then
  echo; echo "DETENIDO: $DIFERENTES Lambda(s) tienen codigo distinto al paquete local. Alguien las cambio a mano."
  echo "Desplegar un paquete nuevo revertiria esos cambios. Revisar antes de continuar."; exit 1
fi

N=$(( ${ACTUAL#v} + 1 )); NUEVO="paquetes/lti-nucleo-v$N.zip"
cp "$ZIP_ACTUAL" "$NUEVO"
TMP=$(mktemp -d); cp "$NUEVO_API" "$TMP/api_sistema.py"
( cd "$TMP" && zip -q "$OLDPWD/$NUEVO" api_sistema.py )
rm -rf "$TMP"
diff <(unzip -Z1 "$ZIP_ACTUAL" | sort) <(unzip -Z1 "$NUEVO" | sort) && echo "Misma lista de archivos: OK"
python3 - "$ZIP_ACTUAL" "$NUEVO" <<'PY'
import sys, zipfile, hashlib
a, b = (zipfile.ZipFile(x) for x in sys.argv[1:3])
cambiados = [n for n in a.namelist() if hashlib.sha256(a.read(n)).digest() != hashlib.sha256(b.read(n)).digest()]
print("Archivos con contenido distinto:", cambiados)
sys.exit(0 if cambiados == ["api_sistema.py"] else 1)
PY
echo "Listo: $NUEVO (solo cambia api_sistema.py). Siguiente: bash scripts/desplegar.sh"
