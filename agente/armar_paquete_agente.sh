#!/usr/bin/env bash
# Empaqueta la Lambda lti-agente-asesor y sube a S3 curada:
#   artefactos/lti-agente-<VERSION>.zip    (codigo que referencia la plantilla)
#   contexto/<TENANT>.json                 (modelo de negocio del tenant, borrador sin aprobar)
# No despliega nada: eso lo hace desplegar.sh con la plantilla. Uso:  ./armar_paquete_agente.sh a1
set -euo pipefail
VERSION="${1:?indica la version, p. ej. a2}"
PERFIL="${AWS_PROFILE:-lti}"; REGION="${AWS_REGION:-us-east-2}"
TENANT="11111111-1111-1111-1111-111111111111"
DIR="$(cd "$(dirname "$0")" && pwd)"
CUENTA="$(aws sts get-caller-identity --query Account --output text --profile "$PERFIL" --region "$REGION")"
BUCKET="lti-curada-$CUENTA"
ZIP="$DIR/lti-agente-$VERSION.zip"

echo "== 1. Pruebas locales (deben pasar antes de subir nada)"
( cd "$DIR" && python3 -m unittest discover -s tests >/dev/null 2>&1 ) || { echo "ABORTO: fallan las pruebas locales"; exit 1; }
( cd "$DIR" && python3 contrato/ejecutar_aceptacion.py >/dev/null ) || { echo "ABORTO: fallan los casos de aceptacion compartidos"; exit 1; }
echo "   OK (pruebas unitarias y casos de aceptacion)"

echo "== 2. Empaquetar (solo codigo, contrato y prompt; sin pruebas ni datos)"
rm -f "$ZIP"
( cd "$DIR/lambda" && find . -name '__pycache__' -prune -exec rm -rf {} + && zip -qr "$ZIP" agente_asesor.py agente_priorizacion prompts )
unzip -l "$ZIP" | tail -n +4 | sed '$d' | sed '$d' | awk '{print "   "$4}'
SHA="$(shasum -a 256 "$ZIP" | cut -c1-64)"
echo "   sha256 $SHA"

if aws s3api head-object --bucket "$BUCKET" --key "artefactos/lti-agente-$VERSION.zip" --profile "$PERFIL" --region "$REGION" >/dev/null 2>&1; then
  echo "ABORTO: artefactos/lti-agente-$VERSION.zip ya existe. Usa una version nueva (los artefactos no se sobrescriben)."; exit 1
fi

echo "== 3. Respaldar el modelo de negocio vigente (se sobrescribe a continuacion; sirve para la reversion)"
SELLO="$(date -u +%Y%m%dT%H%M%SZ)"
if aws s3api head-object --bucket "$BUCKET" --key "contexto/$TENANT.json" --profile "$PERFIL" --region "$REGION" >/dev/null 2>&1; then
  aws s3 cp "s3://$BUCKET/contexto/$TENANT.json" "s3://$BUCKET/contexto/respaldos/$TENANT-$SELLO.json" --sse AES256 \
    --only-show-errors --profile "$PERFIL" --region "$REGION"
  echo "   OK  respaldo s3://$BUCKET/contexto/respaldos/$TENANT-$SELLO.json"
else
  echo "   (no habia modelo de negocio previo)"
fi

echo "== 4. Subir artefacto y modelo de negocio"
aws s3 cp "$ZIP" "s3://$BUCKET/artefactos/lti-agente-$VERSION.zip" --sse AES256 --only-show-errors --profile "$PERFIL" --region "$REGION"
aws s3 cp "$DIR/contexto/modelo_negocio_lyft.json" "s3://$BUCKET/contexto/$TENANT.json" --sse AES256 \
  --content-type application/json --only-show-errors --profile "$PERFIL" --region "$REGION"
echo "   OK  s3://$BUCKET/artefactos/lti-agente-$VERSION.zip"
echo "   OK  s3://$BUCKET/contexto/$TENANT.json"
echo
echo "Siguiente: copiar infra/plantilla-aws.yaml al repositorio y desplegar con desplegar.sh (VersionAgente=$VERSION)."
