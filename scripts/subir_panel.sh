#!/usr/bin/env bash
# Sube el panel a S3 y borra la cache de CloudFront. Uso: bash scripts/subir_panel.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PERFIL=${PERFIL:-lti}; REGION=${REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}
salida() { aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PERFIL" \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
BUCKET=$(salida PanelBucket); DIST=$(salida PanelDistribucionId); POOL=$(salida CognitoUserPoolId)
CLIENTE=$(salida CognitoClientId); URL=$(salida PanelUrl)
[ -n "$BUCKET" ] && [ "$BUCKET" != "None" ] || { echo "No encuentro el bucket del panel: ¿ya hiciste el deploy?"; exit 1; }
TMP=$(mktemp -d); cp frontend/index.html "$TMP/index.html"
cat > "$TMP/config.js" <<CFG
window.LTI_CONFIG = { region: "$REGION", userPoolId: "$POOL", clientId: "$CLIENTE" };
CFG
aws s3 cp "$TMP/index.html" "s3://$BUCKET/index.html" --content-type "text/html; charset=utf-8" --profile "$PERFIL" --region "$REGION"
aws s3 cp "$TMP/config.js"  "s3://$BUCKET/config.js"  --content-type "application/javascript; charset=utf-8" --profile "$PERFIL" --region "$REGION"
aws cloudfront create-invalidation --distribution-id "$DIST" --paths "/*" --profile "$PERFIL" --query "Invalidation.Status" --output text
rm -rf "$TMP"
echo "Listo: $URL"
