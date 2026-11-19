#!/usr/bin/env bash
# Sube el paquete mas reciente (lti-nucleo-vN.zip) y despliega el stack con esa version.
# Uso: bash desplegar.sh        (lee las claves de .env.local)
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env.local ] && source .env.local
for v in CLAVE_RDS CLAVE_USUARIOS CLAVE_NEO4J EMAIL_ADMIN_PANEL EMAIL_PRESUPUESTO; do
  [ -n "${!v:-}" ] || { echo "Falta $v en .env.local"; exit 1; }
done
PERFIL=${AWS_PROFILE:-lti}; REGION=${AWS_REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}
ZIP=$(python3 - <<'PY'
import glob, re
z = sorted(glob.glob("lti-nucleo-v*.zip"), key=lambda f: int(re.search(r"v(\d+)", f).group(1)))
print(z[-1])
PY
)
VERSION=${ZIP#lti-nucleo-}; VERSION=${VERSION%.zip}
CUENTA=$(aws sts get-caller-identity --query Account --output text --profile "$PERFIL")
echo "Paquete: $ZIP (version $VERSION), cuenta $CUENTA"
aws s3 cp "$ZIP" "s3://lti-curada-$CUENTA/artefactos/$ZIP" --profile "$PERFIL" --region "$REGION"
aws cloudformation deploy --template-file lti-prototipo.yaml --stack-name "$STACK" \
  --parameter-overrides EmailPresupuesto="$EMAIL_PRESUPUESTO" IPPermitida="$(curl -s https://checkip.amazonaws.com)/32" \
    ClaveRDS="$CLAVE_RDS" ClaveUsuarios="$CLAVE_USUARIOS" ClaveNeo4j="$CLAVE_NEO4J" EmailAdminPanel="$EMAIL_ADMIN_PANEL" VersionNucleo="$VERSION" \
  --capabilities CAPABILITY_IAM --region "$REGION" --profile "$PERFIL"
echo "Listo. Si cambiaste el panel: bash subir_front.sh"
