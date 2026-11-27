#!/usr/bin/env bash
# Sube el paquete mas reciente (lti-nucleo-vN.zip) y despliega el stack con esa version.
# Uso: bash scripts/desplegar.sh        (.env.local es OPCIONAL)
#
# Cambios respecto a la version anterior (lote del Dia 3):
#  1) Las claves YA NO son necesarias para desplegar: si una variable no esta en .env.local, se reutiliza el
#     valor actual del stack (UsePreviousValue). Solo se pasan si se quieren CAMBIAR.
#     IP_PERMITIDA tampoco se toma ya de la IP de quien despliega (antes: desplegar desde otra red cambiaba
#     en silencio quien podia entrar a RDS y a Neo4j); si no se indica, se conserva la actual.
#  2) Primero se crea un CHANGE SET y se muestra; nada se aplica sin escribir SI.
#  3) Barreras automaticas: se aborta si el change set REEMPLAZA o BORRA la base (BaseDatosRDS) o cualquier
#     recurso con datos (buckets, secretos, Cognito, CMDB).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env.local ] && { set -a; source .env.local; set +a; }
if [ -n "${IP_PERMITIDA:-}" ] && ! [[ "$IP_PERMITIDA" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]]; then
  echo "IP_PERMITIDA debe verse asi: 148.241.129.90/32"; exit 1
fi
PERFIL=${AWS_PROFILE:-lti}; REGION=${AWS_REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}
ZIP=$(python3 - <<'PY'
import glob, re
z = sorted(glob.glob("paquetes/lti-nucleo-v*.zip"), key=lambda f: int(re.search(r"v(\d+)", f).group(1)))
print(z[-1])
PY
)
ZIP_ARCHIVO=$(basename "$ZIP"); VERSION=${ZIP_ARCHIVO#lti-nucleo-}; VERSION=${VERSION%.zip}
CUENTA=$(aws sts get-caller-identity --query Account --output text --profile "$PERFIL")
echo "Paquete: $ZIP (version $VERSION), cuenta $CUENTA, IP permitida: ${IP_PERMITIDA:-se conserva la actual}"
aws s3 cp "$ZIP" "s3://lti-curada-$CUENTA/artefactos/$ZIP_ARCHIVO" --profile "$PERFIL" --region "$REGION"

# AMI de la CMDB: la de la instancia actual (fija), para que CloudFormation nunca la reemplace por una imagen nueva.
CMDB_ID=$(aws cloudformation describe-stack-resource --stack-name "$STACK" --logical-resource-id InstanciaCMDB \
  --region "$REGION" --profile "$PERFIL" --query StackResourceDetail.PhysicalResourceId --output text)
AMI_CMDB=$(aws ec2 describe-instances --instance-ids "$CMDB_ID" --region "$REGION" --profile "$PERFIL" \
  --query 'Reservations[0].Instances[0].ImageId' --output text)
[[ "$AMI_CMDB" =~ ^ami-[0-9a-f]+$ ]] || { echo "No se pudo leer la AMI de la CMDB ($CMDB_ID)"; exit 1; }
echo "AMI de la CMDB (se conserva): $AMI_CMDB"

CS="revision-$(date -u +%Y%m%dT%H%M%S)"
# La plantilla supera los 51,200 bytes que CloudFormation acepta en linea: se pasa por S3 (bucket privado;
# CloudFormation la lee con las credenciales de quien despliega). Cada revision queda guardada con su nombre.
PLANTILLA_KEY="artefactos/plantillas/$CS.yaml"
aws s3 cp infra/plantilla-aws.yaml "s3://lti-curada-$CUENTA/$PLANTILLA_KEY" --profile "$PERFIL" --region "$REGION" --only-show-errors
aws cloudformation create-change-set --stack-name "$STACK" --change-set-name "$CS" \
  --template-url "https://lti-curada-$CUENTA.s3.$REGION.amazonaws.com/$PLANTILLA_KEY" --capabilities CAPABILITY_IAM \
  --parameters "$(VERSION="$VERSION" AMI_CMDB="$AMI_CMDB" python3 - <<'PY'
import json, os
# variable de .env.local -> parametro del stack. Sin valor: se reutiliza el actual (los secretos no salen de AWS).
pares = {"EMAIL_PRESUPUESTO": "EmailPresupuesto", "IP_PERMITIDA": "IPPermitida", "CLAVE_RDS": "ClaveRDS",
         "CLAVE_USUARIOS": "ClaveUsuarios", "CLAVE_NEO4J": "ClaveNeo4j", "EMAIL_ADMIN_PANEL": "EmailAdminPanel"}
p = [{"ParameterKey": "VersionNucleo", "ParameterValue": os.environ["VERSION"]},
     {"ParameterKey": "ImagenLinuxArm", "ParameterValue": os.environ["AMI_CMDB"]},
     {"ParameterKey": "ArnSlack", "UsePreviousValue": True}]   # O-10: sin valor por defecto en la plantilla publica
# C2a: solo se pasan los parametros que la plantilla declara (asi retirar uno no rompe el despliegue).
import re
txt = open("infra/plantilla-aws.yaml", encoding="utf-8").read()
bloque = re.search(r"^Parameters:\n(.*?)^\S", txt, re.S | re.M).group(1)
declarados = set(re.findall(r"^  ([A-Za-z0-9]+):\s*$", bloque, re.M))
p = [x for x in p if x["ParameterKey"] in declarados]
for var, clave in pares.items():
    if clave not in declarados: continue
    v = os.environ.get(var, "")
    p.append({"ParameterKey": clave, "ParameterValue": v} if v else {"ParameterKey": clave, "UsePreviousValue": True})
print(json.dumps(p))
PY
)" \
  --region "$REGION" --profile "$PERFIL" --query Id --output text >/dev/null
if ! aws cloudformation wait change-set-create-complete --stack-name "$STACK" --change-set-name "$CS" \
      --region "$REGION" --profile "$PERFIL" 2>/dev/null; then
  aws cloudformation describe-change-set --stack-name "$STACK" --change-set-name "$CS" \
    --region "$REGION" --profile "$PERFIL" --query StatusReason --output text
  echo "No se creo el change set (si dice que no hay cambios, no hay nada que desplegar)."
  aws cloudformation delete-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION" --profile "$PERFIL" || true
  exit 1
fi

CAMBIOS=$(aws cloudformation describe-change-set --stack-name "$STACK" --change-set-name "$CS" \
  --region "$REGION" --profile "$PERFIL" --output json \
  --query 'Changes[].ResourceChange.{accion:Action,recurso:LogicalResourceId,tipo:ResourceType,reemplazo:Replacement}')
echo; echo "=== CAMBIOS PROPUESTOS ==="
export CAMBIOS
python3 - <<'PY'
import json, os
for c in json.loads(os.environ["CAMBIOS"]):
    print("  %-7s %-32s %-38s reemplazo=%s" % (c["accion"], c["recurso"], c["tipo"], c.get("reemplazo") or "-"))
PY

PELIGRO=$(python3 - <<'PY'
import json, os
protegidos = {"BaseDatosRDS", "BucketRaw", "BucketCurada", "BucketFront", "UsuariosPanel", "InstanciaCMDB", "VpcRDS"}
# Los secretos declaran su valor en la plantilla ("PENDIENTE"): CUALQUIER cambio borraria la clave real.
intocables = {"SecretoNVD", "SecretoSlack"}
print(" ".join(c["recurso"] for c in json.loads(os.environ["CAMBIOS"])
               if c["recurso"] in intocables
               or (c["recurso"] in protegidos and (c["accion"] == "Remove" or c.get("reemplazo") in ("True", "Conditional")))))
PY
)
if [ -n "$PELIGRO" ]; then
  echo; echo "ABORTADO: el change set reemplazaria o borraria recursos con datos: $PELIGRO"
  echo "Detalle (que propiedad lo provoca):"
  for r in $PELIGRO; do
    aws cloudformation describe-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION" \
      --profile "$PERFIL" --output table --query "Changes[?ResourceChange.LogicalResourceId=='$r'].ResourceChange.Details[].{recurso:'$r',propiedad:Target.Name,recrea:Target.RequiresRecreation,evaluacion:Evaluation,origen:ChangeSource,causa:CausingEntity}"
  done
  aws cloudformation delete-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION" --profile "$PERFIL"
  exit 1
fi

# Leccion de C-1 (24-nov): un cambio en Cognito exige que el panel publicado ya lo soporte.
if printf '%s' "$CAMBIOS" | grep -q '"UsuariosPanel"'; then
  echo; echo "AVISO: el change set modifica Cognito (UsuariosPanel). Antes de escribir SI, confirma que el panel"
  echo "       publicado (s3://.../index.html) ya es la version que soporta este cambio."
fi
echo; read -r -p "Revisa la lista. Escribe SI para aplicar: " RESP
if [ "$RESP" != "SI" ]; then
  aws cloudformation delete-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION" --profile "$PERFIL"
  echo "Cancelado. No se cambio nada."; exit 0
fi
aws cloudformation execute-change-set --stack-name "$STACK" --change-set-name "$CS" --region "$REGION" --profile "$PERFIL"
echo "Aplicando..."
aws cloudformation wait stack-update-complete --stack-name "$STACK" --region "$REGION" --profile "$PERFIL"
echo "Listo. Si cambiaste el panel: bash scripts/subir_panel.sh"
