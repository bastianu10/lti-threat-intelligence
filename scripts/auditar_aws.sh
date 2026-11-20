#!/usr/bin/env bash
# Inventario de SOLO LECTURA de la cuenta de AWS para revisar conexiones, puertos, duplicados y deriva.
# No crea, cambia ni borra nada: solo llamadas describe/list/get. No guarda valores de secretos, de
# parametros de SSM ni variables de entorno de las Lambdas.
# Uso: bash scripts/auditar_aws.sh            (perfil lti, us-east-2)
#      bash scripts/auditar_aws.sh --deriva   (ademas inicia la deteccion de deriva del stack; tampoco cambia recursos)
set -uo pipefail
cd "$(dirname "$0")/.."
PERFIL=${AWS_PROFILE:-lti}; REGION=${AWS_REGION:-us-east-2}; STACK=${STACK:-lti-prototipo}
export AWS_PAGER=""
A=(aws --profile "$PERFIL" --region "$REGION" --output json --no-cli-pager)
SAL="auditoria-aws-$(date +%Y%m%d-%H%M)"; mkdir -p "$SAL"
FALLAS="$SAL/_fallas.txt"; : > "$FALLAS"

# uno NOMBRE -- comando...   guarda la salida en NOMBRE.json; si falla, lo anota y sigue
uno() {
  local nombre="$1"; shift; shift
  if "$@" > "$SAL/$nombre.json" 2> "$SAL/$nombre.err"; then rm -f "$SAL/$nombre.err"
  else echo "$nombre: $(head -c 300 "$SAL/$nombre.err" | tr '\n' ' ')" >> "$FALLAS"; rm -f "$SAL/$nombre.err"; fi
}

echo "Cuenta y perfil..."
uno identidad -- "${A[@]}" sts get-caller-identity

echo "Red..."
uno vpcs -- "${A[@]}" ec2 describe-vpcs
uno subredes -- "${A[@]}" ec2 describe-subnets
uno tablas-de-rutas -- "${A[@]}" ec2 describe-route-tables
uno internet-gateways -- "${A[@]}" ec2 describe-internet-gateways
uno nat-gateways -- "${A[@]}" ec2 describe-nat-gateways
uno vpc-endpoints -- "${A[@]}" ec2 describe-vpc-endpoints
uno grupos-de-seguridad -- "${A[@]}" ec2 describe-security-groups
uno reglas-de-seguridad -- "${A[@]}" ec2 describe-security-group-rules
uno interfaces-de-red -- "${A[@]}" ec2 describe-network-interfaces
uno acls-de-red -- "${A[@]}" ec2 describe-network-acls
uno ips-elasticas -- "${A[@]}" ec2 describe-addresses
uno peering -- "${A[@]}" ec2 describe-vpc-peering-connections

echo "Computo y base de datos..."
uno ec2 -- "${A[@]}" ec2 describe-instances
uno rds -- "${A[@]}" rds describe-db-instances
uno rds-grupos-de-subredes -- "${A[@]}" rds describe-db-subnet-groups
# Lambdas: se omite Environment a proposito (puede traer claves)
uno lambdas -- "${A[@]}" lambda list-functions --query 'Functions[].{Nombre:FunctionName,Runtime:Runtime,Rol:Role,Handler:Handler,Timeout:Timeout,Memoria:MemorySize,Vpc:VpcConfig,Modificada:LastModified,Tamano:CodeSize}'

echo "Integracion y entrada..."
uno step-functions -- "${A[@]}" stepfunctions list-state-machines
uno eventbridge-reglas -- "${A[@]}" events list-rules
for r in $("${A[@]}" events list-rules --query 'Rules[].Name' --output text 2>/dev/null); do
  uno "eventbridge-destinos-$r" -- "${A[@]}" events list-targets-by-rule --rule "$r"
done
uno api-gateway -- "${A[@]}" apigatewayv2 get-apis
uno cloudfront -- "${A[@]}" cloudfront list-distributions
uno cognito -- "${A[@]}" cognito-idp list-user-pools --max-results 20

echo "Almacenamiento y secretos (solo nombres)..."
uno s3-buckets -- "${A[@]}" s3api list-buckets
for b in $("${A[@]}" s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null); do
  uno "s3-acceso-publico-$b" -- "${A[@]}" s3api get-public-access-block --bucket "$b"
  uno "s3-politica-$b" -- "${A[@]}" s3api get-bucket-policy --bucket "$b"
done
uno secretos-nombres -- "${A[@]}" secretsmanager list-secrets --query 'SecretList[].{Nombre:Name,ARN:ARN,Rotacion:RotationEnabled,Modificado:LastChangedDate}'
uno ssm-parametros-nombres -- "${A[@]}" ssm describe-parameters --query 'Parameters[].{Nombre:Name,Tipo:Type,Modificado:LastModifiedDate}'

echo "Permisos (IAM)..."
uno iam-roles -- "${A[@]}" iam list-roles
uno iam-politicas-y-roles -- "${A[@]}" iam get-account-authorization-details --filter Role LocalManagedPolicy
uno iam-usuarios -- "${A[@]}" iam list-users

echo "Stack y recursos fuera de la plantilla..."
uno stack -- "${A[@]}" cloudformation describe-stacks --stack-name "$STACK"
uno stack-recursos -- "${A[@]}" cloudformation list-stack-resources --stack-name "$STACK"
if [ "${1:-}" = "--deriva" ]; then
  ID=$("${A[@]}" cloudformation detect-stack-drift --stack-name "$STACK" --query StackDriftDetectionId --output text 2>/dev/null)
  for i in $(seq 1 30); do
    E=$("${A[@]}" cloudformation describe-stack-drift-detection-status --stack-drift-detection-id "$ID" --query DetectionStatus --output text 2>/dev/null)
    [ "$E" = "DETECTION_COMPLETE" ] || [ "$E" = "DETECTION_FAILED" ] && break; sleep 5
  done
  uno deriva-recursos -- "${A[@]}" cloudformation describe-stack-resource-drifts --stack-name "$STACK"
fi

# Resumen legible de lo que mas interesa
{
  echo "# Resumen rapido ($(date))"
  echo "## Grupos de seguridad con reglas abiertas a 0.0.0.0/0 o ::/0"
  "${A[@]}" ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0'] || Ipv6Ranges[?CidrIpv6=='::/0']]].[GroupId,GroupName,VpcId]" --output text 2>/dev/null
  echo "## Interfaces de red: quien usa cada grupo de seguridad"
  "${A[@]}" ec2 describe-network-interfaces --query "NetworkInterfaces[].[NetworkInterfaceId,InterfaceType,Description,join(',',Groups[].GroupId),SubnetId,PrivateIpAddress]" --output text 2>/dev/null
  echo "## VPC endpoints"
  "${A[@]}" ec2 describe-vpc-endpoints --query "VpcEndpoints[].[VpcEndpointId,ServiceName,VpcEndpointType,State]" --output text 2>/dev/null
} > "$SAL/_resumen.txt"

zip -qr "$SAL.zip" "$SAL" 2>/dev/null || tar czf "$SAL.tgz" "$SAL"
echo
echo "Listo. Carpeta: $SAL  (y su .zip)"
[ -s "$FALLAS" ] && { echo "Algunas consultas fallaron (probablemente falta de permisos). Ver $FALLAS:"; cat "$FALLAS"; }
echo "Antes de subirlo, revisa que no contenga nada que no quieras compartir."
