#!/bin/bash
# Actualiza la CMDB YA DESPLEGADA para que compare lo descubierto contra el inventario. Se corre una vez:
#   bash actualizar_cmdb.sh <endpoint-de-RDS> <clave-de-los-usuarios>
set -eu
[ $# -eq 2 ] || { echo "uso: actualizar_cmdb.sh <endpoint-de-RDS> <clave-usuarios>"; exit 1; }
DB_HOST_NUEVO="$1"; DB_PASSWORD_NUEVA="$2"
. /opt/cmdb/env
cd /opt/cmdb
for f in descubrimiento.py sincronizar.sh; do
  aws s3 cp "s3://$BUCKET/artefactos/cmdb/$f" "$f" --region "$REGION"
done
chmod 700 /opt/cmdb/sincronizar.sh
/opt/cmdb/venv/bin/pip install --quiet pg8000
# variables de la base (sin duplicarlas si se ejecuta otra vez)
grep -v '^DB_' /opt/cmdb/env > /opt/cmdb/env.nuevo || true
printf 'DB_HOST=%s\nDB_USER=u_descubrimiento\nDB_PASSWORD=%s\n' "$DB_HOST_NUEVO" "$DB_PASSWORD_NUEVA" >> /opt/cmdb/env.nuevo
mv /opt/cmdb/env.nuevo /opt/cmdb/env
chmod 600 /opt/cmdb/env
systemctl start --no-block cmdb-sync.service
echo "actualizado: la sincronizacion corre en segundo plano (tarda unos 20 minutos)"
