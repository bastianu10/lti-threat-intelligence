#!/bin/bash
# Sincroniza la CMDB: baja sus archivos del bucket, carga los activos, deja que Cartography descubra la cuenta,
# vuelve a enlazar y compara lo descubierto contra el inventario de RDS. Se ejecuta cada 6 horas.
set -u
cd /opt/cmdb
for f in cargar_cmdb.py activos.csv descubrimiento.py; do
  aws s3 cp "s3://$BUCKET/artefactos/cmdb/$f" "$f" --region "$REGION" || exit 1
done
/opt/cmdb/venv/bin/python cargar_cmdb.py activos.csv
/opt/cmdb/venv/bin/cartography --neo4j-uri "$NEO4J_URI" --neo4j-user "$NEO4J_USER" \
  --neo4j-password-env-var NEO4J_PASSWORD --selected-modules aws
/opt/cmdb/venv/bin/python cargar_cmdb.py activos.csv
/opt/cmdb/venv/bin/python descubrimiento.py
