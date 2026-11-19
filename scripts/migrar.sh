#!/usr/bin/env bash
# Aplica la migracion de la base (tabla de metricas y alertas). Es seguro repetirla.
# Uso: bash scripts/migrar.sh        (necesita tu IP permitida: corre antes desplegar.sh si cambio)
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env.local ] && source .env.local
: "${CLAVE_RDS:?Falta CLAVE_RDS en .env.local}"; : "${RDS_HOST:?Falta RDS_HOST en .env.local}"
python3 lambdas/rds_migracion_api.py --host "$RDS_HOST" --password "$CLAVE_RDS"
