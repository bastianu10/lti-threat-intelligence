# Lyft Threat Intelligence (Equipo 4)

Prototipo en AWS (us-east-2): descarga NVD+KEV, EPSS y GitHub Advisories, las normaliza, las carga en RDS PostgreSQL,
cruza contra el inventario, mantiene un CMDB (Neo4j + Cartography) y muestra todo en un panel web con alertas a Slack.
Todos los comandos se corren desde la raíz del repo.

## Mapa del repo
| Carpeta | Qué contiene |
|---|---|
| `infra/` | `plantilla-aws.yaml`: todo el stack de AWS (CloudFormation) |
| `scripts/` | Lo que se ejecuta para desplegar: `desplegar.sh`, `migrar.sh`, `subir_panel.sh` |
| `bd/` | SQL de la base: `esquema.sql`, `descubrimiento.sql`, `api.sql` (migraciones) y `consultas_demo.sql` |
| `backend/api_panel/` | API del panel: `api_datos.py` (datos, alertas, resumen) y `api_sistema.py` (configuración) |
| `backend/ingesta/` | Conectores de las fuentes y `normalizacion_lti.py` |
| `lambdas/` | Código de las Lambdas de carga y cruce (`lambda_handlers.py`, `rds_*.py`, `lti_db.py`), scripts `ver_*.py` para correrlos a mano contra RDS y `requisitos.txt` |
| `cmdb/` | Neo4j + Cartography: `cargar_cmdb.py`, `descubrimiento.py` y sus scripts de sincronización |
| `frontend/` | El panel web (`index.html`). `config.js` lo genera `subir_panel.sh` |
| `datos/` | Inventario de activos (`activos.csv`, `activos_v3.csv`) y datos de prueba |
| `paquetes/` | `lti-nucleo-vN.zip`: código de las Lambdas. Se usa siempre el de número más alto |
| `archivo/` | Material obsoleto, solo de consulta |

## Preparar tu computadora (Mac o Linux)
```bash
git clone <URL-DEL-REPO> lti && cd lti
pip3 install -r lambdas/requisitos.txt
cp .env.local.example .env.local      # llena claves y correos; este archivo NO se sube a git
aws configure --profile lti            # credenciales de la cuenta de AWS
```

## Cada vez que haya cambios
```bash
git pull
bash scripts/migrar.sh        # solo si cambió algo en bd/
bash scripts/desplegar.sh     # si cambió la plantilla o el zip (sube el zip más reciente y despliega)
bash scripts/subir_panel.sh   # si cambió frontend/index.html
```

## Reglas del equipo
- Nunca subas contraseñas, claves ni la URL del webhook de Slack. Van en `.env.local` y en Secrets Manager.
- Si cambias código de `backend/` o `lambdas/`, hay que reconstruir el zip con número nuevo (`paquetes/lti-nucleo-v6.zip`, etc.) para que las Lambdas lo tomen. El zip incluye las librerías (pg8000, six).
- La Lambda de Slack (`Iti-SlackConection1`) vive fuera del stack; la plantilla solo recibe su ARN.
