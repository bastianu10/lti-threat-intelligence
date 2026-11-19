# Lyft Threat Intelligence (Equipo 4)

Prototipo en AWS (us-east-2): descarga NVD+KEV, EPSS y GitHub Advisories cada día, las normaliza, las carga en RDS PostgreSQL,
cruza contra el inventario, mantiene un CMDB (Neo4j + Cartography) y muestra todo en un panel web con alertas a Slack.

| Carpeta o archivo | Qué es |
|---|---|
| `lti-prototipo.yaml` | Todo el stack de AWS (CloudFormation) |
| `lti-nucleo-vN.zip` | Código de las Lambdas (normalización, carga, cruce, API). Siempre se usa el de número más alto |
| `backend/` | Código fuente de la API del panel (`api_datos.py`, `api_sistema.py`). Ya viene dentro del zip |
| `frontend/` | El panel (`index.html`). `config.js` lo genera `subir_front.sh` |
| `esquema.sql`, `descubrimiento.sql`, `api.sql` | Esquema de la base y sus migraciones |
| `rds_*.py`, `ver_*.py` | Scripts que se corren a mano contra RDS |

## Preparar tu computadora (Mac o Linux)
```bash
git clone <URL-DEL-REPO> lti && cd lti
pip3 install -r requisitos.txt
cp .env.local.example .env.local      # llena claves y correos; este archivo NO se sube a git
aws configure --profile lti            # credenciales de la cuenta de AWS
```

## Cada vez que haya cambios
```bash
git pull
bash migrar.sh        # solo si cambió api.sql, descubrimiento.sql o esquema.sql
bash desplegar.sh     # si cambió el yaml o el zip (sube el zip más reciente y despliega)
bash subir_front.sh   # si cambió frontend/index.html
```

## Reglas del equipo
- Nunca subas contraseñas, claves ni la URL del webhook de Slack. Van en `.env.local` y en Secrets Manager.
- Si cambias algo de `backend/`, hay que reconstruir el zip con un número nuevo (`lti-nucleo-v5.zip`, etc.) para que las Lambdas lo tomen.
- La Lambda de Slack (`Iti-SlackConection1`) vive fuera del stack; el yaml solo recibe su ARN.
