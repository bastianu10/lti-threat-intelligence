-- =====================================================================
--  Lyft Threat Intelligence - Esquema relacional v3 (normalizado)
--  Motor: PostgreSQL 15+ (RDS PostgreSQL o Aurora PostgreSQL)
-- =====================================================================
--  Fuentes de verdad (una por dato; la base NO duplica lo que vive fuera):
--    - Cognito / IdP corporativo .... identidad, MFA y roles (grupos)
--    - DynamoDB (config de tenant) .. contexto, dominios y ambientes
--                                     habilitados, canales de Slack
--    - S3 Raw / Curada .............. datos crudos e historico (EPSS diario,
--                                     instantaneas de cada corrida)
--    - Esta base .................... inventario, catalogo vigente de
--                                     vulnerabilidades, hallazgos,
--                                     evaluaciones, aprobaciones y planes
--
--  Forma normal objetivo: 3FN / FNBC. Desnormalizaciones conscientes:
--    D1. tenant_id en tablas hijas: requisito de RLS; consistencia
--        garantizada por llaves foraneas compuestas (tenant_id, id).
--    D2. hallazgos.estado: estado vigente materializado de la bitacora
--        `decisiones`; solo lo escribe el trigger aplicar_decision().
--    D3. cvss_metricas.puntaje_base: funcion del vector CVSS.
--    D4. notificaciones.slack_canal_id: instantanea del destino real al
--        momento del envio (hecho historico).
--
--  CAMBIOS RESPECTO A LA VERSION ORIGINAL (marcados con [CAMBIO]):
--    1. GRANT SELECT sobre evaluacion_senales y politicas_sla a
--       ti_agente_notificacion: sin ellos, v_hallazgos_tablero (vista
--       security_invoker) falla con "permission denied".
--    2. Semilla de la organizacion 'lyft' y su SLA (seccion 8), antes de
--       activar RLS, para que el prototipo tenga un tenant donde cargar.
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION catalogo_global() RETURNS uuid
LANGUAGE sql IMMUTABLE AS $$ SELECT '00000000-0000-0000-0000-000000000000'::uuid $$;

CREATE OR REPLACE FUNCTION tenant_actual() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION tocar_actualizado_en() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.actualizado_en := now();
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION impedir_modificacion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'La tabla % es de solo inserción (auditoría)', TG_TABLE_NAME;
END $$;

-- ---------------------------------------------------------------------
-- 1. ORGANIZACION E IDENTIDAD
-- ---------------------------------------------------------------------
CREATE TABLE organizaciones (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{3,40}$'),
    nombre      TEXT NOT NULL,
    creado_en   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE usuarios (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organizaciones(id),
    cognito_sub     UUID NOT NULL UNIQUE,
    nombre          TEXT NOT NULL,
    correo          TEXT NOT NULL,
    activo          BOOLEAN NOT NULL DEFAULT TRUE,
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX uq_usuarios_correo ON usuarios (tenant_id, lower(correo));

CREATE TABLE equipos (
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES organizaciones(id),
    nombre      TEXT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, nombre)
);

-- ---------------------------------------------------------------------
-- 2. INVENTARIO (registro manual por los duenos): activo -> despliegue -> componentes
-- ---------------------------------------------------------------------
CREATE TABLE activos (
    id                          UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                   UUID NOT NULL REFERENCES organizaciones(id),
    codigo                      TEXT NOT NULL CHECK (codigo ~ '^[a-z0-9][a-z0-9._-]{1,62}$'),
    nombre                      TEXT NOT NULL,
    tipo                        TEXT NOT NULL CHECK (tipo IN
                                    ('servicio','base_datos','servidor','contenedor',
                                     'funcion_serverless','aplicacion_movil','red','saas','otro')),
    capa                        TEXT CHECK (capa IN
                                    ('presentacion','aplicacion','datos','infraestructura','red')),
    dominio_negocio             TEXT NOT NULL,      -- validado contra DynamoDB por la Lambda de Registro
    criticidad                  SMALLINT NOT NULL CHECK (criticidad BETWEEN 1 AND 5),  -- 5 = critica
    clasificacion_informacion   TEXT NOT NULL CHECK (clasificacion_informacion IN
                                    ('publica','interna','confidencial','restringida')),
    dueno_id                    UUID NOT NULL,
    equipo_id                   UUID,
    descripcion                 TEXT,
    creado_en                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    actualizado_en              TIMESTAMPTZ NOT NULL DEFAULT now(),
    dado_de_baja_en             TIMESTAMPTZ,
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, codigo),
    FOREIGN KEY (tenant_id, dueno_id)  REFERENCES usuarios (tenant_id, id),
    FOREIGN KEY (tenant_id, equipo_id) REFERENCES equipos  (tenant_id, id)
);
CREATE INDEX idx_activos_dueno ON activos (tenant_id, dueno_id);

CREATE TABLE despliegues (
    id                      UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL,
    activo_id               UUID NOT NULL,
    ambiente                TEXT NOT NULL CHECK (ambiente IN ('produccion','pruebas','escenarios')),
    region                  TEXT NOT NULL DEFAULT 'global',
    arquitectura            TEXT,
    expuesto_internet       BOOLEAN NOT NULL DEFAULT FALSE,
    disponibilidad_objetivo NUMERIC(6,3) CHECK (disponibilidad_objetivo BETWEEN 0 AND 100),
    rto                     INTERVAL CHECK (rto >= interval '0'),
    rpo                     INTERVAL CHECK (rpo >= interval '0'),
    creado_en               TIMESTAMPTZ NOT NULL DEFAULT now(),
    actualizado_en          TIMESTAMPTZ NOT NULL DEFAULT now(),
    dado_de_baja_en         TIMESTAMPTZ,
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, activo_id, ambiente, region),
    FOREIGN KEY (tenant_id, activo_id) REFERENCES activos (tenant_id, id)
);

CREATE TABLE despliegue_dependencias (
    tenant_id       UUID NOT NULL,
    despliegue_id   UUID NOT NULL,
    depende_de_id   UUID NOT NULL,
    tipo            TEXT NOT NULL DEFAULT 'ejecucion' CHECK (tipo IN
                        ('ejecucion','datos','autenticacion','red')),
    PRIMARY KEY (tenant_id, despliegue_id, depende_de_id),
    CHECK (despliegue_id <> depende_de_id),
    FOREIGN KEY (tenant_id, despliegue_id) REFERENCES despliegues (tenant_id, id),
    FOREIGN KEY (tenant_id, depende_de_id) REFERENCES despliegues (tenant_id, id)
);

CREATE TABLE recertificaciones (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    activo_id           UUID NOT NULL,
    usuario_id          UUID NOT NULL,
    resultado           TEXT NOT NULL CHECK (resultado IN ('sin_cambios','con_cambios')),
    recertificado_en    TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, activo_id)  REFERENCES activos  (tenant_id, id),
    FOREIGN KEY (tenant_id, usuario_id) REFERENCES usuarios (tenant_id, id)
);
CREATE INDEX idx_recert_activo ON recertificaciones (tenant_id, activo_id, recertificado_en DESC);

-- ---------------------------------------------------------------------
-- 3. CATALOGO DE PRODUCTOS (CPE / PURL). tenant_id = catalogo_global() => producto publico
-- ---------------------------------------------------------------------
CREATE TABLE productos (
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES organizaciones(id),
    vendor      TEXT NOT NULL CHECK (vendor = lower(vendor)),
    nombre      TEXT NOT NULL CHECK (nombre = lower(nombre)),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, vendor, nombre)
);

CREATE TABLE producto_identificadores (
    tenant_id   UUID NOT NULL,
    producto_id UUID NOT NULL,
    esquema     TEXT NOT NULL CHECK (esquema IN ('cpe','purl')),
    valor       TEXT NOT NULL,
    PRIMARY KEY (tenant_id, esquema, valor),
    FOREIGN KEY (tenant_id, producto_id) REFERENCES productos (tenant_id, id),
    CHECK (
        (esquema = 'cpe'  AND valor ~ '^cpe:2\.3:[aho]:[^:]+:[^:]+$') OR
        (esquema = 'purl' AND valor ~ '^pkg:[a-z0-9.+-]+/[^@?#]+$')
    )
);

CREATE TABLE componentes (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    despliegue_id       UUID NOT NULL,
    producto_tenant_id  UUID NOT NULL,
    producto_id         UUID NOT NULL,
    version             TEXT NOT NULL,
    origen              TEXT NOT NULL CHECK (origen IN ('formulario','csv')),
    creado_en           TIMESTAMPTZ NOT NULL DEFAULT now(),
    retirado_en         TIMESTAMPTZ,            -- baja logica: conserva el historial de hallazgos
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, despliegue_id)        REFERENCES despliegues (tenant_id, id),
    FOREIGN KEY (producto_tenant_id, producto_id) REFERENCES productos   (tenant_id, id),
    CHECK (producto_tenant_id IN (tenant_id, catalogo_global()))
);
CREATE UNIQUE INDEX uq_componente_vigente ON componentes (tenant_id, despliegue_id, producto_id, version)
    WHERE retirado_en IS NULL;
CREATE INDEX idx_componente_producto ON componentes (producto_id) WHERE retirado_en IS NULL;

-- ---------------------------------------------------------------------
-- 4. CATALOGO GLOBAL DE VULNERABILIDADES (estado vigente; historico en S3)
-- ---------------------------------------------------------------------
CREATE TABLE fuentes (
    codigo  TEXT PRIMARY KEY CHECK (codigo ~ '^[a-z0-9_]+$'),
    nombre  TEXT NOT NULL,
    tipo    TEXT NOT NULL CHECK (tipo IN ('api','rss','scraping'))
);

CREATE TABLE vulnerabilidades (
    cve             TEXT PRIMARY KEY CHECK (cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    descripcion     TEXT,
    publicado_en    TIMESTAMPTZ,
    modificado_en   TIMESTAMPTZ,
    normalizado_en  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vulnerabilidad_cwe (
    cve     TEXT NOT NULL REFERENCES vulnerabilidades(cve) ON DELETE CASCADE,
    cwe     TEXT NOT NULL CHECK (cwe ~ '^(CWE-[0-9]+|NVD-CWE-(Other|noinfo))$'),
    PRIMARY KEY (cve, cwe)
);

CREATE TABLE cvss_metricas (
    cve             TEXT NOT NULL REFERENCES vulnerabilidades(cve) ON DELETE CASCADE,
    fuente          TEXT NOT NULL REFERENCES fuentes(codigo),
    version         TEXT NOT NULL CHECK (version IN ('2.0','3.0','3.1','4.0')),
    vector          TEXT NOT NULL,
    puntaje_base    NUMERIC(3,1) NOT NULL CHECK (puntaje_base BETWEEN 0 AND 10),
    PRIMARY KEY (cve, fuente, version)
);

CREATE TABLE kev_entradas (
    cve             TEXT PRIMARY KEY REFERENCES vulnerabilidades(cve) ON DELETE CASCADE,
    agregado_en     DATE NOT NULL,
    fecha_limite    DATE,
    uso_ransomware  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE epss_vigente (
    cve         TEXT PRIMARY KEY REFERENCES vulnerabilidades(cve) ON DELETE CASCADE,
    puntaje     NUMERIC(6,5) NOT NULL CHECK (puntaje   BETWEEN 0 AND 1),
    percentil   NUMERIC(6,5) NOT NULL CHECK (percentil BETWEEN 0 AND 1),
    fecha       DATE NOT NULL
);

CREATE TABLE vulnerabilidad_rangos (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve                 TEXT NOT NULL REFERENCES vulnerabilidades(cve) ON DELETE CASCADE,
    fuente              TEXT NOT NULL REFERENCES fuentes(codigo),
    producto_tenant_id  UUID NOT NULL DEFAULT catalogo_global() CHECK (producto_tenant_id = catalogo_global()),
    producto_id         UUID NOT NULL,
    version_exacta      TEXT,
    version_desde       TEXT,
    desde_incluye       BOOLEAN NOT NULL DEFAULT TRUE,
    version_hasta       TEXT,
    hasta_incluye       BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (producto_tenant_id, producto_id) REFERENCES productos (tenant_id, id),
    CHECK (version_exacta IS NULL OR (version_desde IS NULL AND version_hasta IS NULL))
);
CREATE UNIQUE INDEX uq_rango ON vulnerabilidad_rangos
    (cve, fuente, producto_id, coalesce(version_exacta,''), coalesce(version_desde,''),
     coalesce(version_hasta,''), desde_incluye, hasta_incluye);
CREATE INDEX idx_rango_producto ON vulnerabilidad_rangos (producto_id);

-- ---------------------------------------------------------------------
-- 5. ORQUESTACION Y PROCEDENCIA (Step Functions + Bedrock AgentCore)
-- ---------------------------------------------------------------------
CREATE TABLE corridas (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tipo                TEXT NOT NULL CHECK (tipo IN ('semanal_completa','diaria_kev_criticos')),
    sfn_ejecucion_arn   TEXT NOT NULL UNIQUE CHECK (sfn_ejecucion_arn LIKE 'arn:aws:states:%'),
    s3_clave            TEXT NOT NULL,
    s3_version_id       TEXT NOT NULL,
    s3_sha256           TEXT NOT NULL CHECK (s3_sha256 ~ '^[0-9a-f]{64}$'),
    iniciada_en         TIMESTAMPTZ NOT NULL,
    finalizada_en       TIMESTAMPTZ,
    resultado           TEXT CHECK (resultado IN ('exito','parcial','fallo')),
    CHECK ((finalizada_en IS NULL) = (resultado IS NULL)),
    CHECK (finalizada_en IS NULL OR finalizada_en >= iniciada_en)
);

CREATE TABLE configuraciones_agente (
    id                  SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agente              TEXT NOT NULL CHECK (agente IN ('priorizacion','notificacion')),
    modelo_id           TEXT NOT NULL,
    prompt_sha256       TEXT NOT NULL CHECK (prompt_sha256 ~ '^[0-9a-f]{64}$'),
    guardrail_id        TEXT NOT NULL,
    guardrail_version   TEXT NOT NULL,
    registrada_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (agente, modelo_id, prompt_sha256, guardrail_id, guardrail_version)
);

CREATE TABLE ejecuciones_agente (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES organizaciones(id),
    corrida_id          UUID NOT NULL REFERENCES corridas(id),
    configuracion_id    SMALLINT NOT NULL REFERENCES configuraciones_agente(id),
    entrada_sha256      TEXT NOT NULL CHECK (entrada_sha256 ~ '^[0-9a-f]{64}$'),
    iniciada_en         TIMESTAMPTZ NOT NULL,
    finalizada_en       TIMESTAMPTZ NOT NULL,
    resultado           TEXT NOT NULL CHECK (resultado IN ('exito','parcial','fallo')),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    CHECK (finalizada_en >= iniciada_en)
);

-- ---------------------------------------------------------------------
-- 6. HALLAZGOS, EVALUACIONES Y APROBACIONES
-- ---------------------------------------------------------------------
CREATE TABLE niveles_prioridad (
    nivel   SMALLINT PRIMARY KEY CHECK (nivel BETWEEN 1 AND 4),   -- 1 = critica
    nombre  TEXT NOT NULL UNIQUE
);

CREATE TABLE politicas_sla (
    tenant_id   UUID NOT NULL REFERENCES organizaciones(id),
    nivel       SMALLINT NOT NULL REFERENCES niveles_prioridad(nivel),
    dias        SMALLINT NOT NULL CHECK (dias BETWEEN 1 AND 365),
    PRIMARY KEY (tenant_id, nivel)
);

CREATE TABLE estados_hallazgo (
    codigo      TEXT PRIMARY KEY,
    es_cerrado  BOOLEAN NOT NULL
);

CREATE TABLE transiciones_estado (
    desde                   TEXT NOT NULL REFERENCES estados_hallazgo(codigo),
    hacia                   TEXT NOT NULL REFERENCES estados_hallazgo(codigo),
    actor                   TEXT NOT NULL CHECK (actor IN ('dueno','sistema')),
    requiere_justificacion  BOOLEAN NOT NULL DEFAULT FALSE,
    requiere_vencimiento    BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (desde, hacia),
    CHECK (desde <> hacia)
);

CREATE TABLE hallazgos (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    componente_id       UUID NOT NULL,
    cve                 TEXT NOT NULL REFERENCES vulnerabilidades(cve),
    metodo_deteccion    TEXT NOT NULL CHECK (metodo_deteccion IN ('cruce_exacto','cruce_ambiguo_agente')),
    estado              TEXT NOT NULL DEFAULT 'pendiente_aprobacion_dueno'
                            REFERENCES estados_hallazgo(codigo),
    detectado_en        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, componente_id) REFERENCES componentes (tenant_id, id)
);
CREATE UNIQUE INDEX uq_hallazgo_abierto ON hallazgos (tenant_id, componente_id, cve)
    WHERE estado NOT IN ('remediado','falso_positivo','riesgo_aceptado');
CREATE INDEX idx_hallazgos_estado ON hallazgos (tenant_id, estado);
CREATE INDEX idx_hallazgos_cve    ON hallazgos (cve);

CREATE TABLE evaluaciones (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    hallazgo_id     UUID NOT NULL,
    corrida_id      UUID NOT NULL REFERENCES corridas(id),
    ejecucion_id    UUID,
    puntaje_riesgo  NUMERIC(5,2) NOT NULL CHECK (puntaje_riesgo BETWEEN 0 AND 100),
    prioridad_base  SMALLINT NOT NULL REFERENCES niveles_prioridad(nivel),
    prioridad_piso  SMALLINT REFERENCES niveles_prioridad(nivel),
    prioridad_final SMALLINT NOT NULL REFERENCES niveles_prioridad(nivel),
    confianza       NUMERIC(3,2) CHECK (confianza BETWEEN 0 AND 1),
    evaluado_en     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, hallazgo_id)  REFERENCES hallazgos          (tenant_id, id),
    FOREIGN KEY (tenant_id, ejecucion_id) REFERENCES ejecuciones_agente (tenant_id, id),
    CONSTRAINT ck_piso_no_perforado CHECK (prioridad_piso IS NULL OR prioridad_final <= prioridad_piso),
    CONSTRAINT ck_determinista CHECK (ejecucion_id IS NOT NULL OR
        (confianza IS NULL AND prioridad_final = LEAST(prioridad_base, coalesce(prioridad_piso, prioridad_base))))
);
CREATE INDEX idx_eval_vigente ON evaluaciones (tenant_id, hallazgo_id, evaluado_en DESC, id DESC);

CREATE TABLE evaluacion_senales (
    tenant_id       UUID NOT NULL,
    evaluacion_id   BIGINT NOT NULL,
    tipo            TEXT NOT NULL CHECK (tipo IN ('motivo_revision','senal_seguridad')),
    codigo          TEXT NOT NULL CHECK (codigo ~ '^[a-z0-9_]{3,60}$'),
    PRIMARY KEY (evaluacion_id, tipo, codigo),
    FOREIGN KEY (tenant_id, evaluacion_id) REFERENCES evaluaciones (tenant_id, id)
);

CREATE TABLE decisiones (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    hallazgo_id     UUID NOT NULL,
    estado_nuevo    TEXT NOT NULL REFERENCES estados_hallazgo(codigo),
    usuario_id      UUID,           -- persona (lo fija el trigger desde la sesion)
    servicio        TEXT,           -- o servicio (lo fija el trigger: session_user)
    justificacion   TEXT,
    vence_en        DATE,           -- obligatorio para falso positivo y riesgo aceptado
    decidido_en     TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, hallazgo_id) REFERENCES hallazgos (tenant_id, id),
    FOREIGN KEY (tenant_id, usuario_id)  REFERENCES usuarios  (tenant_id, id),
    CHECK (num_nonnulls(usuario_id, servicio) = 1)
);
CREATE INDEX idx_decisiones_hallazgo ON decisiones (tenant_id, hallazgo_id, decidido_en DESC, id DESC);

CREATE OR REPLACE FUNCTION aplicar_decision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_estado    TEXT;
    v_dueno     UUID;
    v_t         transiciones_estado%ROWTYPE;
BEGIN
    IF pg_has_role(session_user, 'ti_dashboard', 'MEMBER') THEN
        NEW.usuario_id := nullif(current_setting('app.usuario_id', true), '')::uuid;
        NEW.servicio   := NULL;
        IF NEW.usuario_id IS NULL THEN
            RAISE EXCEPTION 'Sesión sin usuario autenticado (app.usuario_id)';
        END IF;
    ELSE
        NEW.usuario_id := NULL;
        NEW.servicio   := session_user;
    END IF;

    SELECT h.estado, a.dueno_id INTO v_estado, v_dueno
      FROM hallazgos h
      JOIN componentes c ON c.tenant_id = h.tenant_id AND c.id = h.componente_id
      JOIN despliegues d ON d.tenant_id = c.tenant_id AND d.id = c.despliegue_id
      JOIN activos     a ON a.tenant_id = d.tenant_id AND a.id = d.activo_id
     WHERE h.tenant_id = NEW.tenant_id AND h.id = NEW.hallazgo_id
       FOR UPDATE OF h;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Hallazgo % inexistente en la organización', NEW.hallazgo_id;
    END IF;

    SELECT * INTO v_t FROM transiciones_estado
     WHERE desde = v_estado AND hacia = NEW.estado_nuevo;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transición % -> % no permitida', v_estado, NEW.estado_nuevo;
    END IF;

    IF v_t.actor = 'dueno' AND NEW.usuario_id IS DISTINCT FROM v_dueno THEN
        RAISE EXCEPTION 'Solo el dueño del activo puede aplicar % -> %', v_estado, NEW.estado_nuevo;
    END IF;
    IF v_t.actor = 'sistema' AND NEW.servicio IS NULL THEN
        RAISE EXCEPTION 'La transición % -> % solo la ejecuta el sistema', v_estado, NEW.estado_nuevo;
    END IF;
    IF v_t.requiere_justificacion AND length(btrim(coalesce(NEW.justificacion, ''))) < 20 THEN
        RAISE EXCEPTION 'La transición a % exige justificación (mín. 20 caracteres)', NEW.estado_nuevo;
    END IF;
    IF v_t.requiere_vencimiento THEN
        IF NEW.vence_en IS NULL OR NEW.vence_en <= current_date
           OR NEW.vence_en > current_date + 365 THEN
            RAISE EXCEPTION 'La transición a % exige vencimiento entre mañana y 365 días', NEW.estado_nuevo;
        END IF;
    ELSE
        NEW.vence_en := NULL;
    END IF;

    NEW.decidido_en := now();
    UPDATE hallazgos SET estado = NEW.estado_nuevo
     WHERE tenant_id = NEW.tenant_id AND id = NEW.hallazgo_id;
    RETURN NEW;
END $$;

-- ---------------------------------------------------------------------
-- 7. REMEDIACION Y NOTIFICACION
-- ---------------------------------------------------------------------
CREATE TABLE planes_remediacion (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    hallazgo_id     UUID NOT NULL,
    version         SMALLINT NOT NULL CHECK (version >= 1),
    ejecucion_id    UUID,
    autor_id        UUID,
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, hallazgo_id, id),
    UNIQUE (tenant_id, hallazgo_id, version),
    FOREIGN KEY (tenant_id, hallazgo_id)  REFERENCES hallazgos          (tenant_id, id),
    FOREIGN KEY (tenant_id, ejecucion_id) REFERENCES ejecuciones_agente (tenant_id, id),
    FOREIGN KEY (tenant_id, autor_id)     REFERENCES usuarios           (tenant_id, id),
    CHECK (num_nonnulls(ejecucion_id, autor_id) = 1)
);

CREATE TABLE plan_pasos (
    tenant_id   UUID NOT NULL,
    plan_id     UUID NOT NULL,
    orden       SMALLINT NOT NULL CHECK (orden BETWEEN 1 AND 50),
    descripcion TEXT NOT NULL CHECK (length(descripcion) BETWEEN 5 AND 2000),
    PRIMARY KEY (plan_id, orden),
    FOREIGN KEY (tenant_id, plan_id) REFERENCES planes_remediacion (tenant_id, id)
);

CREATE TABLE notificaciones (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    hallazgo_id         UUID NOT NULL,
    plan_id             UUID,
    motivo              TEXT NOT NULL CHECK (motivo IN
                            ('nuevo_hallazgo','plan_propuesto','sla_por_vencer','sla_vencido','reapertura')),
    canal_clave         TEXT NOT NULL,
    slack_canal_id      TEXT NOT NULL CHECK (slack_canal_id ~ '^[CG][A-Z0-9]{8,}$'),
    clave_idempotencia  TEXT NOT NULL,
    estado              TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','enviada','fallida')),
    intentos            SMALLINT NOT NULL DEFAULT 0 CHECK (intentos BETWEEN 0 AND 10),
    slack_ts            TEXT,
    error               TEXT,
    creado_en           TIMESTAMPTZ NOT NULL DEFAULT now(),
    enviado_en          TIMESTAMPTZ,
    UNIQUE (tenant_id, clave_idempotencia),
    FOREIGN KEY (tenant_id, hallazgo_id)          REFERENCES hallazgos          (tenant_id, id),
    FOREIGN KEY (tenant_id, hallazgo_id, plan_id) REFERENCES planes_remediacion (tenant_id, hallazgo_id, id),
    CHECK ((estado = 'enviada') = (enviado_en IS NOT NULL AND slack_ts IS NOT NULL))
);
CREATE INDEX idx_notif_pendientes ON notificaciones (creado_en) WHERE estado = 'pendiente';

-- ---------------------------------------------------------------------
-- 8. DATOS SEMILLA (catalogos cerrados)
-- ---------------------------------------------------------------------
INSERT INTO organizaciones (id, slug, nombre)
VALUES (catalogo_global(), 'catalogo-global', 'Catálogo global (datos públicos)');

INSERT INTO fuentes (codigo, nombre, tipo) VALUES
    ('nvd','NIST NVD','api'), ('osv','OSV.dev','api'), ('ghsa','GitHub Advisories','api'),
    ('kev','CISA KEV','api'), ('epss','FIRST EPSS','api'),
    ('rss_cert','Boletines CERT / fabricantes','rss'), ('scraping','Sitios de avisos','scraping');

INSERT INTO niveles_prioridad VALUES (1,'critica'),(2,'alta'),(3,'media'),(4,'baja');

-- [CAMBIO 2] Organizacion del prototipo y plazos de atencion (SLA) por prioridad.
-- Los dias son supuestos del equipo: ajustarlos a lo que acuerden con el socio formador.
INSERT INTO organizaciones (id, slug, nombre)
VALUES ('11111111-1111-1111-1111-111111111111', 'lyft', 'Lyft (prototipo)');
INSERT INTO politicas_sla (tenant_id, nivel, dias) VALUES
    ('11111111-1111-1111-1111-111111111111', 1, 7),
    ('11111111-1111-1111-1111-111111111111', 2, 30),
    ('11111111-1111-1111-1111-111111111111', 3, 90),
    ('11111111-1111-1111-1111-111111111111', 4, 180);

INSERT INTO estados_hallazgo VALUES
    ('pendiente_aprobacion_dueno', FALSE), ('confirmado', FALSE), ('en_remediacion', FALSE),
    ('remediado', TRUE), ('falso_positivo', TRUE), ('riesgo_aceptado', TRUE);

INSERT INTO transiciones_estado (desde, hacia, actor, requiere_justificacion, requiere_vencimiento) VALUES
    ('pendiente_aprobacion_dueno','confirmado',      'dueno',   FALSE, FALSE),
    ('pendiente_aprobacion_dueno','falso_positivo',  'dueno',   TRUE,  TRUE ),
    ('pendiente_aprobacion_dueno','riesgo_aceptado', 'dueno',   TRUE,  TRUE ),
    ('confirmado',                'en_remediacion',  'dueno',   FALSE, FALSE),
    ('confirmado',                'riesgo_aceptado', 'dueno',   TRUE,  TRUE ),
    ('en_remediacion',            'remediado',       'dueno',   FALSE, FALSE),
    ('en_remediacion',            'confirmado',      'dueno',   TRUE,  FALSE),
    ('remediado',                 'pendiente_aprobacion_dueno','sistema', FALSE, FALSE),
    ('falso_positivo',            'pendiente_aprobacion_dueno','sistema', FALSE, FALSE),
    ('riesgo_aceptado',           'pendiente_aprobacion_dueno','sistema', FALSE, FALSE);

-- ---------------------------------------------------------------------
-- 9. VISTAS (los datos derivados se calculan, no se almacenan)
-- ---------------------------------------------------------------------
CREATE VIEW v_hallazgos_tablero WITH (security_invoker = true) AS
SELECT h.tenant_id, h.id AS hallazgo_id, h.cve, h.estado, e.es_cerrado, h.detectado_en,
       a.id AS activo_id, a.codigo AS activo_codigo, a.nombre AS activo, a.criticidad,
       a.dominio_negocio, a.dueno_id,
       d.id AS despliegue_id, d.ambiente, d.expuesto_internet,
       p.vendor, p.nombre AS producto, c.version,
       ev.prioridad_final, ev.puntaje_riesgo, ev.evaluado_en,
       EXISTS (SELECT 1 FROM evaluacion_senales s
                WHERE s.evaluacion_id = ev.id AND s.tipo = 'motivo_revision') AS requiere_revision_humana,
       (k.cve IS NOT NULL) AS en_kev,
       ep.puntaje AS epss,
       LEAST((h.detectado_en::date + sla.dias), k.fecha_limite) AS fecha_limite
  FROM hallazgos h
  JOIN estados_hallazgo e ON e.codigo = h.estado
  JOIN componentes c ON c.tenant_id = h.tenant_id AND c.id = h.componente_id
  JOIN productos   p ON p.tenant_id = c.producto_tenant_id AND p.id = c.producto_id
  JOIN despliegues d ON d.tenant_id = c.tenant_id AND d.id = c.despliegue_id
  JOIN activos     a ON a.tenant_id = d.tenant_id AND a.id = d.activo_id
  LEFT JOIN LATERAL (
        SELECT x.* FROM evaluaciones x
         WHERE x.tenant_id = h.tenant_id AND x.hallazgo_id = h.id
         ORDER BY x.evaluado_en DESC, x.id DESC LIMIT 1) ev ON TRUE
  LEFT JOIN kev_entradas  k   ON k.cve = h.cve
  LEFT JOIN epss_vigente  ep  ON ep.cve = h.cve
  LEFT JOIN politicas_sla sla ON sla.tenant_id = h.tenant_id AND sla.nivel = ev.prioridad_final;

CREATE VIEW v_exclusiones_vigentes WITH (security_invoker = true) AS
SELECT h.tenant_id, h.componente_id, h.cve, h.estado, ult.vence_en
  FROM hallazgos h
  JOIN LATERAL (
        SELECT dd.vence_en FROM decisiones dd
         WHERE dd.tenant_id = h.tenant_id AND dd.hallazgo_id = h.id
         ORDER BY dd.decidido_en DESC, dd.id DESC LIMIT 1) ult ON TRUE
 WHERE h.estado IN ('falso_positivo','riesgo_aceptado')
   AND ult.vence_en >= current_date;

CREATE VIEW v_decisiones_historial WITH (security_invoker = true) AS
SELECT d.*, coalesce(lag(d.estado_nuevo) OVER w, 'pendiente_aprobacion_dueno') AS estado_anterior
  FROM decisiones d
WINDOW w AS (PARTITION BY d.tenant_id, d.hallazgo_id ORDER BY d.decidido_en, d.id);

CREATE VIEW v_activos_recertificacion WITH (security_invoker = true) AS
SELECT a.tenant_id, a.id AS activo_id, a.codigo, a.dueno_id, r.ultima,
       (r.ultima IS NULL OR r.ultima < now() - interval '90 days') AS desactualizado
  FROM activos a
  LEFT JOIN LATERAL (SELECT max(x.recertificado_en) AS ultima FROM recertificaciones x
                      WHERE x.tenant_id = a.tenant_id AND x.activo_id = a.id) r ON TRUE
 WHERE a.dado_de_baja_en IS NULL;

-- ---------------------------------------------------------------------
-- 10. TRIGGERS
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_activos_upd     BEFORE UPDATE ON activos     FOR EACH ROW EXECUTE FUNCTION tocar_actualizado_en();
CREATE TRIGGER trg_despliegues_upd BEFORE UPDATE ON despliegues FOR EACH ROW EXECUTE FUNCTION tocar_actualizado_en();

CREATE TRIGGER trg_decision_aplicar BEFORE INSERT ON decisiones FOR EACH ROW EXECUTE FUNCTION aplicar_decision();

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['decisiones','evaluaciones','evaluacion_senales','ejecuciones_agente',
                             'recertificaciones','planes_remediacion','plan_pasos'] LOOP
        EXECUTE format('CREATE TRIGGER trg_%s_inmutable BEFORE UPDATE OR DELETE ON %I
                        FOR EACH ROW EXECUTE FUNCTION impedir_modificacion()', t, t);
        EXECUTE format('CREATE TRIGGER trg_%s_truncate BEFORE TRUNCATE ON %I
                        FOR EACH STATEMENT EXECUTE FUNCTION impedir_modificacion()', t, t);
    END LOOP;
END $$;

CREATE OR REPLACE FUNCTION impedir_sombra_identificador() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_id <> catalogo_global() AND EXISTS (
        SELECT 1 FROM producto_identificadores g
         WHERE g.tenant_id = catalogo_global() AND g.esquema = NEW.esquema AND g.valor = NEW.valor) THEN
        RAISE EXCEPTION 'El identificador % ya existe en el catálogo global: use ese producto', NEW.valor;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_identificador_sombra BEFORE INSERT OR UPDATE ON producto_identificadores
    FOR EACH ROW EXECUTE FUNCTION impedir_sombra_identificador();

-- ---------------------------------------------------------------------
-- 11. ROW-LEVEL SECURITY
-- ---------------------------------------------------------------------
ALTER TABLE organizaciones ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizaciones FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_org ON organizaciones FOR SELECT USING (id IN (tenant_actual(), catalogo_global()));

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['usuarios','equipos','activos','despliegues','despliegue_dependencias',
                             'recertificaciones','componentes','politicas_sla','ejecuciones_agente',
                             'hallazgos','evaluaciones','evaluacion_senales','decisiones',
                             'planes_remediacion','plan_pasos','notificaciones'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE  ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY p_tenant ON %I USING (tenant_id = tenant_actual())
                        WITH CHECK (tenant_id = tenant_actual())', t);
    END LOOP;

    FOREACH t IN ARRAY ARRAY['productos','producto_identificadores'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE  ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY p_lectura ON %I FOR SELECT
                        USING (tenant_id IN (tenant_actual(), catalogo_global()))', t);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 12. ROLES DE MINIMO PRIVILEGIO (uno por componente de la arquitectura)
-- ---------------------------------------------------------------------
DO $$
DECLARE r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['ti_ingesta','ti_inventario','ti_cruce','ti_agente_priorizacion',
                             'ti_output_guard','ti_agente_notificacion','ti_notificador',
                             'ti_dashboard'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
END $$;

CREATE POLICY p_escritura_global ON productos FOR ALL TO ti_ingesta
    USING (tenant_id = catalogo_global()) WITH CHECK (tenant_id = catalogo_global());
CREATE POLICY p_escritura_global ON producto_identificadores FOR ALL TO ti_ingesta
    USING (tenant_id = catalogo_global()) WITH CHECK (tenant_id = catalogo_global());
CREATE POLICY p_escritura_tenant ON productos FOR ALL TO ti_inventario
    USING (tenant_id = tenant_actual()) WITH CHECK (tenant_id = tenant_actual());
CREATE POLICY p_escritura_tenant ON producto_identificadores FOR ALL TO ti_inventario
    USING (tenant_id = tenant_actual()) WITH CHECK (tenant_id = tenant_actual());

GRANT SELECT ON fuentes, niveles_prioridad, estados_hallazgo, transiciones_estado TO
    ti_ingesta, ti_inventario, ti_cruce, ti_agente_priorizacion, ti_output_guard,
    ti_agente_notificacion, ti_notificador, ti_dashboard;

GRANT SELECT, INSERT, UPDATE ON vulnerabilidades, vulnerabilidad_cwe, cvss_metricas, kev_entradas,
                                epss_vigente, vulnerabilidad_rangos, productos, producto_identificadores,
                                corridas TO ti_ingesta;
GRANT DELETE ON vulnerabilidad_cwe, cvss_metricas, kev_entradas, vulnerabilidad_rangos TO ti_ingesta;

GRANT SELECT ON vulnerabilidades, vulnerabilidad_cwe, cvss_metricas, kev_entradas, epss_vigente,
                vulnerabilidad_rangos, productos, producto_identificadores, corridas
    TO ti_inventario, ti_cruce, ti_agente_priorizacion, ti_output_guard,
       ti_agente_notificacion, ti_dashboard;

GRANT SELECT, INSERT, UPDATE ON usuarios, equipos, activos, despliegues, despliegue_dependencias,
                                componentes, politicas_sla TO ti_inventario;
GRANT INSERT ON productos, producto_identificadores TO ti_inventario;
GRANT SELECT, INSERT ON recertificaciones TO ti_inventario;
GRANT DELETE ON despliegue_dependencias TO ti_inventario;

GRANT SELECT ON activos, despliegues, componentes, hallazgos, decisiones, evaluaciones,
                v_exclusiones_vigentes TO ti_cruce;
GRANT INSERT (tenant_id, componente_id, cve, metodo_deteccion) ON hallazgos TO ti_cruce;
GRANT INSERT ON evaluaciones TO ti_cruce;
GRANT INSERT (tenant_id, hallazgo_id, estado_nuevo, justificacion) ON decisiones TO ti_cruce;

GRANT SELECT ON activos, despliegues, despliegue_dependencias, componentes, hallazgos, decisiones
    TO ti_agente_priorizacion;

GRANT SELECT ON activos, despliegues, componentes, hallazgos, configuraciones_agente TO ti_output_guard;
GRANT INSERT (tenant_id, componente_id, cve, metodo_deteccion) ON hallazgos TO ti_output_guard;
GRANT INSERT ON ejecuciones_agente, evaluaciones, evaluacion_senales TO ti_output_guard;

GRANT SELECT ON activos, despliegues, componentes, hallazgos, evaluaciones, decisiones,
                v_hallazgos_tablero TO ti_agente_notificacion;
-- [CAMBIO 1] v_hallazgos_tablero es security_invoker: quien la consulta necesita permiso
-- sobre TODAS las tablas que usa.
GRANT SELECT ON evaluacion_senales, politicas_sla TO ti_agente_notificacion;

GRANT SELECT ON hallazgos, planes_remediacion, configuraciones_agente, v_hallazgos_tablero,
                activos, despliegues, componentes, productos, evaluaciones, evaluacion_senales,
                kev_entradas, epss_vigente, politicas_sla TO ti_notificador;
GRANT INSERT ON ejecuciones_agente, planes_remediacion, plan_pasos TO ti_notificador;
GRANT SELECT, INSERT ON notificaciones TO ti_notificador;
GRANT UPDATE (estado, intentos, slack_ts, error, enviado_en) ON notificaciones TO ti_notificador;

GRANT SELECT ON organizaciones, usuarios, equipos, activos, despliegues, despliegue_dependencias,
                recertificaciones, componentes, politicas_sla, ejecuciones_agente, configuraciones_agente,
                hallazgos, evaluaciones, evaluacion_senales, decisiones, planes_remediacion, plan_pasos,
                notificaciones, v_hallazgos_tablero, v_exclusiones_vigentes, v_decisiones_historial,
                v_activos_recertificacion TO ti_dashboard;
GRANT INSERT (tenant_id, hallazgo_id, estado_nuevo, justificacion, vence_en) ON decisiones TO ti_dashboard;

COMMIT;
