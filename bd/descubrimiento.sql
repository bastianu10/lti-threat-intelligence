-- Descubrimiento: recursos reales de AWS que Cartography encontro, comparados contra el inventario.
-- Un recurso queda 'registrado' si lleva la etiqueta  activo=<codigo>  y ese codigo existe en el inventario.
-- Se aplica DESPUES de esquema.sql y es seguro repetirlo.

BEGIN;

CREATE TABLE IF NOT EXISTS recursos_descubiertos (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id         UUID NOT NULL REFERENCES organizaciones(id),
    arn               TEXT NOT NULL,
    tipo              TEXT NOT NULL CHECK (tipo IN ('lambda','ec2','rds','s3','dynamodb','eks','ecs','elasticache')),
    nombre            TEXT,
    region            TEXT,
    cuenta            TEXT,
    etiqueta_activo   TEXT,                       -- lo que dice la etiqueta, aunque no exista en el inventario
    activo_id         UUID,                       -- el activo del inventario con el que coincidio
    estado            TEXT NOT NULL CHECK (estado IN ('registrado','sin_registrar','ignorado')),
    primera_vez       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ultima_vez        TIMESTAMPTZ NOT NULL DEFAULT now(),
    desaparecido_en   TIMESTAMPTZ,                -- dejo de aparecer en el descubrimiento
    UNIQUE (tenant_id, arn),
    FOREIGN KEY (tenant_id, activo_id) REFERENCES activos (tenant_id, id),
    CHECK (estado <> 'registrado' OR activo_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_recursos_estado ON recursos_descubiertos (tenant_id, estado);

CREATE OR REPLACE VIEW v_recursos_sin_registrar WITH (security_invoker = true) AS
SELECT tenant_id, tipo, nombre, region, arn, etiqueta_activo, primera_vez, ultima_vez
  FROM recursos_descubiertos
 WHERE estado = 'sin_registrar' AND desaparecido_en IS NULL;

ALTER TABLE recursos_descubiertos ENABLE ROW LEVEL SECURITY;
ALTER TABLE recursos_descubiertos FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_tenant ON recursos_descubiertos;
CREATE POLICY p_tenant ON recursos_descubiertos USING (tenant_id = tenant_actual())
    WITH CHECK (tenant_id = tenant_actual());

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ti_descubrimiento') THEN
        CREATE ROLE ti_descubrimiento NOLOGIN;
    END IF;
END $$;

-- La CMDB solo puede leer el inventario y escribir en esta tabla.
GRANT SELECT ON activos TO ti_descubrimiento;
GRANT SELECT, INSERT, UPDATE ON recursos_descubiertos TO ti_descubrimiento;
GRANT SELECT ON recursos_descubiertos, v_recursos_sin_registrar TO ti_dashboard;

COMMIT;
