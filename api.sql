-- Metricas diarias para el tablero (tendencia y cambios contra hace 7 dias) y permisos de lectura que usa la API.
-- Se corre UNA vez con el usuario maestro; es seguro repetirlo.
BEGIN;

CREATE TABLE IF NOT EXISTS metricas_diarias (
    tenant_id          UUID NOT NULL REFERENCES organizaciones(id),
    dia                DATE NOT NULL,
    criticas           INTEGER NOT NULL,
    altas              INTEGER NOT NULL,
    medias             INTEGER NOT NULL,
    bajas              INTEGER NOT NULL,
    kev                INTEGER NOT NULL,
    epss_alto          INTEGER NOT NULL,
    sla_por_vencer     INTEGER NOT NULL,
    activos_expuestos  INTEGER NOT NULL,
    activos_total      INTEGER NOT NULL,
    sin_registrar      INTEGER NOT NULL,
    calculado_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, dia)
);

ALTER TABLE metricas_diarias ENABLE ROW LEVEL SECURITY;
ALTER TABLE metricas_diarias FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_tenant ON metricas_diarias;
CREATE POLICY p_tenant ON metricas_diarias USING (tenant_id = tenant_actual())
    WITH CHECK (tenant_id = tenant_actual());

-- La API lee el catalogo y guarda la foto diaria de numeros (solo en esta tabla).
GRANT SELECT ON cvss_metricas, vulnerabilidades, kev_entradas, epss_vigente TO ti_dashboard;
GRANT SELECT, INSERT, UPDATE ON metricas_diarias TO ti_dashboard;

-- Hallazgos que ya se avisaron por Slack (para no repetir el mismo aviso en cada ejecucion).
CREATE TABLE IF NOT EXISTS alertas_enviadas (
    tenant_id    UUID NOT NULL,
    hallazgo_id  UUID NOT NULL,
    enviado_en   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, hallazgo_id),
    FOREIGN KEY (tenant_id, hallazgo_id) REFERENCES hallazgos (tenant_id, id) ON DELETE CASCADE
);
ALTER TABLE alertas_enviadas ENABLE ROW LEVEL SECURITY;
ALTER TABLE alertas_enviadas FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_tenant ON alertas_enviadas;
CREATE POLICY p_tenant ON alertas_enviadas USING (tenant_id = tenant_actual())
    WITH CHECK (tenant_id = tenant_actual());
GRANT SELECT, INSERT ON alertas_enviadas TO ti_dashboard;

COMMIT;
