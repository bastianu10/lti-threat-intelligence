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

-- Lista oficial: lo que sale del agente. Si el agente no ha corrido con exito en los ultimos 3 dias,
-- la lista oficial es la del filtro determinista (el flujo no se queda sin avisar).
GRANT SELECT ON ejecuciones_agente TO ti_dashboard;
CREATE OR REPLACE VIEW v_lista_oficial WITH (security_invoker = true) AS
SELECT v.*,
       (ev.ejecucion_id IS NOT NULL) AS evaluado_por_agente,
       EXISTS (SELECT 1 FROM evaluacion_senales s
                WHERE s.evaluacion_id = ev.id AND s.codigo = 'no_aplica') AS no_aplica,
       EXISTS (SELECT 1 FROM ejecuciones_agente x
                WHERE x.resultado IN ('exito','parcial')
                  AND x.finalizada_en > now() - interval '3 days') AS agente_activo
  FROM v_hallazgos_tablero v
  LEFT JOIN LATERAL (
        SELECT e.id, e.ejecucion_id FROM evaluaciones e
         WHERE e.tenant_id = v.tenant_id AND e.hallazgo_id = v.hallazgo_id
         ORDER BY e.evaluado_en DESC, e.id DESC LIMIT 1) ev ON TRUE;
GRANT SELECT ON v_lista_oficial TO ti_dashboard;
