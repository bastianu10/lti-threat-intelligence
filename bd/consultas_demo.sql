-- Consultas para las capturas. Ejecutalas conectado como u_dashboard (o u_cruce).
-- PRIMERO, en la misma sesion, elige la organizacion (sin esto la base devuelve 0 filas, a proposito):
SELECT set_config('app.tenant_id', '11111111-1111-1111-1111-111111111111', false);

-- 1. Tablero: hallazgos con su prioridad, KEV, EPSS y fecha limite calculada por SLA
SELECT cve, activo_codigo, producto, version, estado,
       prioridad_final AS prioridad, puntaje_riesgo, en_kev, epss, fecha_limite
  FROM v_hallazgos_tablero
 ORDER BY prioridad_final, cve;

-- 2. Resumen por prioridad y estado
SELECT prioridad_final AS prioridad, estado, count(*) AS hallazgos
  FROM v_hallazgos_tablero
 GROUP BY 1, 2 ORDER BY 1, 2;

-- 3. Que depende de un activo (si este falla, que se cae): ejemplo con el balanceador de Envoy
SELECT a.codigo AS depende, a.nombre AS nombre
  FROM despliegue_dependencias dd
  JOIN despliegues d  ON d.tenant_id = dd.tenant_id AND d.id = dd.depende_de_id
  JOIN activos     ax ON ax.tenant_id = d.tenant_id AND ax.id = d.activo_id
  JOIN despliegues o  ON o.tenant_id = dd.tenant_id AND o.id = dd.despliegue_id
  JOIN activos     a  ON a.tenant_id = o.tenant_id AND a.id = o.activo_id
 WHERE ax.codigo = 'alb-envoy';

-- 4. Contexto de un activo con sus cinco campos (criticidad, clasificacion, exposicion, disponibilidad, dependencias)
SELECT a.codigo, a.criticidad, a.clasificacion_informacion, d.expuesto_internet,
       d.disponibilidad_objetivo, d.rto, d.rpo,
       (SELECT count(*) FROM despliegue_dependencias x WHERE x.despliegue_id = d.id) AS depende_de
  FROM activos a JOIN despliegues d ON d.tenant_id = a.tenant_id AND d.activo_id = a.id
 WHERE a.codigo IN ('auth-oidc', 'aurora-ecobici', 'msk-ecobici');

-- 5. Historial de aprobaciones (quien decidio, cuando y por que)
SELECT hallazgo_id, estado_anterior, estado_nuevo, usuario_id, servicio, justificacion, vence_en, decidido_en
  FROM v_decisiones_historial ORDER BY decidido_en;

-- 6. Exclusiones vigentes (falsos positivos y riesgos aceptados que todavia no vencen)
SELECT * FROM v_exclusiones_vigentes;
