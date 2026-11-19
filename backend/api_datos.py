"""
API de datos del panel (Lambda dentro de la red de la base). Solo lee, con el usuario u_dashboard y seguridad por fila.
Tambien guarda la foto diaria de numeros (tabla metricas_diarias) cuando Step Functions la invoca con {"accion": "snapshot"}.

Rutas (API Gateway HTTP, con Cognito delante):
  GET /api/resumen            numeros de las tarjetas, distribucion por prioridad y cambio contra hace 7 dias
  GET /api/tendencia?dias=30  serie diaria por prioridad (desde metricas_diarias)
  GET /api/hallazgos?limite=8 hallazgos abiertos ordenados por prioridad
  GET /api/recursos           recursos de AWS sin registrar (?estado=sin_registrar|registrado)
  GET /api/cobertura          cobertura del CMDB por tipo de recurso
  GET /api/por-criticidad     hallazgos abiertos por criticidad del activo
  GET /api/ambiguos           casos que el cruce determinista no pudo decidir (aun no se guardan)
"""
import datetime
import decimal
import json
import os
import uuid

import lti_db

TENANT = os.environ.get("TENANT_ID", lti_db.TENANT_LYFT)


class _Args:
    pass


def _con():
    a = _Args()
    a.host, a.port, a.db = os.environ["DB_HOST"], 5432, "lti"
    a.user, a.password, a.sin_ssl = "u_dashboard", os.environ["DB_PASSWORD"], bool(os.environ.get("LTI_SIN_SSL"))
    return lti_db.conectar(a, TENANT)


def _q(con, sql, **p):
    filas = con.run(sql, **p)
    cols = [c["name"] for c in (con.columns or [])]
    return [dict(zip(cols, f)) for f in filas]


def _json(o):
    if isinstance(o, decimal.Decimal):
        return float(o)
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    if isinstance(o, uuid.UUID):
        return str(o)
    raise TypeError(type(o))


def _resp(codigo, cuerpo):
    return {"statusCode": codigo, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(cuerpo, default=_json)}


def _entero(valor, defecto, minimo, maximo):
    try:
        return max(minimo, min(maximo, int(valor)))
    except (TypeError, ValueError):
        return defecto


def calcular(con):
    """Numeros de hoy, tal como estan ahora en la base."""
    h = _q(con, """
        SELECT count(*) FILTER (WHERE prioridad_final = 1)                          AS criticas,
               count(*) FILTER (WHERE prioridad_final = 2)                          AS altas,
               count(*) FILTER (WHERE prioridad_final = 3)                          AS medias,
               count(*) FILTER (WHERE prioridad_final = 4 OR prioridad_final IS NULL) AS bajas,
               count(*) FILTER (WHERE en_kev)                                       AS kev,
               count(*) FILTER (WHERE epss >= 0.5)                                  AS epss_alto,
               count(*) FILTER (WHERE fecha_limite <= current_date + 2)             AS sla_por_vencer
          FROM v_lista_oficial WHERE NOT es_cerrado AND NOT no_aplica AND (NOT agente_activo OR evaluado_por_agente)""")[0]
    h["activos_expuestos"] = con.run(
        "SELECT count(DISTINCT activo_id) FROM despliegues WHERE expuesto_internet AND dado_de_baja_en IS NULL")[0][0]
    h["activos_total"] = con.run("SELECT count(*) FROM activos WHERE dado_de_baja_en IS NULL")[0][0]
    h["sin_registrar"] = con.run(
        "SELECT count(*) FROM recursos_descubiertos WHERE estado = 'sin_registrar' AND desaparecido_en IS NULL")[0][0]
    return h


def snapshot(con):
    m = calcular(con)
    con.run("""
        INSERT INTO metricas_diarias (tenant_id, dia, criticas, altas, medias, bajas, kev, epss_alto, sla_por_vencer,
                                      activos_expuestos, activos_total, sin_registrar)
        VALUES (:t, current_date, :criticas, :altas, :medias, :bajas, :kev, :epss_alto, :sla_por_vencer,
                :activos_expuestos, :activos_total, :sin_registrar)
        ON CONFLICT (tenant_id, dia) DO UPDATE SET
            criticas = EXCLUDED.criticas, altas = EXCLUDED.altas, medias = EXCLUDED.medias, bajas = EXCLUDED.bajas,
            kev = EXCLUDED.kev, epss_alto = EXCLUDED.epss_alto, sla_por_vencer = EXCLUDED.sla_por_vencer,
            activos_expuestos = EXCLUDED.activos_expuestos, activos_total = EXCLUDED.activos_total,
            sin_registrar = EXCLUDED.sin_registrar, calculado_en = now()""", t=TENANT, **m)
    return m


def resumen(con, _p):
    hoy = calcular(con)
    antes = _q(con, "SELECT * FROM metricas_diarias WHERE dia <= current_date - 7 ORDER BY dia DESC LIMIT 1")
    if not antes:   # aun no hay una semana de historia: se compara contra la foto mas vieja que no sea de hoy
        antes = _q(con, "SELECT * FROM metricas_diarias WHERE dia < current_date ORDER BY dia ASC LIMIT 1")
    prev = antes[0] if antes else None
    cambio = {k: (hoy[k] - prev[k] if prev else None)
              for k in ("criticas", "kev", "epss_alto", "activos_expuestos", "sin_registrar", "sla_por_vencer")}
    ag = _q(con, """SELECT coalesce(bool_or(agente_activo), false) AS activo,
                      count(*) FILTER (WHERE NOT es_cerrado AND agente_activo AND NOT evaluado_por_agente) AS pendientes,
                      count(*) FILTER (WHERE NOT es_cerrado AND no_aplica) AS no_aplican
                 FROM v_lista_oficial""")[0]
    return {"agente": ag, "hoy": hoy, "cambio": cambio, "comparado_con": prev["dia"] if prev else None,
            "serie_corta": _q(con, "SELECT dia, criticas, kev, epss_alto, activos_expuestos, sin_registrar, sla_por_vencer "
                                   "FROM metricas_diarias ORDER BY dia DESC LIMIT 14")[::-1]}


def tendencia(con, p):
    d = _entero(p.get("dias"), 30, 1, 365)
    return {"dias": d, "puntos": _q(con, "SELECT dia, criticas, altas, medias, bajas FROM metricas_diarias "
                                         "WHERE dia >= current_date - CAST(:d AS integer) ORDER BY dia", d=d)}


def hallazgos(con, p):
    n = _entero(p.get("limite"), 8, 1, 100)
    return {"items": _q(con, """
        SELECT v.hallazgo_id AS id, v.cve, v.activo_codigo, v.activo, v.criticidad, v.ambiente, v.expuesto_internet,
               v.estado, v.prioridad_final, v.puntaje_riesgo, v.en_kev, v.epss, v.fecha_limite,
               v.requiere_revision_humana, v.evaluado_por_agente, v.no_aplica,
               (v.agente_activo AND NOT v.evaluado_por_agente) AS pendiente_agente,
               (SELECT max(c.puntaje_base) FROM cvss_metricas c WHERE c.cve = v.cve) AS cvss
          FROM v_lista_oficial v
         WHERE NOT v.es_cerrado
         ORDER BY v.prioridad_final NULLS LAST, v.puntaje_riesgo DESC NULLS LAST, v.en_kev DESC, v.detectado_en DESC
         LIMIT CAST(:n AS integer)""", n=n)}


def recursos(con, p):
    est = p.get("estado", "sin_registrar")
    if est not in ("sin_registrar", "registrado", "ignorado"):
        est = "sin_registrar"
    return {"items": _q(con, """
        SELECT tipo, nombre, region, etiqueta_activo, estado, primera_vez, ultima_vez
          FROM recursos_descubiertos
         WHERE estado = :e AND desaparecido_en IS NULL
         ORDER BY primera_vez DESC LIMIT 100""", e=est)}


def cobertura(con, _p):
    return {"items": _q(con, """
        SELECT tipo, count(*) AS total,
               count(*) FILTER (WHERE estado = 'registrado')    AS registrados,
               count(*) FILTER (WHERE estado = 'sin_registrar') AS sin_registrar
          FROM recursos_descubiertos
         WHERE desaparecido_en IS NULL AND estado <> 'ignorado'
         GROUP BY tipo ORDER BY tipo""")}


def por_criticidad(con, _p):
    return {"items": _q(con, "SELECT criticidad, count(*) AS total FROM v_lista_oficial "
                             "WHERE NOT es_cerrado AND NOT no_aplica AND (NOT agente_activo OR evaluado_por_agente) GROUP BY criticidad ORDER BY criticidad DESC")}


def ambiguos(_con, _p):
    return {"items": [], "nota": "El cruce todavia no guarda los casos ambiguos; los recibira el agente."}


RUTAS = {"resumen": resumen, "tendencia": tendencia, "hallazgos": hallazgos, "recursos": recursos,
         "cobertura": cobertura, "por-criticidad": por_criticidad, "ambiguos": ambiguos}


NIVEL = {"critica": 1, "alta": 2, "media": 3, "baja": 4}
NOMBRE = {1: "CRITICA", 2: "ALTA", 3: "MEDIA", 4: "BAJA"}


def alerta(con, cfg):
    """Arma el mensaje de Slack con los hallazgos abiertos que aun no se avisaron y que superan los umbrales."""
    cfg = cfg or {}
    if not cfg.get("slack"):
        return {"enviar": False, "motivo": "slack_desactivado"}
    nivel = NIVEL.get(cfg.get("minPrio"), 4)
    epss = float(cfg.get("epss", 0.5))
    filas = _q(con, """
        SELECT v.hallazgo_id AS id, v.cve, v.activo_codigo, v.expuesto_internet, v.prioridad_final, v.en_kev, v.epss,
               (SELECT max(c.puntaje_base) FROM cvss_metricas c WHERE c.cve = v.cve) AS cvss
          FROM v_lista_oficial v
         WHERE NOT v.es_cerrado AND NOT v.no_aplica AND (NOT v.agente_activo OR v.evaluado_por_agente)
           AND NOT EXISTS (SELECT 1 FROM alertas_enviadas a WHERE a.hallazgo_id = v.hallazgo_id)
           AND (coalesce(v.prioridad_final, 4) <= CAST(:nivel AS integer) OR v.epss >= CAST(:epss AS numeric))
           AND (NOT CAST(:kev AS boolean) OR v.en_kev)
         ORDER BY v.prioridad_final NULLS LAST, v.puntaje_riesgo DESC NULLS LAST, v.epss DESC NULLS LAST, v.cve
         LIMIT 500""", nivel=nivel, epss=epss, kev=bool(cfg.get("soloKev")))
    if not filas:
        return {"enviar": False, "motivo": "sin_nuevos"}
    n = len(filas)
    cuenta = {k: sum(1 for f in filas if f["prioridad_final"] == k) for k in (1, 2, 3, 4)}
    partes = [f"{cuenta[k]} {s if cuenta[k] == 1 else pl}" for k, s, pl in
              ((1, "critico", "criticos"), (2, "alto", "altos"), (3, "medio", "medios"), (4, "bajo", "bajos")) if cuenta[k]]
    titulo = f"Lyft TI: {n} hallazgo{'s' if n != 1 else ''} nuevo{'s' if n != 1 else ''}" + (f" ({', '.join(partes)})" if partes else "")
    lineas = []
    for f in filas[:10]:
        det = [f"CVSS {f['cvss']:.1f}".replace(".", ",")] if f["cvss"] is not None else []
        if f["epss"] is not None:
            det.append(f"EPSS {float(f['epss']):.2f}".replace(".", ","))
        if f["en_kev"]:
            det.append("KEV")
        if f["expuesto_internet"]:
            det.append("expuesto a internet")
        lineas.append(f"- {NOMBRE.get(f['prioridad_final'], 'SIN EVALUAR')} {f['cve']} en {f['activo_codigo']}"
                      + (f" ({', '.join(det)})" if det else ""))
    if n > 10:
        lineas.append(f"... y {n - 10} mas. Revisa el panel de Threat Intelligence.")
    return {"enviar": True, "title": titulo[:150], "body": "\n".join(lineas)[:3000], "ids": [str(f["id"]) for f in filas]}


def resumen_diario(con, cfg):
    """Resumen diario: la lista oficial abierta, ordenada por prioridad y riesgo."""
    cfg = cfg or {}
    if not (cfg.get("slack") and cfg.get("resumen")):
        return {"enviar": False, "motivo": "resumen_desactivado"}
    filas = _q(con, """
        SELECT v.cve, v.activo_codigo, v.prioridad_final, v.puntaje_riesgo, v.en_kev, v.epss, v.expuesto_internet
          FROM v_lista_oficial v
         WHERE NOT v.es_cerrado AND NOT v.no_aplica AND (NOT v.agente_activo OR v.evaluado_por_agente)
         ORDER BY v.prioridad_final NULLS LAST, v.puntaje_riesgo DESC NULLS LAST, v.cve LIMIT 500""")
    n = len(filas)
    cuenta = {k: sum(1 for f in filas if (f["prioridad_final"] or 4) == k) for k in (1, 2, 3, 4)}
    titulo = (f"Lyft TI resumen diario: {n} abiertos ({cuenta[1]} criticos, {cuenta[2]} altos, "
              f"{cuenta[3]} medios, {cuenta[4]} bajos)")
    lineas = [f"- {NOMBRE.get(f['prioridad_final'], 'BAJA')} {f['cve']} en {f['activo_codigo']}"
              + (" (KEV)" if f["en_kev"] else "") for f in filas[:10]]
    if n > 10:
        lineas.append(f"... y {n - 10} mas. Revisa el panel de Threat Intelligence.")
    return {"enviar": True, "title": titulo[:150], "body": "\n".join(lineas) or "Sin hallazgos abiertos.", "ids": []}


def marcar(con, ids):
    ids = [i for i in (ids or []) if isinstance(i, str)]
    for i in range(0, len(ids), 100):
        trozo = ids[i:i + 100]
        params = {f"i{k}": v for k, v in enumerate(trozo)}
        marcas = ",".join(f"CAST(:i{k} AS uuid)" for k in range(len(trozo)))
        con.run(f"INSERT INTO alertas_enviadas (tenant_id, hallazgo_id) SELECT CAST(:t AS uuid), x FROM unnest(ARRAY[{marcas}]) AS x "
                f"ON CONFLICT DO NOTHING", t=TENANT, **params)
    return {"marcados": len(ids)}


def handler(event, context):
    con = None
    try:
        con = _con()
        if event.get("accion") == "snapshot":                      # lo llama Step Functions al final del flujo
            m = snapshot(con)
            print("snapshot", m)
            return {"snapshot": m}
        if event.get("accion") == "alerta":                        # lo llama Step Functions
            r = (resumen_diario if event.get("resumen") else alerta)(con, event.get("alertas"))
            print("alerta", {k: v for k, v in r.items() if k not in ("body", "ids")}, "ids", len(r.get("ids", [])))
            return r
        if event.get("accion") == "marcar":
            return marcar(con, event.get("ids"))
        ruta = (event.get("rawPath") or "").split("/api/", 1)[-1].strip("/")
        f = RUTAS.get(ruta)
        if not f:
            return _resp(404, {"error": "ruta desconocida"})
        return _resp(200, f(con, event.get("queryStringParameters") or {}))
    except Exception as e:                                          # el detalle queda en CloudWatch, no en la respuesta
        print("ERROR", repr(e))
        return _resp(500, {"error": "No se pudieron leer los datos"})
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
