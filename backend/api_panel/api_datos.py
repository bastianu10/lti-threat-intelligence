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
ICONO = {1: "🔴", 2: "🟠", 3: "🟡", 4: "🟢"}
ETIQ = {1: "Crítica", 2: "Alta", 3: "Media", 4: "Baja"}
PLURAL = {1: "críticas", 2: "altas", 3: "medias", 4: "bajas"}
SINGULAR = {1: "crítica", 2: "alta", 3: "media", 4: "baja"}
MESES = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")
OFICIAL = "NOT v.es_cerrado AND NOT v.no_aplica AND (NOT v.agente_activo OR v.evaluado_por_agente)"


def _fecha(d):
    return f"{d.day} {MESES[d.month - 1]}" if d else None


def _por_cve(filas):
    """Una entrada por vulnerabilidad, con los sistemas afectados, en orden de urgencia."""
    g = {}
    for f in filas:
        x = g.setdefault(f["cve"], {"cve": f["cve"], "nivel": 4, "riesgo": 0, "cvss": None, "epss": None,
                                    "kev": False, "internet": False, "plazo": None, "activos": []})
        x["nivel"] = min(x["nivel"], f["prioridad_final"] or 4)
        x["riesgo"] = max(x["riesgo"], float(f["puntaje_riesgo"] or 0))
        x["cvss"] = f["cvss"] if x["cvss"] is None else x["cvss"]
        x["epss"] = f["epss"] if x["epss"] is None else x["epss"]
        x["kev"] = x["kev"] or bool(f["en_kev"])
        x["internet"] = x["internet"] or bool(f["expuesto_internet"])
        if f["fecha_limite"] and (x["plazo"] is None or f["fecha_limite"] < x["plazo"]):
            x["plazo"] = f["fecha_limite"]
        if f["activo_codigo"] not in x["activos"]:
            x["activos"].append(f["activo_codigo"])
    return sorted(g.values(), key=lambda x: (x["nivel"], -x["riesgo"], x["cve"]))


def _bloque(x):
    n = len(x["activos"])
    sis = ", ".join(x["activos"][:4]) + (f" y {n - 4} más" if n > 4 else "")
    por_que = []
    if x["kev"]:
        por_que.append("⚠️ Ya la están explotando en ataques reales (lista CISA KEV)")
    if x["internet"]:
        por_que.append("🌐 Es alcanzable desde internet")
    if x["epss"] is not None and float(x["epss"]) >= 0.3:
        por_que.append(f"📈 Probabilidad de ataque en 30 días: {round(float(x['epss']) * 100)}%")
    if x["cvss"] is not None:
        por_que.append(f"Gravedad técnica: {float(x['cvss']):.1f} de 10".replace(".", ","))
    lineas = [f"{ICONO[x['nivel']]} *{x['cve']}* · prioridad {ETIQ[x['nivel']].lower()}",
              f"> *Afecta a {n} sistema{'s' if n != 1 else ''}:* {sis}"]
    lineas += [f"> {t}" for t in por_que]
    if x["plazo"]:
        lineas.append(f"> ⏰ Plazo para corregir: *{_fecha(x['plazo'])}*")
    return "\n".join(lineas)


def _cuenta(filas):
    return {k: sum(1 for f in filas if (f["prioridad_final"] or 4) == k) for k in (1, 2, 3, 4)}


def _semaforo(c):
    return "  ".join(f"{ICONO[k]} {c[k]} {SINGULAR[k] if c[k] == 1 else PLURAL[k]}" for k in (1, 2, 3, 4) if c[k]) or "Sin hallazgos"


CAMPOS = """v.hallazgo_id AS id, v.cve, v.activo_codigo, v.expuesto_internet, v.prioridad_final, v.puntaje_riesgo,
               v.en_kev, v.epss, v.fecha_limite,
               (SELECT max(c.puntaje_base) FROM cvss_metricas c WHERE c.cve = v.cve) AS cvss"""
ORDEN = "ORDER BY v.prioridad_final NULLS LAST, v.puntaje_riesgo DESC NULLS LAST, v.epss DESC NULLS LAST, v.cve LIMIT 500"
PIE = "_Detalle completo, filtros y estado en el panel de Threat Intelligence._"


def alerta(con, cfg):
    """Mensaje de Slack con lo nuevo de la lista oficial (aun no avisado) que supera los umbrales."""
    cfg = cfg or {}
    if not cfg.get("slack"):
        return {"enviar": False, "motivo": "slack_desactivado"}
    nivel = NIVEL.get(cfg.get("minPrio"), 4)
    filas = _q(con, f"""
        SELECT {CAMPOS} FROM v_lista_oficial v
         WHERE {OFICIAL}
           AND NOT EXISTS (SELECT 1 FROM alertas_enviadas a WHERE a.hallazgo_id = v.hallazgo_id)
           AND (coalesce(v.prioridad_final, 4) <= CAST(:nivel AS integer) OR v.epss >= CAST(:epss AS numeric))
           AND (NOT CAST(:kev AS boolean) OR v.en_kev)
         {ORDEN}""", nivel=nivel, epss=float(cfg.get("epss", 0.5)), kev=bool(cfg.get("soloKev")))
    if not filas:
        return {"enviar": False, "motivo": "sin_nuevos"}
    cves = _por_cve(filas)
    c = _cuenta(filas)
    peor = cves[0]["nivel"]
    n = len(cves)
    titulo = f"{ICONO[peor]} Lyft TI · {n} vulnerabilidad{'es' if n != 1 else ''} nueva{'s' if n != 1 else ''} detectada{'s' if n != 1 else ''}"
    kev = sum(1 for x in cves if x["kev"])
    cab = [f"*Resumen:* {_semaforo(c)}"]
    if kev:
        cab.append(f"⚠️ {kev} de ellas ya se explota{'n' if kev != 1 else ''} en ataques reales: atender primero.")
    cuerpo = ["", "\n".join(cab), "", "*Lo más urgente*"] + [_bloque(x) + "\n" for x in cves[:5]]
    if n > 5:
        cuerpo.append(f"_...y {n - 5} vulnerabilidades más, de menor urgencia._")
    cuerpo.append(PIE)
    return {"enviar": True, "title": titulo[:150], "body": "\n".join(cuerpo)[:3000], "ids": [str(f["id"]) for f in filas]}


def resumen_diario(con, cfg):
    """Resumen diario para direccion: estado de toda la lista oficial abierta."""
    cfg = cfg or {}
    if not (cfg.get("slack") and cfg.get("resumen")):
        return {"enviar": False, "motivo": "resumen_desactivado"}
    filas = _q(con, f"SELECT {CAMPOS} FROM v_lista_oficial v WHERE {OFICIAL} {ORDEN}")
    if not filas:
        return {"enviar": True, "title": "🟢 Lyft TI · Resumen diario: sin vulnerabilidades abiertas",
                "body": "\nNo hay vulnerabilidades abiertas que atender hoy.\n" + PIE, "ids": []}
    cves = _por_cve(filas)
    c = _cuenta(filas)
    sistemas = len({f["activo_codigo"] for f in filas})
    kev = sum(1 for x in cves if x["kev"])
    pronto = sum(1 for x in cves if x["plazo"] and x["plazo"] <= datetime.date.today() + datetime.timedelta(days=2))
    titulo = f"{ICONO[cves[0]['nivel']]} Lyft TI · Resumen diario: {len(cves)} vulnerabilidad{'es' if len(cves) != 1 else ''} abierta{'s' if len(cves) != 1 else ''}"
    cab = [f"*Estado hoy:* {_semaforo(c)}",
           f"Afectan a {sistemas} sistema{'s' if sistemas != 1 else ''}."]
    if kev:
        cab.append(f"⚠️ {kev} ya se explota{'n' if kev != 1 else ''} en ataques reales.")
    if pronto:
        cab.append(f"⏰ {pronto} con plazo de corrección en los próximos 2 días.")
    cuerpo = ["", "\n".join(cab), "", "*Las más urgentes*"] + [_bloque(x) + "\n" for x in cves[:3]]
    if len(cves) > 3:
        cuerpo.append(f"_...y {len(cves) - 3} más en el panel._")
    cuerpo.append(PIE)
    return {"enviar": True, "title": titulo[:150], "body": "\n".join(cuerpo)[:3000], "ids": []}


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
