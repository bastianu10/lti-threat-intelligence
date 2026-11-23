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
  GET /api/reporte-semanal    reporte ejecutivo de los ultimos 7 dias (postura, plazos, KEV, agente)
  GET /api/asesoria?hallazgo=<uuid>  asesoria del agente (no vinculante) para un hallazgo del tenant
"""
import datetime
import decimal
import json
import os
import re
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


# ---------------------------------------------------------------- Asesoria del agente (solo lectura)
# El agente guarda cada asesoria en S3 curada: agente/<tenant>/<corrida>/<hallazgo>-<sha>.json.
# Controles: (1) el hallazgo debe existir para el tenant (consulta con RLS); (2) la ruta en S3 la arma el
# servidor, nunca el cliente; (3) el documento debe ser del mismo tenant y hallazgo, estar "aceptada" y traer la
# prioridad del motor; (4) se devuelve una LISTA BLANCA de campos, con textos acotados; (5) el navegador los
# escapa al pintarlos. La asesoria NO cambia la prioridad ni el estado: es informativa para el dueno.
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CORRIDAS_A_BUSCAR = 5
MAX_DOC_BYTES = 512 * 1024
_S3 = None


class ErrorCliente(Exception):
    def __init__(self, codigo, mensaje):
        super().__init__(mensaje)
        self.codigo = codigo


def _s3():
    global _S3
    if _S3 is None:
        import boto3
        from botocore.config import Config
        # Tiempos cortos: la Lambda tiene 30 s y el panel no debe quedarse esperando a S3.
        _S3 = boto3.client("s3", config=Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 2}))
    return _S3


def _t(v, n=1500):
    return v[:n] if isinstance(v, str) else None


def _ent(v, minimo, maximo):
    return v if isinstance(v, int) and not isinstance(v, bool) and minimo <= v <= maximo else None


def _items(v, campos, n=12):
    out = []
    for x in (v if isinstance(v, list) else [])[:n]:
        if isinstance(x, dict):
            out.append({c: (_t(x.get(c), 600) if not isinstance(x.get(c), int) else _ent(x.get(c), 0, 999))
                        for c in campos})
    return out


def _textos(v, n=12, largo=80):
    return [x[:largo] for x in (v if isinstance(v, list) else [])[:n] if isinstance(x, str)]


def _resumen_asesoria(doc, hid, corrida_id, generado_en, vigente):
    s = doc.get("salida_validada") or {}
    pr = doc.get("prioridad") or {}
    esc = s.get("escenario_riesgo") or {}
    ru = s.get("recomendacion_urgencia") or {}
    rec = doc.get("recomendacion") or {}
    pd = doc.get("propuesta_para_dueno") or {}
    rv = doc.get("revision") or {}
    ent = doc.get("entrada") or {}
    ctx = ent.get("contexto_negocio") or {}
    ev = ent.get("evaluacion_determinista") or {}
    return {
        "disponible": True, "hallazgo_id": hid, "corrida_id": corrida_id, "generado_en": generado_en,
        "vigente": vigente,
        "motor": {"prioridad_final": _ent(pr.get("final"), 1, 4), "prioridad_base": _ent(pr.get("base"), 1, 4),
                  "piso": _ent(pr.get("piso"), 1, 4), "tipo": _t(pr.get("tipo"), 40),
                  "aplicabilidad": _t(ev.get("estado_aplicabilidad"), 40),
                  "version": _t((ent.get("trazabilidad") or {}).get("motor_version"), 60)},
        "explicacion": _t(s.get("explicacion_dashboard"), 2500),
        "escenario": {"amenaza": _t(esc.get("amenaza")), "vector": _t(esc.get("vector_ataque")),
                      "proceso": _t(esc.get("proceso_negocio_afectado")),
                      "consecuencia": _t(esc.get("consecuencia_negocio")),
                      "tecnicas": [x for x in _textos(esc.get("tecnicas_attack"), 8, 20)
                                   if re.match(r"^T\d{4}(\.\d{3})?$", x)]},
        "plan": _items(s.get("plan_accion"), ("orden", "tipo", "descripcion")),
        "controles": _items(s.get("controles_sugeridos"), ("tipo", "descripcion")),
        "mitigacion_temporal": _t(s.get("mitigacion_temporal")),
        "datos_a_verificar": _items(s.get("datos_a_verificar"), ("ruta_campo", "motivo")),
        "observaciones": _items(s.get("observaciones_para_revision"), ("ruta_campo", "observacion")),
        "recomendacion": {"efectiva": _t(rec.get("efectiva"), 30), "propuesta": _t(rec.get("propuesta"), 30),
                          "justificacion": _t(ru.get("justificacion"))},
        "propuesta_dueno": {"probabilidad": _ent(pd.get("probabilidad"), 1, 3), "impacto": _ent(pd.get("impacto"), 1, 3),
                            "condicion": _t(pd.get("condicion"), 60), "estado": _t(pd.get("estado"), 60)},
        "revision": {"requerida": rv.get("requerida") is True, "prioridad": _t(rv.get("prioridad"), 20),
                     "motivos": _textos(rv.get("motivos"), 15, 60)},
        "confianza": s.get("confianza") if isinstance(s.get("confianza"), (int, float)) else None,
        "modelo": _t(doc.get("modelo"), 80),
        "contexto_negocio": {"version": _t(ctx.get("version"), 60), "aprobado": ctx.get("aprobado") is True},
    }


def _documento_valido(doc, hid):
    return (isinstance(doc, dict) and doc.get("hallazgo_id") == hid and doc.get("tenant_id") == TENANT
            and doc.get("estado") == "aceptada" and (doc.get("prioridad") or {}).get("fuente") == "motor")


def asesoria(con, p):
    hid = str(p.get("hallazgo") or "").strip().lower()
    if not RE_UUID.match(hid):
        raise ErrorCliente(400, "Identificador de hallazgo invalido")
    if not _q(con, "SELECT 1 AS ok FROM hallazgos WHERE id = CAST(:h AS uuid)", h=hid):   # RLS: solo el tenant
        raise ErrorCliente(404, "Hallazgo no encontrado")
    bucket = os.environ.get("BUCKET_CURADA")
    if not bucket:
        return {"disponible": False, "motivo": "La asesoria del agente no esta configurada en este entorno"}
    corridas = _q(con, "SELECT id FROM corridas WHERE resultado = 'exito' ORDER BY iniciada_en DESC LIMIT "
                       + str(CORRIDAS_A_BUSCAR))
    for i, c in enumerate(corridas):
        cid = str(c["id"])
        r = _s3().list_objects_v2(Bucket=bucket, Prefix=f"agente/{TENANT}/{cid}/{hid}-", MaxKeys=10)
        objs = [o for o in (r.get("Contents") or []) if o.get("Size", 0) <= MAX_DOC_BYTES]
        if not objs:
            continue
        o = max(objs, key=lambda x: x["LastModified"])
        try:
            doc = json.loads(_s3().get_object(Bucket=bucket, Key=o["Key"])["Body"].read(MAX_DOC_BYTES + 1))
        except ValueError:
            print("asesoria ilegible", {"hallazgo": hid, "corrida": cid})
            continue
        if not isinstance(doc, dict) or not _documento_valido(doc, hid):
            print("asesoria descartada", {"hallazgo": hid, "corrida": cid})
            continue
        return _resumen_asesoria(doc, hid, cid, o["LastModified"], vigente=(i == 0))
    return {"disponible": False, "motivo": "El agente no ha asesorado este hallazgo en las corridas recientes"}


# ---------------------------------------------------------------- reporte ejecutivo semanal (solo lectura)
# Una pagina para direccion: postura, tendencia, plazos, explotacion activa, movimiento, riesgo por proceso de
# negocio (del agente) y decisiones pendientes. Mismos numeros que el panel (lista oficial con RLS). El analisis
# del agente se lee del prefijo FIJO agente/<tenant>/ (lo arma el servidor), se valida documento por documento y
# solo se devuelven campos de una lista blanca. El reporte NO cambia nada: no hay escrituras.
COSTO_POR_CASO_USD = 0.063      # medido en la corrida A5 (98,384 + 18,296 tokens por 9 casos, Claude en Bedrock)
REP_MAX_DOCS = 25               # documentos del agente que se abren por reporte (los mas urgentes)
REP_DIAS_AGENTE = 7
RE_CLAVE_AGENTE = re.compile(r"^agente/[0-9a-f-]{36}/([0-9a-f-]{36})/([0-9a-f-]{36})-[0-9a-f]{16}\.json$")
RECOMENDACIONES = ("escalar", "mantener", "revisar_a_la_baja")


def _semana(hoy):
    a, s, _ = hoy.isocalendar()
    return f"{a}-W{s:02d}"


def _docs_agente(bucket, ahora):
    """{hallazgo_id: (clave, corrida, fecha)} con el documento mas reciente de los ultimos 7 dias, y cuantos hubo."""
    limite = ahora - datetime.timedelta(days=REP_DIAS_AGENTE)
    indice, total, params = {}, 0, {"Bucket": bucket, "Prefix": f"agente/{TENANT}/", "MaxKeys": 1000}
    for _ in range(10):
        r = _s3().list_objects_v2(**params)
        for o in r.get("Contents") or []:
            m = RE_CLAVE_AGENTE.match(o.get("Key", ""))
            f = o.get("LastModified")
            if not m or not f or f < limite or o.get("Size", 0) > MAX_DOC_BYTES:
                continue
            total += 1
            corrida, hid = m.group(1), m.group(2)
            if hid not in indice or f > indice[hid][2]:
                indice[hid] = (o["Key"], corrida, f)
        if not r.get("IsTruncated"):
            break
        params["ContinuationToken"] = r["NextContinuationToken"]
    return indice, total


def _agente_de(bucket, indice, hid):
    if hid not in indice:
        return None
    clave, corrida, _ = indice[hid]
    try:
        doc = json.loads(_s3().get_object(Bucket=bucket, Key=clave)["Body"].read(MAX_DOC_BYTES + 1))
    except ValueError:
        return None
    if not _documento_valido(doc, hid) or doc.get("corrida_id") != corrida:
        return None
    rec = (doc.get("recomendacion") or {}).get("efectiva") if isinstance(doc.get("recomendacion"), dict) else None
    esc_ = ((doc.get("salida_validada") or {}).get("escenario_riesgo") or {}) if isinstance(doc.get("salida_validada"), dict) else {}
    return {"recomendacion": rec if rec in RECOMENDACIONES else None,
            "proceso": _t(esc_.get("proceso_negocio_afectado"), 140) if isinstance(esc_, dict) else None,
            "consecuencia": _t(esc_.get("consecuencia_negocio"), 220) if isinstance(esc_, dict) else None}


def reporte_semanal(con, _p):
    hoy = _q(con, "SELECT current_date AS d")[0]["d"]
    desde = hoy - datetime.timedelta(days=6)
    ahora = datetime.datetime.now(datetime.timezone.utc)
    filas = _q(con, f"""
        SELECT v.hallazgo_id AS id, v.cve, v.activo_codigo, v.ambiente, v.expuesto_internet, v.prioridad_final,
               v.puntaje_riesgo, v.en_kev, v.epss, v.fecha_limite, v.estado, v.dominio_negocio,
               NULL::numeric AS cvss
          FROM v_lista_oficial v WHERE {OFICIAL} {ORDEN}""")
    cves = _por_cve(filas)
    por_p = {str(n): sum(1 for f in filas if (f["prioridad_final"] or 4) == n) for n in (1, 2, 3, 4)}
    vencidos = [f for f in filas if f["fecha_limite"] and f["fecha_limite"] < hoy]
    max_dias = max(((hoy - f["fecha_limite"]).days for f in vencidos), default=0)

    # tendencia: foto de hace 7 dias (o la mas vieja disponible) en metricas_diarias, igual que /api/resumen
    serie = _q(con, "SELECT dia, criticas, altas, medias, bajas FROM metricas_diarias "
                    "WHERE dia >= current_date - 13 ORDER BY dia")
    antes = _q(con, "SELECT dia, criticas + altas + medias + bajas AS abiertos, criticas FROM metricas_diarias "
                    "WHERE dia <= current_date - 7 ORDER BY dia DESC LIMIT 1") or \
        _q(con, "SELECT dia, criticas + altas + medias + bajas AS abiertos, criticas FROM metricas_diarias "
                "WHERE dia < current_date ORDER BY dia ASC LIMIT 1")
    prev = antes[0] if antes else None

    mov = _q(con, """
        WITH d AS (
          SELECT x.hallazgo_id, x.decidido_en, e.es_cerrado,
                 lag(e.es_cerrado) OVER (PARTITION BY x.hallazgo_id ORDER BY x.decidido_en, x.id) AS antes_cerrado
            FROM decisiones x JOIN estados_hallazgo e ON e.codigo = x.estado_nuevo)
        SELECT (SELECT count(*) FROM hallazgos WHERE detectado_en >= CAST(:desde AS date)) AS nuevos,
               count(DISTINCT hallazgo_id) FILTER (WHERE es_cerrado AND NOT coalesce(antes_cerrado, false)
                                                     AND decidido_en >= CAST(:desde AS date)) AS cerrados,
               count(DISTINCT hallazgo_id) FILTER (WHERE NOT es_cerrado AND antes_cerrado
                                                     AND decidido_en >= CAST(:desde AS date)) AS reabiertos
          FROM d""", desde=desde)[0]

    # agente: casos de la semana y analisis del documento mas reciente de los CVE mas urgentes
    bucket = os.environ.get("BUCKET_CURADA")
    agente = {"disponible": False, "casos_semana": 0, "costo_estimado_usd": None,
              "recomendaciones": {r: 0 for r in RECOMENDACIONES}}
    por_hallazgo = {}
    if bucket:
        try:
            indice, total = _docs_agente(bucket, ahora)
            abiertos_ids = [str(f["id"]) for f in filas]
            for hid in abiertos_ids[:REP_MAX_DOCS]:
                a = _agente_de(bucket, indice, hid)
                if a:
                    por_hallazgo[hid] = a
                    if a["recomendacion"]:
                        agente["recomendaciones"][a["recomendacion"]] += 1
            agente.update(disponible=True, casos_semana=total,
                          costo_estimado_usd=round(total * COSTO_POR_CASO_USD, 2))
        except Exception as e:          # el reporte sale igual, sin la seccion del agente
            print("reporte: agente no disponible", type(e).__name__)

    id_por_cve = {}
    for f in filas:
        id_por_cve.setdefault(f["cve"], []).append(str(f["id"]))
    top, procesos = [], {}
    for x in cves:
        ases = [por_hallazgo[h] for h in id_por_cve.get(x["cve"], []) if h in por_hallazgo]
        rec = next((a["recomendacion"] for a in ases if a["recomendacion"] == "escalar"), None) or \
            next((a["recomendacion"] for a in ases if a["recomendacion"]), None)
        proc = next((a["proceso"] for a in ases if a.get("proceso")), None)
        cons = next((a["consecuencia"] for a in ases if a.get("consecuencia")), None)
        dias = (x["plazo"] - hoy).days if x["plazo"] else None
        if len(top) < 6:
            top.append({"cve": x["cve"], "prioridad": x["nivel"], "kev": x["kev"], "internet": x["internet"],
                        "fecha_limite": x["plazo"], "dias": dias, "activos": x["activos"][:6],
                        "n_activos": len(x["activos"]), "ia": rec})
        if proc:
            p = procesos.setdefault(proc, {"proceso": proc, "prioridad": x["nivel"], "cves": 0, "kev": False,
                                           "vencido": False, "escalar": 0, "consecuencia": cons})
            p["prioridad"] = min(p["prioridad"], x["nivel"])
            p["cves"] += 1
            p["kev"] = p["kev"] or x["kev"]
            p["vencido"] = p["vencido"] or (dias is not None and dias < 0)
            p["escalar"] += 1 if rec == "escalar" else 0
    kev = [x for x in cves if x["kev"]]
    return {
        "periodo": {"desde": desde, "hasta": hoy, "semana": _semana(hoy), "generado_en": ahora.isoformat()},
        "postura": {"abiertos": len(filas), "cves": len(cves), "sistemas": len({f["activo_codigo"] for f in filas}),
                    "por_prioridad": por_p,
                    "cambio_abiertos": (len(filas) - prev["abiertos"]) if prev else None,
                    "cambio_criticas": (int(por_p["1"]) - prev["criticas"]) if prev else None,
                    "comparado_con": prev["dia"] if prev else None},
        "serie": serie,
        "plazos": {"en_plazo": len(filas) - len(vencidos), "vencidos": len(vencidos), "max_dias_vencido": max_dias,
                   "pct_en_plazo": round(100 * (len(filas) - len(vencidos)) / len(filas)) if filas else 100,
                   "vencen_7d": sum(1 for f in filas if f["fecha_limite"] and 0 <= (f["fecha_limite"] - hoy).days <= 7)},
        "kev": {"cves": len(kev), "activos": sum(len(x["activos"]) for x in kev),
                "produccion": sum(1 for f in filas if f["en_kev"] and f["ambiente"] == "produccion")},
        "movimiento": {"nuevos": int(mov["nuevos"]), "cerrados": int(mov["cerrados"]), "reabiertos": int(mov["reabiertos"])},
        "top": top,
        "procesos": sorted(procesos.values(), key=lambda p: (p["prioridad"], not p["kev"], -p["cves"]))[:6],
        "decisiones_pendientes": sum(1 for f in filas if f["estado"] == "pendiente_aprobacion_dueno"),
        "agente": agente,
    }


RUTAS = {"resumen": resumen, "tendencia": tendencia, "hallazgos": hallazgos, "recursos": recursos,
         "cobertura": cobertura, "por-criticidad": por_criticidad, "ambiguos": ambiguos,
         "asesoria": asesoria, "reporte-semanal": reporte_semanal}


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
    except ErrorCliente as e:                                       # 400/404 con mensaje propio, sin detalle interno
        return _resp(e.codigo, {"error": str(e)})
    except Exception as e:                                          # el detalle queda en CloudWatch, no en la respuesta
        print("ERROR", repr(e))
        return _resp(500, {"error": "No se pudieron leer los datos"})
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass
