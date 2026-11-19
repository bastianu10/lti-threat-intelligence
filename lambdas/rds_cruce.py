"""
Cruce determinista sobre el esquema v3: componentes del inventario x rangos de version de cada CVE.
Se conecta como u_cruce (seguridad por fila activa). Crea hallazgos, evaluaciones y reaperturas.

Uso:
  python3 rds_cruce.py --host TU-ENDPOINT --password CLAVE_USUARIOS
"""
import argparse, re
from lti_db import TENANT_LYFT, agregar_argumentos, conectar, insertar_lote

GLOBAL = "00000000-0000-0000-0000-000000000000"
CERRADOS = "('remediado','falso_positivo','riesgo_aceptado')"


def version_de(t):
    d = re.findall(r"\d+", t or "")
    return tuple(int(x) for x in d) if d else None


def cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def coincide(v, exacta, desde, d_inc, hasta, h_inc):
    if exacta:
        e = version_de(exacta)
        return e is not None and cmp(v, e) == 0
    if desde:
        d = version_de(desde)
        if d is None or cmp(v, d) < 0 or (cmp(v, d) == 0 and not d_inc):
            return False
    if hasta:
        h = version_de(hasta)
        if h is None or cmp(v, h) > 0 or (cmp(v, h) == 0 and not h_inc):
            return False
    return True


def prioridades(cvss, kev, epss, expuesto):
    base = 3 if cvss is None else 1 if cvss >= 9 else 2 if cvss >= 7 else 3 if cvss >= 4 else 4
    piso = 1 if (kev or (epss is not None and epss >= 0.5)) else None
    puntaje = min(100.0, (cvss or 0) * 10 + (15 if kev else 0) + (epss or 0) * 10 + (5 if expuesto else 0))
    return base, piso, min(base, piso or base), round(puntaje, 2)


def main():
    ap = argparse.ArgumentParser()
    agregar_argumentos(ap, "u_cruce")
    ap.add_argument("--tenant", default=TENANT_LYFT)
    args = ap.parse_args()
    t = args.tenant
    con = conectar(args, tenant=t)
    con.run("BEGIN")        # reaperturas, hallazgos y evaluaciones: todo o nada

    corrida = con.run("SELECT id FROM corridas ORDER BY iniciada_en DESC LIMIT 1")
    if not corrida:
        raise SystemExit("No hay ninguna corrida: ejecuta primero rds_cargar_vulnerabilidades.py")
    corrida = corrida[0][0]

    # 1) Reaperturas (antes de crear nada, para no duplicar hallazgos abiertos)
    reabrir = {}
    for (h,) in con.run(f"SELECT h.id FROM hallazgos h WHERE h.tenant_id=:t AND h.estado IN ('falso_positivo','riesgo_aceptado') "
                        "AND NOT EXISTS (SELECT 1 FROM v_exclusiones_vigentes e WHERE e.componente_id=h.componente_id AND e.cve=h.cve)", t=t):
        reabrir[h] = "Exclusion vencida: el hallazgo se vuelve a evaluar"
    for (h,) in con.run("SELECT h.id FROM hallazgos h JOIN kev_entradas k ON k.cve = h.cve WHERE h.tenant_id=:t "
                        "AND h.estado IN ('falso_positivo','riesgo_aceptado') AND k.agregado_en > "
                        "(SELECT max(d.decidido_en)::date FROM decisiones d WHERE d.tenant_id=h.tenant_id AND d.hallazgo_id=h.id)", t=t):
        reabrir[h] = "El CVE entro al catalogo KEV despues de la decision: se reabre"
    for h, motivo in reabrir.items():
        con.run("INSERT INTO decisiones (tenant_id, hallazgo_id, estado_nuevo, justificacion) "
                "VALUES (:t, :h, 'pendiente_aprobacion_dueno', :j)", t=t, h=h, j=motivo)

    # 2) Componentes vigentes con producto del catalogo global
    comps = con.run(
        "SELECT c.id, c.producto_id, c.version, d.expuesto_internet FROM componentes c "
        "JOIN despliegues d ON d.tenant_id=c.tenant_id AND d.id=c.despliegue_id "
        "JOIN activos a ON a.tenant_id=d.tenant_id AND a.id=d.activo_id "
        "WHERE c.tenant_id=:t AND c.retirado_en IS NULL AND d.dado_de_baja_en IS NULL AND a.dado_de_baja_en IS NULL "
        "AND c.producto_tenant_id=:g", t=t, g=GLOBAL)
    por_producto = {}
    for cid, pid, ver, exp in comps:
        por_producto.setdefault(pid, []).append((cid, ver, exp))
    rangos = con.run("SELECT cve, producto_id, version_exacta, version_desde, desde_incluye, version_hasta, hasta_incluye "
                     "FROM vulnerabilidad_rangos WHERE producto_id = ANY(:p)", p=list(por_producto)) if por_producto else []

    # 3) Coincidencias
    pares, ambiguos = {}, 0
    for cve, pid, exacta, desde, d_inc, hasta, h_inc in rangos:
        for cid, ver, exp in por_producto[pid]:
            v = version_de(ver)
            if v is None:
                ambiguos += 1                      # version no interpretable: lo resolveria el agente de IA
            elif coincide(v, exacta, desde, d_inc, hasta, h_inc):
                pares[(cid, cve)] = exp
    cves = sorted({c for _, c in pares})
    cvss = {c: float(p) for c, p in con.run("SELECT cve, max(puntaje_base) FROM cvss_metricas WHERE cve = ANY(:l) GROUP BY cve", l=cves)} if cves else {}
    kev = {c for (c,) in con.run("SELECT cve FROM kev_entradas WHERE cve = ANY(:l)", l=cves)} if cves else set()
    epss = {c: float(p) for c, p in con.run("SELECT cve, puntaje FROM epss_vigente WHERE cve = ANY(:l)", l=cves)} if cves else {}
    excluidos = {(c, v) for c, v in con.run("SELECT componente_id, cve FROM v_exclusiones_vigentes")}

    # 4) Hallazgos nuevos (un solo hallazgo abierto por componente y CVE)
    nuevos = [(t, c, v, "cruce_exacto") for (c, v) in sorted(pares) if (c, v) not in excluidos]
    antes = con.run("SELECT count(*) FROM hallazgos")[0][0]
    insertar_lote(con, "hallazgos", ["tenant_id", "componente_id", "cve", "metodo_deteccion"], nuevos, "ON CONFLICT DO NOTHING")
    creados = con.run("SELECT count(*) FROM hallazgos")[0][0] - antes
    abiertos = {(c, v): h for h, c, v in con.run(f"SELECT id, componente_id, cve FROM hallazgos WHERE tenant_id=:t AND estado NOT IN {CERRADOS}", t=t)}

    # 5) Evaluaciones: solo si no hay una o si cambio la prioridad
    ultima = {h: (f, p) for h, f, p in con.run(
        "SELECT DISTINCT ON (hallazgo_id) hallazgo_id, prioridad_final, prioridad_piso FROM evaluaciones "
        "WHERE tenant_id=:t ORDER BY hallazgo_id, evaluado_en DESC, id DESC", t=t)}
    evals, criticos = [], 0
    for (c, v), exp in pares.items():
        h = abiertos.get((c, v))
        if not h:
            continue
        base, piso, final, puntaje = prioridades(cvss.get(v), v in kev, epss.get(v), exp)
        criticos += final == 1
        if ultima.get(h) != (final, piso):
            evals.append((t, h, corrida, None, puntaje, base, piso, final, None))
    insertar_lote(con, "evaluaciones", ["tenant_id", "hallazgo_id", "corrida_id", "ejecucion_id", "puntaje_riesgo",
                                        "prioridad_base", "prioridad_piso", "prioridad_final", "confianza"], evals)
    con.run("COMMIT")
    print(f"componentes evaluados: {len(comps)} | coincidencias: {len(pares)} | hallazgos creados: {creados} "
          f"(abiertos: {len(abiertos)}) | evaluaciones nuevas: {len(evals)} | criticos: {criticos} | "
          f"excluidos vigentes: {len(excluidos)} | reabiertos: {len(reabrir)} | version ambigua (para el agente): {ambiguos}")
    con.close()


if __name__ == "__main__":
    main()
