"""
API de sistema del panel (Lambda FUERA de la red de la base: habla con la API de AWS, no con RDS).

  GET  /api/sistema/ejecuciones   ultimas ejecuciones del flujo (Step Functions)
  GET  /api/sistema/configuracion frecuencias de las fuentes, CMDB y alertas
  PUT  /api/sistema/configuracion guarda y APLICA: reglas de EventBridge y temporizador del CMDB   (solo grupo admin)
  POST /api/sistema/probar-slack  manda un mensaje de prueba a Slack (solo grupo admin)
  POST /api/sistema/ejecutar      inicia el flujo ahora: {"fuente": "nvd" | "epss" | "osv" | "todas"} (solo grupo admin)

La configuracion vive en un parametro de SSM (/lti/configuracion). Cada fuente tiene su regla de EventBridge; la regla
inicia el mismo flujo con una bandera que dice que fuente descargar.
"""
import datetime
import json
import os
import re

import boto3

ssm, ev, sf = boto3.client("ssm"), boto3.client("events"), boto3.client("stepfunctions")
lam = boto3.client("lambda")
SLACK_ARN = os.environ.get("SLACK_ARN", "")
PARAM = os.environ["PARAM_CONFIG"]
FLUJO = os.environ["FLUJO_ARN"]
CMDB_ID = os.environ["CMDB_ID"]
REGLAS = {"nvd": os.environ["REGLA_NVD"], "epss": os.environ["REGLA_EPSS"], "osv": os.environ["REGLA_OSV"]}
REGLA_RESUMEN = os.environ["REGLA_RESUMEN"]
DOC_CMDB = os.environ.get("DOC_CMDB", "lti-cmdb-frecuencia")
MINUTO = {"nvd": 0, "epss": 15, "osv": 30}       # escalonado: las tres fuentes no arrancan el flujo al mismo minuto
FREQS = ("1h", "6h", "12h", "24h", "7d")
DOWS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")

DEFECTO = {
    "feeds": {k: {"freq": "24h", "hora": 12, "dow": "MON", "pausado": False} for k in REGLAS},
    "cmdb": {"intervalo": 6},
    "alertas": {"slack": True, "canal": "#lti-alertas", "minPrio": "baja", "epss": 0.5, "soloKev": False,
                "resumen": True, "hora": 9},
}


def _resp(codigo, cuerpo):
    return {"statusCode": codigo, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(cuerpo, default=str)}


def _es_admin(event):
    claims = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or {}
    return "admin" in re.findall(r"[A-Za-z0-9_-]+", str(claims.get("cognito:groups", "")))


def leer_config():
    try:
        guardada = json.loads(ssm.get_parameter(Name=PARAM)["Parameter"]["Value"])
    except ssm.exceptions.ParameterNotFound:
        guardada = {}
    cfg = json.loads(json.dumps(DEFECTO))
    for k in ("feeds", "cmdb", "alertas"):
        if isinstance(guardada.get(k), dict):
            for sub, val in guardada[k].items():
                if k == "feeds" and isinstance(val, dict) and sub in cfg["feeds"]:
                    cfg["feeds"][sub].update(val)
                elif k != "feeds":
                    cfg[k][sub] = val
    return cfg


def _entero(v, permitidos=None, minimo=None, maximo=None):
    """Entero estricto: rechaza bool (True == 1 en Python) y float (1.0 == 1)."""
    if type(v) is not int:
        return False
    if permitidos is not None and v not in permitidos:
        return False
    return (minimo is None or v >= minimo) and (maximo is None or v <= maximo)


def validar(c):
    """Devuelve la configuracion limpia o lanza ValueError con un mensaje para la persona."""
    out = json.loads(json.dumps(DEFECTO))
    for k in REGLAS:
        f = (c.get("feeds") or {}).get(k) or {}
        if f.get("freq") not in FREQS:
            raise ValueError(f"Frecuencia no valida en {k}")
        hora = f.get("hora", 12)
        if not _entero(hora, minimo=0, maximo=23):
            raise ValueError(f"Hora no valida en {k}")
        if f.get("dow", "MON") not in DOWS:
            raise ValueError(f"Dia no valido en {k}")
        out["feeds"][k] = {"freq": f["freq"], "hora": hora, "dow": f.get("dow", "MON"), "pausado": bool(f.get("pausado"))}
    iv = (c.get("cmdb") or {}).get("intervalo")
    if not _entero(iv, permitidos=(1, 3, 6, 12, 24)):
        raise ValueError("Intervalo del CMDB no valido")
    out["cmdb"] = {"intervalo": iv}
    a = c.get("alertas") or {}
    if not re.fullmatch(r"#[a-z0-9._-]{1,79}", str(a.get("canal", ""))):
        raise ValueError("El canal de Slack debe verse asi: #nombre-del-canal")
    if a.get("minPrio") not in ("critica", "alta", "media", "baja"):
        raise ValueError("Prioridad minima no valida")
    ep = a.get("epss")
    if not isinstance(ep, (int, float)) or isinstance(ep, bool) or not 0 <= ep <= 1:
        raise ValueError("EPSS minimo debe estar entre 0 y 1")
    hr = a.get("hora", 9)
    if not _entero(hr, minimo=0, maximo=23):
        raise ValueError("Hora del resumen no valida")
    out["alertas"] = {"slack": bool(a.get("slack")), "canal": a["canal"], "minPrio": a["minPrio"], "epss": float(ep),
                      "soloKev": bool(a.get("soloKev")), "resumen": bool(a.get("resumen")), "hora": hr}
    return out


def expresion(clave, f):
    m = MINUTO[clave]
    return {"1h": "rate(1 hour)", "6h": "rate(6 hours)", "12h": "rate(12 hours)",
            "24h": f"cron({m} {f['hora']} * * ? *)",
            "7d": f"cron({m} {f['hora']} ? * {f['dow']} *)"}[f["freq"]]


def aplicar(nueva, anterior):
    """Cambia las reglas y el temporizador. Devuelve que se aplico y que fallo, sin romper lo guardado."""
    res = {}
    for k, nombre in REGLAS.items():
        f = nueva["feeds"][k]
        try:
            ev.put_rule(Name=nombre, ScheduleExpression=expresion(k, f),
                        State="DISABLED" if f["pausado"] else "ENABLED",
                        Description=f"Fuente {k}: lo administra el panel (Configuracion)")
            res[k] = "aplicado"
        except Exception as e:
            print("ERROR regla", k, repr(e))
            res[k] = "error"
    try:
        al = nueva["alertas"]
        ev.put_rule(Name=REGLA_RESUMEN, ScheduleExpression=f"cron(0 {al['hora']} * * ? *)",
                    State="ENABLED" if al["resumen"] and al["slack"] else "DISABLED",
                    Description="Resumen diario a Slack: lo administra el panel (Configuracion)")
        res["resumen"] = "aplicado"
    except Exception as e:
        print("ERROR regla resumen", repr(e))
        res["resumen"] = "error"
    if nueva["cmdb"]["intervalo"] != anterior["cmdb"]["intervalo"]:
        h = nueva["cmdb"]["intervalo"]
        try:
            # Documento SSM propio: el comando es fijo y "intervalo" solo admite 1, 3, 6, 12 o 24 (lo valida SSM).
            # El rol ya no puede usar AWS-RunShellScript: aunque esta Lambda se comprometiera, no podria ejecutar
            # comandos arbitrarios en el CMDB.
            ssm.send_command(InstanceIds=[CMDB_ID], DocumentName=DOC_CMDB, Comment="Frecuencia del CMDB",
                             Parameters={"intervalo": [str(h)]})
            res["cmdb"] = "aplicado"
        except Exception as e:
            print("ERROR cmdb", repr(e))
            res["cmdb"] = "error"
    return res


def ejecuciones():
    items = []
    for x in sf.list_executions(stateMachineArn=FLUJO, maxResults=10)["executions"]:
        it = {"nombre": x["name"], "estado": x["status"], "inicio": x["startDate"],
              "fin": x.get("stopDate")}
        if x["status"] in ("FAILED", "TIMED_OUT", "ABORTED") and len(items) < 5:
            try:
                d = sf.describe_execution(executionArn=x["executionArn"])
                it["motivo"] = (d.get("error") or d.get("cause") or "")[:140]
            except Exception:
                pass
        items.append(it)
    return {"items": items}


def ejecutar(cuerpo):
    f = cuerpo.get("fuente", "todas")
    if f not in ("nvd", "epss", "osv", "todas"):
        raise ValueError("Fuente no valida")
    entrada = {"nvd": True, "epss": True, "osv": True} if f == "todas" else {k: (k == f) for k in REGLAS}
    entrada["resumen"] = False
    r = sf.start_execution(stateMachineArn=FLUJO, input=json.dumps(entrada))
    return {"iniciada": r["startDate"], "fuente": f}


def probar_slack():
    if not SLACK_ARN:
        raise ValueError("No hay una Lambda de Slack configurada")
    # Contrato del emisor v2 (lti-notificador-slack): {"mensajes": [...]} -> {"resultados": [...]}.
    # "ids" solo se devuelve en el resultado; el emisor no toca la base.
    r = lam.invoke(FunctionName=SLACK_ARN, Payload=json.dumps({"mensajes": [{
        "ids": [1], "title": "Prueba desde el panel de Threat Intelligence",
        "body": "Si ves este mensaje, la conexion con Slack funciona."}]}).encode())
    if r.get("FunctionError"):
        return {"ok": False, "estado": "error_del_emisor"}
    cuerpo = json.loads(r["Payload"].read() or b"{}")
    res = (cuerpo.get("resultados") or [{}])[0]
    return {"ok": res.get("status") == "sent", "estado": res.get("status", "desconocido")}


def handler(event, context):
    if event.get("accion") == "alertas":                 # lo llama Step Functions para leer los umbrales
        return leer_config()["alertas"]
    try:
        ruta = (event.get("rawPath") or "").split("/api/sistema/", 1)[-1].strip("/")
        metodo = (event.get("requestContext", {}).get("http", {}).get("method") or "GET").upper()
        if ruta == "ejecuciones" and metodo == "GET":
            return _resp(200, ejecuciones())
        if ruta == "configuracion" and metodo == "GET":
            return _resp(200, leer_config())
        if metodo in ("PUT", "POST") and not _es_admin(event):
            return _resp(403, {"error": "Esta accion es solo para administradores"})
        cuerpo = json.loads(event.get("body") or "{}")
        if ruta == "configuracion" and metodo == "PUT":
            nueva, anterior = validar(cuerpo), leer_config()
            ssm.put_parameter(Name=PARAM, Value=json.dumps(nueva), Type="String", Overwrite=True)
            return _resp(200, {"configuracion": nueva, "aplicado": aplicar(nueva, anterior)})
        if ruta == "probar-slack" and metodo == "POST":
            return _resp(200, probar_slack())
        if ruta == "ejecutar" and metodo == "POST":
            return _resp(200, ejecutar(cuerpo))
        return _resp(404, {"error": "ruta desconocida"})
    except ValueError as e:
        return _resp(400, {"error": str(e)})
    except Exception as e:
        print("ERROR", repr(e))
        return _resp(500, {"error": "No se pudo completar la accion"})
