"""Utilidades comunes para los scripts de RDS (conexion, lotes, separador de SQL)."""
import ssl
import pg8000.native as pg

TENANT_LYFT = "11111111-1111-1111-1111-111111111111"


def agregar_argumentos(ap, usuario_defecto):
    ap.add_argument("--host", required=True, help="endpoint de RDS")
    ap.add_argument("--port", type=int, default=5432)
    ap.add_argument("--db", default="lti")
    ap.add_argument("--user", default=usuario_defecto)
    ap.add_argument("--password", required=True)
    ap.add_argument("--ca-bundle", default=None, help="ruta al certificado CA de RDS (ej. rds-ca-bundle.pem)")
    ap.add_argument("--sin-ssl", action="store_true", help="solo para pruebas con una base local sin TLS")


def conectar(args, tenant=None):
    ctx = None
    if not args.sin_ssl:
        # P0.2: validar certificado y hostname del servidor RDS. Pasar --ca-bundle con el PEM
        # de AWS (descargable de https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem).
        ctx = ssl.create_default_context(cafile=getattr(args, "ca_bundle", None) or None)
        # check_hostname y verify_mode=CERT_REQUIRED son el default de create_default_context.
    con = pg.Connection(args.user, host=args.host, port=args.port, database=args.db,
                        password=args.password, ssl_context=ctx)
    con.run("SET TIME ZONE 'UTC'")
    if tenant:
        # La seguridad por fila (RLS) filtra todo con este valor.
        con.run("SELECT set_config('app.tenant_id', :t, false)", t=tenant)
    return con


def insertar_lote(con, tabla, columnas, filas, sufijo="", tam=300):
    """INSERT de varias filas por sentencia (mucho mas rapido por internet que fila por fila)."""
    total = 0
    for i in range(0, len(filas), tam):
        trozo = filas[i:i + tam]
        params, valores = {}, []
        for r, fila in enumerate(trozo):
            marcas = []
            for c, v in enumerate(fila):
                k = f"p{r}_{c}"
                params[k] = v
                marcas.append(f":{k}")
            valores.append("(" + ",".join(marcas) + ")")
        con.run(f"INSERT INTO {tabla} ({','.join(columnas)}) VALUES {','.join(valores)} {sufijo}", **params)
        total += len(trozo)
    return total


def separar_sql(texto):
    """Separa un script en sentencias respetando comentarios, comillas simples y bloques $$...$$."""
    sentencias, actual, i, n = [], [], 0, len(texto)
    en_simple, tag_dolar = False, None
    while i < n:
        c = texto[i]
        if tag_dolar is None and not en_simple:
            if texto.startswith("--", i):                      # comentario de linea
                j = texto.find("\n", i)
                i = n if j == -1 else j
                continue
            if c == "$":                                       # posible inicio de $tag$
                j = i + 1
                while j < n and (texto[j].isalnum() or texto[j] == "_"):
                    j += 1
                if j < n and texto[j] == "$":
                    tag_dolar = texto[i:j + 1]
                    actual.append(tag_dolar)
                    i = j + 1
                    continue
            if c == "'":
                en_simple = True
            elif c == ";":
                sent = "".join(actual).strip()
                if sent:
                    sentencias.append(sent)
                actual = []
                i += 1
                continue
        elif en_simple:
            if c == "'":
                if texto.startswith("''", i):
                    actual.append("''")
                    i += 2
                    continue
                en_simple = False
        elif tag_dolar is not None and texto.startswith(tag_dolar, i):
            actual.append(tag_dolar)
            i += len(tag_dolar)
            tag_dolar = None
            continue
        actual.append(c)
        i += 1
    resto = "".join(actual).strip()
    if resto:
        sentencias.append(resto)
    return sentencias
