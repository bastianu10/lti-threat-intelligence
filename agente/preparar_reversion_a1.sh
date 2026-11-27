#!/usr/bin/env bash
# Prepara (NO despliega) la reversion del agente a a1 cambiando SOLO sus dos lineas de infra/plantilla-aws.yaml:
#   VersionAgente  Default: a2              -> a1
#   PROMPT_ARCHIVO sistema_v2_<n>.md        -> sistema_v2_4.md
# No toca nada mas de la plantilla: si el motor ya desplego cambios propios, se conservan.
# Ademas comprueba, en solo lectura, que el artefacto a1 sigue en S3 con el mismo hash que registro el despliegue a1.
#
# Uso (desde la raiz del repositorio):
#   bash agente/preparar_reversion_a1.sh --ensayo   escribe la plantilla revertida en /tmp y la compara con la de a1
#                                                     (commit 2a54663). No modifica nada. Para el ensayo previo.
#   bash agente/preparar_reversion_a1.sh             modifica infra/plantilla-aws.yaml en el arbol de trabajo.
#                                                     Despues: revisar git diff, commit y desplegar.sh (change set + SI).
set -euo pipefail
cd "$(dirname "$0")/.."
PERFIL="${AWS_PROFILE:-lti}"; REGION="${AWS_REGION:-us-east-2}"
COMMIT_A1="2a54663"
ENSAYO=0; [ "${1:-}" = "--ensayo" ] && ENSAYO=1
DESTINO="infra/plantilla-aws.yaml"; [ $ENSAYO = 1 ] && DESTINO="$(mktemp -t plantilla-reversion-XXXX).yaml"

echo "== 1. Artefacto a1 en S3 (solo lectura)"
CUENTA="$(aws sts get-caller-identity --query Account --output text --profile "$PERFIL" --region "$REGION")"
TMPZIP="$(mktemp -t lti-agente-a1-XXXX).zip"
aws s3 cp "s3://lti-curada-$CUENTA/artefactos/lti-agente-a1.zip" "$TMPZIP" --only-show-errors --profile "$PERFIL" --region "$REGION"
HEX="$(shasum -a 256 "$TMPZIP" | cut -c1-64)"
B64="$(python3 -c 'import sys,hashlib,base64;print(base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode())' "$TMPZIP")"
rm -f "$TMPZIP"
echo "   sha256 hex    $HEX"
echo "   CodeSha256    $B64   (debe coincidir con el CodeSha256 registrado del despliegue a1)"

echo "== 2. Plantilla revertida (solo las dos lineas del agente)"
python3 - "$DESTINO" <<'PY'
import pathlib, re, sys
origen = pathlib.Path("infra/plantilla-aws.yaml")
s = origen.read_text()
lineas = s.split("\n")
cambios = 0
for i, l in enumerate(lineas):
    if l.strip() == "VersionAgente:":
        for j in range(i + 1, min(i + 6, len(lineas))):
            if lineas[j].strip().startswith("Default:"):
                if lineas[j].strip() != "Default: a1":
                    lineas[j] = re.sub(r"Default: \S+", "Default: a1", lineas[j]); cambios += 1
                break
    if re.match(r"^\s*PROMPT_ARCHIVO: sistema_v\d+_\d+\.md\s*$", l) and "sistema_v2_4.md" not in l:
        lineas[i] = re.sub(r"sistema_v\d+_\d+\.md", "sistema_v2_4.md", l); cambios += 1
if cambios != 2:
    sys.exit(f"ABORTO: se esperaban exactamente 2 cambios y hubo {cambios}; revisar la plantilla a mano")
pathlib.Path(sys.argv[1]).write_text("\n".join(lineas))
print(f"   OK  2 lineas cambiadas -> {sys.argv[1]}")
PY

if [ $ENSAYO = 1 ]; then
  echo "== 3. Ensayo: comparar con la plantilla desplegada en a1 ($COMMIT_A1)"
  if diff -q <(git show "$COMMIT_A1:infra/plantilla-aws.yaml") "$DESTINO" >/dev/null; then
    echo "   OK  identica a la plantilla de a1 (no hay otros cambios de infraestructura desde a1)"
  else
    echo "   AVISO: difiere de la plantilla de a1. Es lo esperado SOLO si el motor u otro equipo desplego cambios"
    echo "   propios despues de a1; revisar que las diferencias no sean del agente:"
    diff <(git show "$COMMIT_A1:infra/plantilla-aws.yaml") "$DESTINO" | head -20 || true
  fi
  rm -f "$DESTINO"
else
  echo "== 3. Revisar y desplegar"
  git diff --stat infra/plantilla-aws.yaml
  echo "   Siguiente: git diff infra/plantilla-aws.yaml (deben ser 2 lineas), commit, y bash scripts/desplegar.sh"
fi
