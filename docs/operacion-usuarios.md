# Procedimiento: usuarios del panel (altas, grupos, bajas)

El panel **no** crea ni modifica usuarios: la sección «Usuarios del panel» es solo una lista
de lectura para administradores. Las altas, los cambios de grupo y las bajas los hace una
persona administradora con la CLI de AWS, siguiendo este procedimiento. Cada comando
`admin-*` queda registrado en **CloudTrail** (eventos de administración), así que la acción
es auditable (quién, cuándo y sobre qué usuario).

## Antes de empezar
- Perfil de AWS con permisos sobre Cognito: `--profile lti --region us-east-2`.
- Grupos válidos del panel: **`admin`** (acceso total, incluida esta lista y la configuración)
  y **`lectura`** (solo ve el panel).
- Obtén el ID del grupo de usuarios (User Pool) desde la salida del stack:

```bash
POOL=$(aws cloudformation describe-stacks --stack-name lti-prototipo \
  --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolId'].OutputValue" \
  --output text --profile lti --region us-east-2)
echo "$POOL"
```

Todos los comandos siguientes usan `"$POOL"` y `--profile lti --region us-east-2`.

## Alta de un usuario
Crea la cuenta y envía por correo una contraseña temporal (el usuario la cambia al entrar).
El `--username` debe ser sin espacios (p. ej. `nombre.apellido`).

```bash
aws cognito-idp admin-create-user --user-pool-id "$POOL" \
  --username nombre.apellido \
  --user-attributes Name=email,Value=persona@lyft.com Name=email_verified,Value=true \
  --desired-delivery-mediums EMAIL \
  --profile lti --region us-east-2

# Asignarle su grupo (admin o lectura):
aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" \
  --username nombre.apellido --group-name lectura \
  --profile lti --region us-east-2
```

## Cambiar el grupo de un usuario
Quita el grupo anterior y agrega el nuevo (un usuario puede estar en varios, pero el modelo
del panel espera uno).

```bash
aws cognito-idp admin-remove-user-from-group --user-pool-id "$POOL" \
  --username nombre.apellido --group-name lectura \
  --profile lti --region us-east-2

aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" \
  --username nombre.apellido --group-name admin \
  --profile lti --region us-east-2
```

## Baja de un usuario
Preferir **deshabilitar** (reversible) antes que borrar. Deshabilitar corta el acceso de
inmediato sin perder el historial.

```bash
# Baja reversible (recomendado):
aws cognito-idp admin-disable-user --user-pool-id "$POOL" \
  --username nombre.apellido --profile lti --region us-east-2

# Reactivar:
aws cognito-idp admin-enable-user --user-pool-id "$POOL" \
  --username nombre.apellido --profile lti --region us-east-2

# Baja definitiva (solo si hay que borrar la cuenta del todo):
aws cognito-idp admin-delete-user --user-pool-id "$POOL" \
  --username nombre.apellido --profile lti --region us-east-2
```

## Otros ajustes útiles
```bash
# Forzar restablecimiento de contraseña (reenvía el flujo de cambio):
aws cognito-idp admin-reset-user-password --user-pool-id "$POOL" \
  --username nombre.apellido --profile lti --region us-east-2
```

## Verificar
- En el panel: entra como admin a **Usuarios del panel**; el cambio aparece en la lista
  (correo, grupo, estado, MFA, alta).
- Por CLI, el grupo de un usuario:

```bash
aws cognito-idp admin-list-groups-for-user --user-pool-id "$POOL" \
  --username nombre.apellido --query "Groups[].GroupName" \
  --profile lti --region us-east-2
```

## Notas
- **MFA por app (TOTP):** la columna «MFA» del panel se basa en `ListUsers`, que no reporta
  el MFA por aplicación. Para usuarios con TOTP puede verse «No» aunque lo tengan activo;
  confírmalo con `admin-get-user` si hace falta.
- **Permisos de la API:** `FuncionApiSistema` solo tiene permisos de **lectura** sobre el
  pool (`ListUsers`, `ListGroups`, `ListUsersInGroup`, `AdminListGroupsForUser`). Las
  escrituras de este procedimiento las hace la persona administradora con su propio acceso,
  no la Lambda.
