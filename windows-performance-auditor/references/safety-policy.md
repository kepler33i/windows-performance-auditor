# Politica de seguridad

## 1. Modo predeterminado
- `audit-only` siempre al comenzar y despues de cualquier ambiguedad.
- Una peticion generica ("optimiza", "acelera", "arregla", "limpia", "haz lo necesario") **no autoriza cambios**.

## 2. Autorizacion
Una accion solo se ejecuta si se cumplen **todas** las condiciones:

1. Existe en `action-plan.json` de la **sesion actual** (SessionId) y el plan no expiro (1-12 h, por defecto 4 h).
2. Se mostraron al usuario: identificador, hallazgo y evidencia, comando exacto, objetivo exacto, elementos afectados, beneficio, riesgo, administrador/reinicio/red, respaldo, reversion (o su ausencia) y validacion.
3. El usuario escribio un verbo de aprobacion explicito (`apruebo`, `autorizo`, `approve`...) junto con el identificador literal de la accion (`A-...`) o del paquete (`P-...`), sin negaciones.
4. Riesgo medio: el mensaje contiene **solo** ese identificador, y la accion nunca forma parte de un paquete.
5. Los paquetes (modo `asistido` y `tecnico`; en tecnico ademas con ticket) se aprueban escribiendo su identificador `P-...` y contienen unicamente acciones de riesgo bajo, sin red, con reversion confiable y sin punto de restauracion obligatorio.
6. `apply-approved-action.ps1` recibe `-Apply`, `-SessionId`, `-ActionId`, `-Target` exacto y `-ApprovalText` literal.
7. El hash del plan es valido. El comando regenerado desde la allowlist coincide con el del plan, y los campos de riesgo, red, administrador, reversion y punto de restauracion coinciden con el catalogo.
8. La accion no fue ejecutada antes (`executed-actions.json`).
9. Desinstalaciones y reparaciones: existe un `CREATE-RESTORE-POINT` **validado** en la misma sesion.

No cuentan como aprobacion: "si", "ok", "dale", "todo", "todas", "las recomendadas", "haz lo que sugieras", aprobaciones dadas en otra sesion o antes de mostrar el plan, ni rangos ("de la 1 a la 5").

> `-ApprovalText` es una verificacion de coherencia y trazabilidad: el agente transcribe el mensaje del usuario. La barrera real es que el usuario vea el plan y apruebe.

## 3. Equipos administrados
- Se consideran administrados si estan unidos a un dominio, a Entra ID, inscritos en MDM o tienen edicion Enterprise/Education. Las autoridades integradas `Deploy`, `Cloud` y `Local Authority` no cuentan.
- Sin autorizacion: solo verificaciones de solo lectura.
- **Autorizacion corporativa verificable**, valida solo si se cumple todo lo siguiente:
  - el archivo esta en `%ProgramData%\WindowsPerformanceAuditor\org-authorization.json` o en la ruta indicada;
  - su propietario es Administradores o SYSTEM;
  - usuarios estandar, Usuarios autenticados, Todos y el usuario actual no tienen permisos de escritura;
  - el dominio o tenant del equipo, el ticket del plan y el tipo de accion estan permitidos;
  - `ValidUntil` no vencio.
- La autorizacion se verifica al proponer **y de nuevo al ejecutar**.

Ejemplo (lo despliega TI por GPO o Intune, no el agente):
```json
{
  "Organization": "Contoso",
  "AllowedDomains": ["corp.contoso.com"],
  "AllowedTenantIds": ["00000000-0000-0000-0000-000000000000"],
  "Technician": "tec01",
  "Ticket": "INC-2041",
  "ValidUntil": "2026-12-31",
  "AllowedActionTypes": ["POWER-SET-SCHEME", "STARTUP-DISABLE-USER-RUN", "DISK-OPTIMIZE", "APP-UNINSTALL"]
}
```

## 4. Ejecucion
- Una accion por invocacion y ningun comando adicional fuera del plan.
- El estado previo se guarda en `backup-<ActionId>.json` y se relee antes de ejecutar; si no se puede, no se ejecuta.
- El objetivo se revalida en vivo antes de ejecutar: huella, existencia, procesos o servicios activos, tipo real de disco y presencia de bateria.
- Despues de cada accion se valida. Ante falla o regresion: **detenerse**, informar y proponer la reversion, que requiere una nueva aprobacion.
- No se afirma que exista respaldo o punto de restauracion sin verificarlo. Si Windows impide crear un punto por su limite de 24 h, solo se acepta un punto existente de menos de 24 h cuando ningun cambio de la sesion lo precede, y se informa su numero y fecha. Nunca se modifica `SystemRestorePointCreationFrequency`.
- Nunca se autoeleva.

## 5. Prohibido (no existe codigo para ello y debe rechazarse)
- Desactivar Defender, Firewall, UAC, Windows Update o BitLocker.
- Deshabilitar servicios o tareas de forma masiva. Solo se deshabilitan **uno por uno** servicios y tareas **huerfanos** de terceros cuyo ejecutable ya no existe, nunca los de Windows.
- Detener servicios o procesos.
- Desactivar o reducir el archivo de paginacion.
- Limpiadores de RAM o de registro (vaciar la cache de Windows empeora el rendimiento); cerrar procesos; "debloat" generico; desinstalar aplicaciones de la Tienda o del sistema.
- Borrar carpetas de aplicaciones en lugar de usar su desinstalador.
- Borrar con comodines, rutas ambiguas o recursion generica.
- Cruzar junctions, symlinks, reparse points, OneDrive o carpetas sincronizadas. La limpieza por categoria solo opera en raices fijas del catalogo, recorre sin seguir enlaces y deja la lista exacta de lo eliminado.
- `Invoke-Expression`, codigo codificado u ofuscado, scriptblocks dinamicos.
- Descargar y ejecutar scripts. Instalar programas, modulos o dependencias. `winget` solo actualiza aplicaciones ya instaladas, una por una y con aprobacion.
- Cambiar la ExecutionPolicy. Solo se admite `-ExecutionPolicy Bypass` por proceso, con permiso del usuario.
- `takeown`, `icacls`, `Set-Acl`.
- BIOS/UEFI, firmware, overclock, voltajes. Actualizar o cambiar controladores automaticamente.
- Borrar documentos, descargas o duplicados.
- Desfragmentar un SSD. Desactivar la hibernacion en portatiles.

## 6. Privacidad
- No se recopilan contrasenas, cookies, tokens, historial de navegacion, contenido de documentos, credenciales Wi-Fi, lineas de comando de procesos ni secretos.
- Evidencia de uso de programas, solo con `-IncludeAppUsage` y consentimiento: Prefetch y UserAssist se leen en memoria para calcular **una fecha de ultimo uso por programa**. No se guarda la lista de ejecuciones.
- Las entradas de inicio se registran por nombre, ejecutable y hash del comando.
- Los reportes compartibles sanitizan usuario, equipo, dominio, tenant, organizacion, tecnico, ticket, seriales, SIDs, correos e IP publicas.
- Los reportes solo se guardan en la carpeta elegida por el usuario.

## 7. Registro
`audit-log.jsonl` registra cada sonda, comando, resultado, codigo de salida, rechazo, ticket y cambio aprobado (con el texto de aprobacion sanitizado). Las limpiezas dejan `cleanup-<ActionId>.json` con cada archivo eliminado.

## 8. Red
- Ninguna llamada de red durante el diagnostico.
- Solo `DEFENDER-SCAN`, `APP-UPDATE-CHECK`, `APP-UPDATE` y `REPAIR-DISM-RESTOREHEALTH` usan red. Estan marcadas en el plan, nunca van en paquetes y requieren su propia aprobacion.
