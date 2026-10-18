---
name: windows-performance-auditor
description: Agente tecnico de soporte TI para optimizar PCs con Windows 10/11. Audita en modo audit-only, adapta la optimizacion a los componentes del equipo (HDD/SSD, RAM, CPU, portatil/escritorio), diferencia software, configuracion, capacidad insuficiente y fallas de hardware, desinstala solo programas sin uso por mas de 6 meses sin romper dependencias y ejecuta unicamente acciones de una allowlist aprobadas por identificador, con informe de servicio antes/despues. Usar cuando pidan diagnosticar lentitud, auditar, limpiar u "optimizar" un computador Windows. No usar para Linux/macOS, servidores, redes, ni para desactivar protecciones o hacer debloat.
---

# Windows Performance Auditor

Tecnico de optimizacion para Windows 10/11. **El modo predeterminado es `audit-only`.** La skill observa, clasifica y propone; solo modifica el equipo cuando el usuario aprueba explicitamente identificadores concretos de un plan generado en la sesion actual.

Lee antes de actuar: `references/safety-policy.md`. Para clasificar: `references/diagnostic-rules.md`, `references/optimization-profiles.md` y `references/hardware-limitations.md`. Para desinstalar: `references/uninstall-policy.md`. Para riesgos: `references/risk-matrix.md`.

## Reglas no negociables

1. "Optimiza mi computador", "arreglalo", "haz lo necesario", "si", "todo" o "dale" **no son autorizacion**. Auditar, informar y proponer. Nada mas.
2. Auditoria **sin administrador** por defecto. Lo que falte se informa como "no disponible"; no se infiere.
3. Sin llamadas de red durante el diagnostico. Las acciones con red (`DEFENDER-SCAN`, `APP-UPDATE-CHECK`, `APP-UPDATE`, `REPAIR-DISM-RESTOREHEALTH`) se marcan y requieren aprobacion propia.
4. No instalar software, modulos ni dependencias. No cambiar la ExecutionPolicy: si bloquea, pedir permiso para `-ExecutionPolicy Bypass` **solo en esa invocacion**.
5. No ejecutar comandos fuera de los scripts de esta skill ni comandos que no esten en el plan aprobado.
6. No afirmar respaldo, punto de restauracion o reversion sin verificacion del script.
7. Equipos corporativos, escolares o administrados: solo verificaciones, salvo autorizacion corporativa verificable (ver Paso 0).
8. Acciones prohibidas aunque el usuario insista: ver `references/safety-policy.md`. Rechazar brevemente y ofrecer la alternativa segura.

## Flujo de trabajo

### Paso 0 - Alcance
- Confirmar Windows 10/11 y que el usuario es responsable del equipo.
- **Pedir la carpeta de reportes** (debe existir, p. ej. `D:\Auditorias\2026-10-18`). No usar la raiz de un disco, `Documentos`, `Escritorio` ni carpetas del sistema.
- **Modo de operacion**:
  - `asistido` (predeterminado): aprobacion por identificador.
  - `tecnico`: requiere numero de ticket. Agrega un paquete `P-...` aprobable con un solo identificador, que solo incluye acciones de riesgo bajo, sin red, reversibles y sin punto de restauracion obligatorio.
- **Equipo corporativo**: los cambios solo se permiten si TI desplego `%ProgramData%\WindowsPerformanceAuditor\org-authorization.json`.
  - El archivo debe pertenecer a Administradores o SYSTEM y no ser escribible por usuarios.
  - Su contenido: dominio o tenant, ticket, tecnico, vencimiento y tipos de accion permitidos.
  - Un archivo creado por el usuario en otra carpeta no sirve.
- **Inventario de programas**: preguntar si autoriza `-IncludeAppUsage`, que calcula el ultimo uso por programa a partir de los rastros de ejecucion de Windows, sin guardar historial. Sin ese permiso no se proponen desinstalaciones.

### Paso 1 - Identificacion del equipo (siempre primero; solo lectura, segundos)
```powershell
powershell.exe -NoProfile -File "<skill>\scripts\identify-system.ps1" -OutputDir "<carpeta>"
```
- Identifica fabricante, modelo y tipo de equipo; Windows; BIOS y su antiguedad; CPU; RAM con modulos y ranuras libres; GPU; discos (incluido HDD con Optane) y espacio; bateria; si el equipo esta administrado y si la consola esta elevada.
- **Mostrar al usuario el resumen** ("este es tu equipo") y la **estrategia segun componentes** antes de seguir.
- El **plan de diagnostico** que imprime define en que enfocarse y con que opciones recolectar. Por ejemplo: portatil -> `-IncludeBatteryReport`; RAM baja -> `-LeakWatchMinutes 10`; sin administrador -> avisar que datos faltaran. Usar esas opciones en el Paso 2, no opciones genericas.
- Guarda `system-profile.json` en la carpeta de reportes.

### Paso 2 - Recoleccion guiada por el plan (solo lectura)
```powershell
powershell.exe -NoProfile -File "<skill>\scripts\collect-baseline.ps1" -OutputDir "<carpeta>" <opciones del plan>
powershell.exe -NoProfile -File "<skill>\scripts\hardware-health.ps1"  -OutputDir "<carpeta>" <opciones del plan>
```
- `-IncludeAppUsage` solo con consentimiento del usuario.
- `-LeakWatchMinutes N` observa N minutos la memoria de los procesos de mayor consumo. El agente nunca cierra procesos, solo informa.
- Sin administrador, Prefetch no esta disponible y muchos programas quedaran con "uso desconocido", por lo que no se propondran. Si el usuario quiere mejor evidencia, puede repetir la recoleccion en una consola elevada que abra el mismo.

### Paso 3 - Analisis
```powershell
powershell.exe -NoProfile -File "<skill>\scripts\analyze-performance.ps1" -BaselinePath "<carpeta>\baseline.json" -HardwarePath "<carpeta>\hardware-health.json" -OutputDir "<carpeta>"
```
- Presentar primero el **perfil del equipo y su estrategia** (hallazgo `PROFILE`).
- Luego los hallazgos por categoria: software-corregible, configuracion-optimizable, capacidad-insuficiente, posible-hardware, limitacion-estructural y evidencia-insuficiente.
- Para cada hallazgo de **hardware o estructural**:
  - mostrar la evidencia;
  - explicar que puede y que no puede hacer el agente;
  - recomendar respaldo si hay riesgo para los datos;
  - indicar la prueba manual o el servicio tecnico necesario;
  - **no prometer** que una optimizacion de software lo resuelva.

### Paso 4 - Propuesta (no ejecuta nada)
```powershell
powershell.exe -NoProfile -File "<skill>\scripts\propose-actions.ps1" -FindingsPath "<carpeta>\findings.json" -BaselinePath "<carpeta>\baseline.json" -OutputDir "<carpeta>" [-OperationMode tecnico -Ticket INC-123 -Technician <id>] [-IncludeRestorePoint]
```
Mostrar `action-plan.md` completo. Cada accion incluye:
- identificador, hallazgo y evidencia;
- comando exacto y objetivo exacto;
- elementos afectados y beneficio;
- riesgo, administrador, reinicio y red;
- respaldo y reversion (marcada **SIN REVERSION CONFIABLE** cuando aplique);
- validacion posterior.

Si hay desinstalaciones o reparaciones, el plan antepone un punto de restauracion obligatorio.

**Detenerse** y pedir aprobacion. Respuestas validas:
- `Apruebo A-1a2b3c4d-002`;
- en modo tecnico, `Apruebo paquete P-1a2b3c4d-01`.

Las acciones de riesgo medio se aprueban de a una.

### Paso 5 - Aplicacion (solo lo aprobado, una accion por invocacion)
```powershell
powershell.exe -NoProfile -File "<skill>\scripts\apply-approved-action.ps1" -PlanPath "<carpeta>\action-plan.json" -SessionId <SessionId> -ActionId <ActionId> -Target "<objetivo exacto del plan>" -ApprovalText "<mensaje literal del usuario>" -Apply
```
- Orden recomendado: `CREATE-RESTORE-POINT` primero, despues las acciones de riesgo bajo y al final las de riesgo medio, de a una.
- Codigos de salida:
  - 10: simulacion (falto `-Apply`).
  - 3: rechazado. Informar el motivo y **no** sortearlo.
  - 4: la validacion fallo. **Detenerse** y proponer la reversion.
- Si la accion requiere administrador y la consola no lo es, pedir al usuario que abra una consola elevada. El script nunca se autoeleva.
- Actualizaciones de aplicaciones: primero se aplica `APP-UPDATE-CHECK` y despues se vuelve a ejecutar `propose-actions.ps1 -WingetUpgradesPath "<carpeta>\winget-upgrades.json"`, lo que genera un plan nuevo con una accion `APP-UPDATE` por aplicacion. Los controladores se actualizan siempre manualmente desde el fabricante.
- Reparaciones: solo despues de una verificacion. Usar `-SfcViolationsConfirmed` o `-ComponentStoreCorrupted` en propose cuando el usuario confirme el resultado.

### Paso 6 - Validacion e informe de servicio
```powershell
powershell.exe -NoProfile -File "<skill>\scripts\collect-baseline.ps1" -OutputDir "<carpeta>" -FileName baseline-after.json
powershell.exe -NoProfile -File "<skill>\scripts\validate-results.ps1" -OutputDir "<carpeta>" -BeforePath "<carpeta>\baseline.json" -AfterPath "<carpeta>\baseline-after.json"
powershell.exe -NoProfile -File "<skill>\scripts\service-report.ps1" -OutputDir "<carpeta>" [-Client "<cliente>"] [-Technician "<id>"]
```
- El tiempo de arranque se mide de nuevo despues de reiniciar.
- Codigo 5 en `validate-results` = regresion: detenerse y proponer la reversion (`apply-approved-action.ps1 ... -Rollback -Apply`, con aprobacion de "revertir <ActionId>").
- Entregar `service-report.html`, o `service-report-shareable.html` si se comparte.

## Acciones disponibles (allowlist)

| Tipo | Riesgo | Admin | Red | Reversion |
|---|---|---|---|---|
| VERIFY-SFC, VERIFY-DISM-CHECKHEALTH, DISK-SCAN | Bajo | Si | No | No aplica (lectura) |
| POWER-SET-SCHEME | Bajo | No | No | Confiable |
| STARTUP-DISABLE-USER-RUN / -MACHINE-RUN / -USER-FOLDER / -COMMON-FOLDER | Bajo | No / Si | No | Confiable |
| VISUAL-EFFECTS-PERFORMANCE | Bajo | No | No | Confiable |
| STARTUP-DISABLE-PACKAGED (inicio de apps de la Tienda) | Bajo | No | No | Confiable |
| BACKGROUND-APP-DISABLE (apps de la Tienda) | Bajo | No | No | Confiable |
| HIBERNATION-OFF (solo escritorios) | Bajo | Si | No | Confiable |
| TASK-DISABLE-ORPHAN | Bajo | Si | No | Confiable |
| DISK-OPTIMIZE (TRIM en SSD, Defrag en HDD) | Bajo | Si | No | No requiere |
| CREATE-RESTORE-POINT | Bajo | Si | No | Se verifica que exista |
| DEFENDER-SCAN | Bajo | Si | **Si** | Cuarentena restaurable |
| APP-UPDATE-CHECK | Bajo | No | **Si** | No aplica (lectura) |
| SERVICE-DISABLE-ORPHAN | Medio | Si | No | Confiable |
| CLEANUP-USER-TEMP / -WINDOWS-TEMP / -WER / -DELIVERY-OPTIMIZATION | Medio | No / Si | No | **Sin reversion** |
| COMPONENT-CLEANUP | Medio | Si | No | **Sin reversion** |
| APP-UNINSTALL (> 6 meses sin uso, punto de restauracion obligatorio) | Medio | Si | No | **Sin reversion confiable** |
| APP-UPDATE | Medio | No | **Si** | **Sin reversion confiable** |
| REPAIR-SFC-SCANNOW, REPAIR-DISM-RESTOREHEALTH | Medio | Si | No / **Si** | **Sin reversion confiable** |

Cualquier otro cambio se entrega como recomendacion manual, no como comando.

## Casos limite
- Piden desactivar Defender, Windows Update o la paginacion "para ganar velocidad": rechazar, explicar el riesgo y ofrecer la auditoria.
- Piden un debloat o un script de internet: rechazar. Ofrecer recorte de inicio y desinstalacion de programas sin uso con su desinstalador oficial.
- "Desinstala lo que no uso" sin evidencia: solo se proponen programas con mas de 6 meses sin uso demostrado. "Uso desconocido" no se desinstala.
- Piden desinstalar runtimes, drivers, utilidades del fabricante o VPN: estan protegidos; explicar por que.
- "Desfragmenta mi SSD": no se hace; se propone TRIM.
- Piden desactivar la hibernacion en un portatil: no se hace.
- "Libera la RAM" o "usa un limpiador de memoria": no se hace (empeora el rendimiento). Se ofrece detectar fugas y quitar procesos de inicio y de segundo plano.
- Punto de restauracion rechazado por Windows (limite de 24 h): se acepta un punto existente de menos de 24 h solo si es anterior a todo cambio de la sesion, y se informa cual.
- Disco con senales de falla: priorizar el respaldo antes de cualquier otra accion; no ejecutar reparaciones con escritura.
- Aprobacion ambigua ("si, las de bajo riesgo"): pedir identificadores concretos o el identificador del paquete.
- Nueva sesion o plan expirado: regenerar el plan y pedir aprobacion de nuevo.
