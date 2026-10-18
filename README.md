# windows-performance-auditor

Agent Skill (estandar `SKILL.md`, compatible con Claude Code y Codex) que actua como tecnico de soporte TI para optimizar PCs con Windows 10/11:

- Audita en modo **audit-only** (solo lectura, sin red, sin instalar nada).
- Adapta la optimizacion a los componentes del equipo (HDD/SSD/NVMe, RAM, CPU, portatil/escritorio).
- Separa problemas de software, configuracion, capacidad insuficiente y posibles fallas de hardware.
- Desinstala solo programas con **mas de 6 meses sin uso demostrado** y sin dependencias, previo punto de restauracion verificado.
- Ejecuta unicamente acciones de una allowlist, **aprobadas una por una por identificador**, con respaldo del estado previo, validacion posterior y reversion cuando existe.
- Genera un informe de servicio con metricas antes/despues (arranque, CPU, memoria, confiabilidad, espacio).

La skill esta en [`windows-performance-auditor/`](windows-performance-auditor/). Empieza por [`SKILL.md`](windows-performance-auditor/SKILL.md) y [`references/safety-policy.md`](windows-performance-auditor/references/safety-policy.md).

## Requisitos

- Windows 10 u 11 con Windows PowerShell 5.1 (incluido en Windows). PowerShell 7 es opcional.
- Claude Code o Codex.
- Ninguna dependencia adicional.

## Instalacion en otro PC

Clonar con git (recomendado: los archivos clonados no quedan bloqueados por la marca de "descargado de internet"):

```powershell
git clone https://github.com/kepler33i/windows-performance-auditor.git
```

Copiar la carpeta de la skill al directorio de skills del agente:

```powershell
# Claude Code (todas las sesiones del usuario)
Copy-Item -Recurse .\windows-performance-auditor\windows-performance-auditor "$env:USERPROFILE\.claude\skills\"

# Codex
Copy-Item -Recurse .\windows-performance-auditor\windows-performance-auditor "$env:USERPROFILE\.codex\skills\"
```

Tambien puede usarse a nivel de proyecto copiandola en `.claude/skills/` del repositorio de trabajo.

### Politica de ejecucion

La skill **nunca** cambia la ExecutionPolicy.
- Si el equipo tiene `RemoteSigned` (habitual), los scripts clonados con git se ejecutan sin cambios.
- Si se descargo como ZIP, Windows marca los archivos como descargados y `RemoteSigned` los bloquea. En ese caso, el propietario del equipo puede desbloquear **solo** la carpeta de la skill despues de revisarla (`Get-ChildItem -Recurse <carpeta> | Unblock-File`), o permitir `-ExecutionPolicy Bypass` en una invocacion puntual.
- Con `Restricted` (por defecto en algunas ediciones), el agente pedira permiso para usar `-ExecutionPolicy Bypass` solo en esa invocacion de proceso.

## Uso

Pidele al agente, por ejemplo: *"Mi PC con Windows anda lento, auditalo"*. El agente:

1. Pide la carpeta donde guardar reportes y si autorizas el inventario de programas.
2. **Identifica el equipo y sus componentes** (modelo, Windows, BIOS, CPU, RAM y ranuras, GPU, discos, bateria) y define un plan de diagnostico adaptado a ese hardware.
3. Recolecta datos segun ese plan (solo lectura) y analiza.
4. Muestra los hallazgos y un plan con comandos exactos, riesgos y reversion.
5. **Se detiene** hasta que apruebes identificadores concretos (`Apruebo A-xxxxxxxx-001`) o el paquete de bajo riesgo.
6. Aplica una accion por vez, valida cada resultado y genera el informe de servicio.

"Optimiza mi computador" no autoriza cambios: solo inicia la auditoria.

### Modo tecnico y equipos corporativos

- `-OperationMode tecnico -Ticket <id>` habilita paquetes (`P-...`) que agrupan solo acciones de riesgo bajo, sin red y reversibles.
- En equipos administrados (dominio, Entra ID, MDM), los cambios requieren una autorizacion desplegada por TI en `%ProgramData%\WindowsPerformanceAuditor\org-authorization.json`, protegida por ACL. Ver [`safety-policy.md`](windows-performance-auditor/references/safety-policy.md).

## Pruebas

No modifican el equipo: usan datos simulados, y las rutas de ejecucion se prueban con la ejecucion suprimida.

```powershell
powershell.exe -NoProfile -File .\windows-performance-auditor\tests\test-readonly.ps1
```

## Estructura

```
windows-performance-auditor/
  SKILL.md                    instrucciones del agente
  scripts/                    recoleccion, analisis, propuesta, aplicacion, validacion, informe
  scripts/lib/                modulos: core, plan, catalog (allowlist), inventory
  references/                 politica de seguridad, riesgos, reglas, perfiles, desinstalacion
  assets/                     plantillas HTML de reportes
  tests/                      pruebas no destructivas y prompts de evaluacion
```

## Limitaciones

- Sin administrador, la evidencia de uso de programas es limitada y muchos quedan como "uso desconocido", por lo que no se proponen para desinstalar.
- Las temperaturas reales no se leen sin herramientas del fabricante.
- La sanitizacion de reportes compartibles se basa en patrones: revisarlos antes de compartirlos.
