#Requires -Version 5.1
<#
  common.ps1 - Cargador de modulos compartidos de windows-performance-auditor.

    lib/core.ps1       utilidades, rutas seguras, reportes, bitacora, sanitizacion, contexto
    lib/plan.ps1       hash del plan, aprobaciones y paquetes, autorizacion corporativa
    lib/catalog.ps1    allowlist de acciones, comando exacto, lectura de estado, validacion
    lib/inventory.ps1  programas y uso, huerfanos, perfil de hardware, winget

  Ningun modulo modifica el sistema. Solo apply-approved-action.ps1 ejecuta cambios.
#>

Set-StrictMode -Version 2.0
foreach ($wpaModule in @('core.ps1', 'plan.ps1', 'catalog.ps1', 'inventory.ps1')) {
    . (Join-Path (Join-Path $PSScriptRoot 'lib') $wpaModule)
}
Remove-Variable -Name wpaModule -ErrorAction SilentlyContinue
