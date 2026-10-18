# Matriz de riesgo

## Niveles
| Nivel | Definicion | Aprobacion |
|---|---|---|
| Bajo | Solo lectura, o cambio con reversion confiable y verificada | Identificador explicito; en modo tecnico, tambien el paquete (si ademas no usa red) |
| Medio | Cambio sin reversion confiable, sobre servicios o sobre archivos/programas | Individual: un solo identificador por mensaje; nunca en paquetes |
| Alto | Puede causar perdida de datos, inestabilidad o exposicion | **Ninguna accion automatizada es de riesgo alto**; se recomiendan manualmente |
| Prohibido | Ver `safety-policy.md` | No disponible |

Regla del catalogo (verificada por las pruebas): toda accion que modifica sin reversion confiable, o que exige punto de restauracion, es al menos de riesgo medio.

## Acciones de la allowlist
| Tipo | Riesgo | Modifica | Admin | Red | Respaldo previo | Reversion | Validacion |
|---|---|---|---|---|---|---|---|
| VERIFY-SFC | Bajo | No | Si | No | - | No aplica | Codigo + CBS.log |
| VERIFY-DISM-CHECKHEALTH | Bajo | No | Si | No | - | No aplica | Codigo |
| DISK-SCAN (`chkdsk /scan`) | Bajo | No | Si | No | - | No aplica | Codigo 0/3 |
| APP-UPDATE-CHECK | Bajo | No | No | Si | - | No aplica | winget-upgrades.json |
| POWER-SET-SCHEME | Bajo | Si | No | No | GUID previo | `powercfg /setactive <previo>` | Plan activo |
| STARTUP-DISABLE-USER-RUN | Bajo | Si (HKCU) | No | No | Valor previo | Restaurar/quitar | Byte impar, Run intacto |
| STARTUP-DISABLE-MACHINE-RUN | Bajo | Si (HKLM) | Si | No | Valor previo | Restaurar/quitar | Byte impar, Run intacto |
| STARTUP-DISABLE-USER-FOLDER | Bajo | Si (HKCU) | No | No | Valor previo | Restaurar/quitar | Byte impar, acceso directo intacto |
| STARTUP-DISABLE-COMMON-FOLDER | Bajo | Si (HKLM) | Si | No | Valor previo | Restaurar/quitar | Byte impar, acceso directo intacto |
| STARTUP-DISABLE-PACKAGED | Bajo | Si (HKCU) | No | No | State previo | Restaurar State | State = 1 |
| BACKGROUND-APP-DISABLE | Bajo | Si (HKCU) | No | No | 2 valores previos | Restaurar/quitar | Disabled = 1 y DisabledByUser = 1 |
| VISUAL-EFFECTS-PERFORMANCE | Bajo | Si (HKCU) | No | No | 4 valores previos | Restaurar/quitar cada uno | Valores |
| HIBERNATION-OFF | Bajo | Si | Si | No | Estado previo | `powercfg /hibernate on` | HibernateEnabled = 0 |
| TASK-DISABLE-ORPHAN | Bajo | Si | Si | No | Estado previo | `Enable-ScheduledTask` | Disabled |
| DISK-OPTIMIZE | Bajo | Si (sin datos) | Si | No | - | No requiere | Sin error; rechazado en volumenes RAID u Optane |
| CREATE-RESTORE-POINT | Bajo | Si | Si | No | Es el respaldo | No requiere | `Get-ComputerRestorePoint` |
| DEFENDER-SCAN | Bajo | Si (cuarentena) | Si | Si | - | Restaurar cuarentena manual | QuickScanAge = 0 |
| SERVICE-DISABLE-ORPHAN | Medio | Si | Si | No | Tipo de inicio previo | `Set-Service -StartupType <previo>` | Disabled |
| CLEANUP-USER-TEMP | Medio | Si | No | No | Lista de eliminados | **Ninguna** | Espacio libre |
| CLEANUP-WINDOWS-TEMP | Medio | Si | Si | No | Lista de eliminados | **Ninguna** | Espacio libre |
| CLEANUP-WER | Medio | Si | Si | No | Lista de eliminados | **Ninguna** | Espacio libre |
| CLEANUP-DELIVERY-OPTIMIZATION | Medio | Si | Si | No | - | **Ninguna** | Sin error |
| COMPONENT-CLEANUP | Medio | Si | Si | No | - | **Ninguna** | Codigo 0 |
| APP-UNINSTALL | Medio | Si | Si | No | Punto de restauracion validado + inventario | **No confiable** (reinstalar / rstrui) | Programa ausente; ningun otro desaparecio; sin nuevos dispositivos con error |
| APP-UPDATE | Medio | Si | No | Si | Version previa | **No confiable** | Codigo 0 |
| REPAIR-SFC-SCANNOW | Medio | Si | Si | No | Punto de restauracion validado | **No confiable** | VERIFY-SFC posterior |
| REPAIR-DISM-RESTOREHEALTH | Medio | Si | Si | Si | Punto de restauracion validado | **No confiable** | CheckHealth posterior |

## Recomendaciones manuales (no automatizadas)
| Recomendacion | Riesgo | Motivo |
|---|---|---|
| Actualizar controladores | Medio-Alto | Requiere elegir el controlador correcto del fabricante |
| Reactivar archivo de paginacion | Bajo | Requiere reinicio; se guia al usuario |
| Diagnostico de memoria (`mdsched`) | Bajo | Reinicia el equipo |
| `chkdsk /r` o reparacion fuera de linea | Medio-Alto | Escritura en disco; respaldo previo obligatorio |
| Desinstalar programas con uso desconocido o protegidos | Medio | Requiere decision informada del usuario |
| Reemplazo de SSD/RAM/bateria, limpieza termica | N/A | Fisico: servicio tecnico |
