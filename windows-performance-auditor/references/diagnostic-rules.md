# Reglas de diagnostico

Implementadas en `scripts/analyze-performance.ps1` con los mismos `RuleId` (las pruebas verifican que cada regla del codigo este documentada aqui). Umbrales conservadores; una sola muestra tiene confianza baja.

## Categorias
| Categoria | Significado |
|---|---|
| software-corregible | Causa en programas concretos (procesos, inicio, controladores, fallos, temporales, huerfanos, programas sin uso) |
| configuracion-optimizable | Ajuste de Windows (energia, efectos visuales, hibernacion, mantenimiento de disco, paginacion, seguridad, reinicio) |
| capacidad-insuficiente | La carga supera los recursos (RAM, CPU, disco pequeno) |
| posible-hardware | Senales de degradacion fisica (disco, memoria, bateria, throttling, energia) |
| limitacion-estructural | Caracteristica fija del equipo (HDD, poca RAM, CPU de 2 hilos) |
| evidencia-insuficiente | Datos faltantes o no concluyentes; no se infiere |

## Reglas
| RuleId | Condicion | Categoria | Severidad | Accion propuesta |
|---|---|---|---|---|
| BIOS-01 | BIOS/UEFI con 3 anios o mas | configuracion-optimizable | bajo | Manual (actualizar desde el fabricante; la skill no toca firmware) |
| PROFILE | Siempre: perfil de componentes y estrategia | evidencia-insuficiente | info | Orienta el resto (ver optimization-profiles.md) |
| CTX-MANAGED | Dominio, Entra ID, MDM real o Enterprise/Education | evidencia-insuficiente | info | Bloquea cambios sin autorizacion corporativa |
| MEM-01 | Commit >= 80% (alto >= 90%) | capacidad-insuficiente si RAM <= 8 GB; si no software-corregible | medio/alto | Manual |
| MEM-02 | RAM disponible < 10% | capacidad-insuficiente | medio (confianza baja) | Manual |
| MEM-03 | Un grupo de procesos > 30% de la RAM | software-corregible | medio | Manual |
| MEM-04 | Paginas/s >= 1000 | capacidad-insuficiente | bajo | Manual |
| MEM-05 | Evento Resource-Exhaustion 2004 | capacidad-insuficiente | alto | Manual |
| RAM-SPEC | RAM < 7.5 GB | limitacion-estructural | medio/alto | Ninguna |
| PAGE-01 | Sin archivo de paginacion | configuracion-optimizable | medio | Manual (nunca se reduce) |
| CPU-01 | CPU >= 80%: proceso >= 25% => software; <= 4 hilos => capacidad; otro => evidencia | segun caso | alto/medio | Manual |
| CPU-SPEC | <= 2 procesadores logicos | limitacion-estructural | medio | Ninguna |
| PWR-01 | Plan Economizador activo | configuracion-optimizable | medio | POWER-SET-SCHEME |
| HW-THROTTLE | Frecuencia < 50% con CPU >= 50% => posible-hardware (alto). Solo evento 37 => evidencia-insuficiente (bajo), frecuente en portatiles | segun caso | alto/bajo | Manual / servicio tecnico |
| BOOT-01 | Mediana de arranque > 60 s (SSD) o > 120 s (HDD). Con administrador incluye los culpables que identifica Windows (Diagnostics-Performance 101-110) | software si >= 6 programas + apps de inicio; HDD => estructural; si no evidencia | medio | Recorte de inicio (Run y apps de la Tienda) |
| REL-01 | Indice de confiabilidad < 5 | evidencia-insuficiente | medio | Manual (perfmon /rel) |
| VISUAL-01 | Perfil de gama baja | configuracion-optimizable | bajo | VISUAL-EFFECTS-PERFORMANCE |
| DISKOPT-01 | Optimizacion programada > 30 dias o nunca | configuracion-optimizable | bajo | DISK-OPTIMIZE (Defrag en HDD, ReTrim en SSD) |
| HIBER-01 | Escritorio con hibernacion activa | configuracion-optimizable | bajo | HIBERNATION-OFF |
| DEF-01 | Defender activo con analisis > 14 dias o firmas > 7 dias | configuracion-optimizable | bajo | DEFENDER-SCAN (red) |
| DSK-01 | Unidad del sistema < 10% o < 15 GB libres | software-corregible (capacidad si <= 130 GB) | medio/alto | Manual + CLEANUP-02 |
| DSK-02 | Disco del sistema HDD o HDD acelerado con Optane (RST lo reporta como SSD/RAID) | limitacion-estructural | alto | Ninguna (migrar a SSD) |
| DSK-03 | Tiempo de disco >= 90% o cola >= 2 | estructural si HDD; si no evidencia | medio | Manual |
| CLEANUP-01 | Temporales usuario >= 500 MB, Windows >= 500 MB, WER >= 200 MB (> 7 dias) | software-corregible | bajo | CLEANUP-USER-TEMP / -WINDOWS-TEMP / -WER (riesgo medio) |
| CLEANUP-02 | DSK-01 presente | software-corregible | bajo | COMPONENT-CLEANUP, CLEANUP-DELIVERY-OPTIMIZATION |
| ORPHAN-01 | Tarea de terceros cuyo ejecutable no existe | software-corregible | bajo | TASK-DISABLE-ORPHAN (una por una) |
| ORPHAN-02 | Servicio de terceros detenido cuyo ejecutable no existe | software-corregible | bajo | SERVICE-DISABLE-ORPHAN (riesgo medio) |
| APP-UNUSED-01 | Programas que cumplen uninstall-policy.md (> 6 meses sin uso, sin dependencias) | software-corregible | medio | APP-UNINSTALL (punto de restauracion obligatorio) |
| APP-REVIEW | Resumen del inventario: candidatos, protegidos, usados, uso desconocido | evidencia-insuficiente | info | Ninguna |
| APPUPD-01 | winget disponible | configuracion-optimizable | info | APP-UPDATE-CHECK (red) y luego APP-UPDATE por aplicacion |
| HW-DISK | Health != Healthy, desgaste >= 70%, errores no corregidos, PredictFailure | posible-hardware | alto/critico | Respaldo + servicio tecnico |
| HW-DISK-EVENTS | Eventos disk 7/11/51, Ntfs 55/98 de nivel critico/error/advertencia (Ntfs 98 informativo = volumen correcto, no cuenta) | posible-hardware | alto | Respaldo + diagnostico |
| HW-WHEA | WHEA de CPU o memoria (corregidos: medio; fatales o CPU: alto), agrupados por Id/componente con rango de fechas y tasa diaria | posible-hardware | medio/alto | mdsched manual |
| WHEA-PCIE-01 | WHEA PCIe corregidos (AER, p. ej. evento 17), con puerto y dispositivo conectado identificados | configuracion-optimizable | medio | Manual: driver del dispositivo, BIOS, ASPM (estado de vinculo PCIe) |
| HW-BATTERY | Salud < 70% (alto < 50%) | posible-hardware | medio/alto | Servicio tecnico |
| HW-POWER | Kernel-Power 41 >= 3 (1-2 => evidencia-insuficiente) | posible-hardware | medio | Manual |
| SEC-01 | Defender en tiempo real apagado sin otro antivirus | configuracion-optimizable | alto | Manual (reactivar) |
| SEC-02 | Perfil de firewall desactivado | configuracion-optimizable | alto | Manual (reactivar) |
| SEC-03 | > 60 dias sin actualizaciones | configuracion-optimizable | medio | Manual |
| SYS-REBOOT | Reinicio pendiente o > 168 h encendido | configuracion-optimizable | bajo | Manual |
| DRV-01 | Dispositivos con error (excluye codigo 22: deshabilitado por el usuario) | software-corregible | medio | Manual (controlador del fabricante) |
| GPU-01 | Evento Display 4101 (TDR) | software-corregible | medio | Manual |
| APP-01 | Aplicacion con >= 5 fallos | software-corregible | medio | Manual (reparar/actualizar) |
| SYS-INTEGRITY | >= 10 fallos repartidos en >= 3 apps, TDR o Kernel-Power 41 >= 3 | evidencia-insuficiente | bajo | VERIFY-DISM-CHECKHEALTH, VERIFY-SFC, DISK-SCAN |
| STARTUP-01 | >= 8 programas de inicio habilitados (>= 4 en gama baja o RAM baja); incluye carpetas Inicio; solo protege antivirus registrados en Seguridad de Windows | software-corregible | medio | STARTUP-DISABLE-USER-RUN / -MACHINE-RUN por entrada (excluye seguridad, sincronizacion, respaldo, controladores) |
| BGAPP-01 | App de la Tienda con procesos sin ventana, permiso de segundo plano no denegado y no protegida | software-corregible | bajo | BACKGROUND-APP-DISABLE (por app) |
| MEM-LEAK-01 | Con -LeakWatchMinutes: crecimiento >= 200 MB, >= 10 MB/min, en >= 80% de las muestras | software-corregible | medio | Manual (reiniciar/actualizar la app; el agente no cierra procesos) |
| MEM-LEAK-00 | Observacion sin crecimiento sostenido | evidencia-insuficiente | info | Ninguna |
| STARTUP-02 | App de la Tienda con tarea de inicio habilitada (State = 2) y no protegida | software-corregible | medio | STARTUP-DISABLE-PACKAGED (por app) |
| TASK-01 | >= 25 tareas de terceros habilitadas | evidencia-insuficiente | info | Ninguna |
| EVID-01 | Metricas no disponibles o hardware-health no ejecutado | evidencia-insuficiente | info | Repetir sondas con permiso |

## Principios de interpretacion
1. Correlacionar antes de concluir: un evento o una muestra no prueba una falla.
2. Hardware antes que software: si el disco esta degradado, el primer paso es respaldar.
3. Optimizar segun los componentes: no aplicar la misma receta a un HDD con 4 GB que a un NVMe con 32 GB.
4. No atribuir la lentitud a "demasiados servicios" ni recomendar deshabilitarlos.
5. Separar lo que el usuario puede cambiar (software y configuracion) de lo que no (estructural).
6. Lo no medido se informa como "no disponible". El uso desconocido de un programa no equivale a "sin uso".
