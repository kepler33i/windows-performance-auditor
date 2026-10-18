# Optimizacion segun componentes

`analyze-performance.ps1` calcula un perfil (`Get-WpaHardwareProfile` en `scripts/lib/inventory.ps1`) y elige las acciones con el. El perfil aparece como hallazgo `PROFILE` y en los reportes.

## Clasificacion
| Dimension | Valores | Fuente |
|---|---|---|
| Disco del sistema | HDD, SSD, NVMe, desconocido | `Get-PhysicalDisk` (MediaType, BusType) |
| RAM | bajo (< 7.5 GB), medio (< 15.5 GB), alto | `Win32_OperatingSystem` |
| CPU | bajo (<= 4 hilos), medio (<= 8), alto | `Win32_Processor` |
| Tipo de equipo | portatil, escritorio, desconocido | `PCSystemType`, `ChassisTypes`, bateria |
| GPU | integrada, dedicada, desconocido | nombre del adaptador |
| Gama baja (`LowEnd`) | HDD, o RAM baja, o CPU baja | combinacion |

## Que se propone segun el perfil
| Situacion | Accion | Por que |
|---|---|---|
| HDD | `DISK-OPTIMIZE` modo Defrag (si la optimizacion programada tiene > 30 dias); priorizar recorte de inicio | El disco mecanico es el cuello de botella; la mejora definitiva es SSD (recomendacion manual) |
| HDD + Intel Optane (RST) | Ninguna optimizacion de disco (Windows lo reporta como SSD/RAID; la cache la gestiona RST); tratar como HDD en umbrales y estrategia | Sigue siendo mecanico; TRIM o Defrag sobre el volumen virtual no corresponden |
| SSD / NVMe | `DISK-OPTIMIZE` modo ReTrim (si > 30 dias) | Nunca desfragmentar un SSD; `apply` lo rechaza aunque el plan lo pida |
| Gama baja | `VISUAL-EFFECTS-PERFORMANCE`; recorte de inicio desde 4 programas | Animaciones y transparencias consumen recursos escasos |
| RAM baja / commit alto | Recorte de inicio, desinstalar lo que no se usa; recomendar ampliacion | Ninguna configuracion compensa falta de RAM |
| Escritorio con hibernacion | `HIBERNATION-OFF` | Libera hiberfil.sys y evita problemas del inicio rapido |
| Portatil | Nunca `HIBERNATION-OFF` (`apply` lo rechaza si hay bateria); revisar bateria y temperatura | La hibernacion protege la sesion ante bateria agotada |
| Plan Economizador | `POWER-SET-SCHEME` a Equilibrado | Equilibrado ya entrega maximo rendimiento bajo carga en CPUs modernas |
| Arranque lento | Recorte de inicio + medicion antes/despues | Referencia: < 60 s en SSD, < 120 s en HDD |
| Defender atrasado | `DEFENDER-SCAN` | Descartar malware antes de culpar al hardware |
| Poco espacio | Limpieza por categoria, `COMPONENT-CLEANUP`, cache de Optimizacion de distribucion | Windows necesita espacio para actualizar y paginar |

## Lo que nunca se hace por perfil
- Plan "Alto rendimiento" o "Rendimiento maximo" en portatiles.
- Desactivar servicios "para ganar rendimiento".
- Reducir o desactivar el archivo de paginacion, aunque haya mucha RAM.
- Overclock, voltajes, XMP o cambios de BIOS.
- Actualizar controladores automaticamente (siempre manual desde el fabricante).
