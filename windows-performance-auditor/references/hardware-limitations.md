# Limitaciones de hardware

Principio: **una optimizacion de software no repara hardware**. Ante senales fisicas, el agente muestra la evidencia, explica lo que puede y no puede hacer, recomienda respaldo cuando hay riesgo de datos e indica la prueba manual o el servicio tecnico.

## Que puede y que no puede hacer el agente
| Puede | No puede |
|---|---|
| Leer estado SMART/confiabilidad expuesto por Windows | Reparar o reemplazar componentes |
| Contar eventos WHEA, disco, energia, throttling | Medir temperatura real sin sensores accesibles |
| Calcular salud de bateria si Windows la expone | Modificar BIOS/UEFI, firmware, voltajes, overclock |
| Recomendar respaldo y pruebas del fabricante | Ejecutar pruebas que reinicien el equipo sin decision del usuario |
| Informar "no disponible" cuando falta un dato | Instalar herramientas para obtener metricas |

## Senales y respuesta
### SSD/HDD degradado
- Evidencia: `HealthStatus` distinto de Healthy, `Wear` >= 70%, `ReadErrorsUncorrected` > 0, SMART `PredictFailure`, eventos disk 7/11/51/153, Ntfs 55/98.
- Respuesta: **respaldar de inmediato**; diagnostico del fabricante; reemplazo por servicio tecnico. No ejecutar `chkdsk /r` ni escrituras masivas sin respaldo.

### Errores de memoria
- Evidencia: eventos WHEA-Logger, resultados de MemoryDiagnostics, pantallazos azules recurrentes.
- Respuesta: `mdsched.exe` manual (reinicia) o prueba del fabricante; desactivar perfiles XMP inestables desde BIOS solo por el usuario/servicio tecnico.

### Throttling termico / refrigeracion deficiente
- Evidencia: Kernel-Processor-Power 37 y frecuencia promedio < 50% del maximo bajo carga. Las zonas termicas ACPI no se usan: suelen entregar valores fijos o ficticios.
- Respuesta: limpieza de polvo, revision de ventiladores y pasta termica por servicio tecnico; usar sobre superficie dura; cargador original.

### Bateria deteriorada
- Evidencia: capacidad completa / capacidad de diseno < 70% (alto si < 50%), ciclos altos.
- Respuesta: reemplazo con servicio autorizado. Bateria hinchada: dejar de usar y desconectar.

### Apagados inesperados
- Evidencia: Kernel-Power 41 repetidos, EventLog 6008.
- Respuesta: descartar apagados forzados por el usuario; revisar fuente/cargador, temperatura, BugCheck.

### Programas del fabricante
- Utilidades OEM (Lenovo, HP, Dell, ASUS...) controlan teclas de funcion, ventiladores, umbrales de carga y firmware. Nunca se proponen para desinstalacion automatica.

### Componentes insuficientes (limitacion estructural)
- RAM < 8 GB, 2 o menos procesadores logicos, Windows sobre HDD, disco del sistema <= 128 GB.
- Respuesta: explicar que ninguna configuracion compensa el limite; sugerir ampliacion (verificar si RAM/disco son reemplazables en el manual) o ajustar expectativas de uso.

## Confiabilidad de las fuentes
| Fuente | Confiabilidad | Nota |
|---|---|---|
| Get-PhysicalDisk HealthStatus | Media-Alta | Resumen del controlador |
| Get-StorageReliabilityCounter | Media | Requiere admin en muchos equipos; campos vacios = no disponible |
| MSStorageDriver_FailurePredictStatus | Media | Requiere admin; no siempre en NVMe |
| BatteryStaticData / batteryreport | Media-Alta | Depende del firmware |
| Eventos del sistema | Alta para existencia, baja para causa | Correlacionar antes de concluir |
