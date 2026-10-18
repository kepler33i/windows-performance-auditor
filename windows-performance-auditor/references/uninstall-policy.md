# Politica de desinstalacion

Regla del usuario: **solo se desinstala lo que lleva mas de 6 meses sin uso, y sin romper nada**. La implementacion es `Test-WpaUninstallCandidate` (`scripts/lib/inventory.ps1`). Si falta evidencia, el programa **no** se propone.

## Requisitos (todos obligatorios)
1. **Desinstalador oficial valido**
   - MSI: `msiexec.exe /x {GUID} /passive /norestart`.
   - EXE: el desinstalador registrado, que debe existir en disco y estar dentro de la carpeta del programa, `Program Files`, `Program Files (x86)`, `ProgramData\Package Cache` o `%LOCALAPPDATA%\Programs`.
   - Se rechazan `cmd`, `powershell`, `rundll32`, `mshta`, `wscript`, `regsvr32` y similares, los metacaracteres de consola y la marca `NoRemove`.
2. **Carpeta de instalacion conocida**: sin ella no se puede verificar uso ni dependencias.
3. **Instalado hace 180 dias o mas.** Se usa la fecha de instalacion registrada o, si falta, la fecha de creacion de la carpeta.
4. **Sin uso hace 180 dias o mas, con evidencia**:
   - *Alta*: Prefetch de Windows (requiere administrador). Ultima ejecucion de cualquier `.exe` de la carpeta del programa. Si no hay ejecuciones y Prefetch cubre 180 dias o mas, se considera "sin ejecuciones" con evidencia alta.
   - *Media*: UserAssist del usuario actual (programas abiertos desde el Explorador).
   - *Desconocida*: no se propone. La recoleccion con administrador mejora la cobertura.
5. **No pertenece a categorias protegidas**: runtimes y frameworks (.NET, Visual C++, DirectX, Java), drivers y software de hardware (Intel, AMD, NVIDIA, Realtek, audio, touchpad), utilidades del fabricante del equipo (Lenovo, HP, Dell, ASUS...), seguridad, VPN, respaldo, sincronizacion (OneDrive, Dropbox), acceso remoto, herramientas de desarrollo (Python, Git, Node, Visual Studio), impresoras y escaneres, virtualizacion, Office y cualquier programa publicado por Microsoft.
5b. **Sin contraevidencia de uso**:
   - Ningun `.exe` de su carpeta fue modificado en los ultimos 180 dias. Muchas apps (por ejemplo las basadas en Squirrel/Electron) solo se actualizan mientras se ejecutan, y Prefetch puede no registrarlo.
   - No esta anclado a la barra de tareas.
   - Motivo: una app puede no tener rastro en Prefetch y aun asi haberse actualizado varias veces (varias carpetas de version) o estar anclada, senales claras de que se usa.
5c. **Sin datos del usuario en su carpeta**:
   - No se proponen servidores locales ni bases de datos (XAMPP, WAMP, Laragon, MySQL, PostgreSQL...).
   - Tampoco programas cuya carpeta contenga subcarpetas de datos con archivos (`htdocs`, `www`, `data`, `mysql\data`, `projects`, `saves`...), porque su desinstalador podria borrarlos.
5d. **Confirmacion del usuario**: el agente pregunta si usa cada programa antes de pedir la aprobacion. La evidencia tecnica no reemplaza su criterio.
6. **Sin dependencias activas**: ningun proceso en ejecucion, servicio o driver desde su carpeta, ni entrada de inicio habilitada, y su carpeta no se comparte con otro programa.

## Ejecucion
- Antes, y de forma obligatoria: `CREATE-RESTORE-POINT` **validado** en la misma sesion. Sin el, `apply` rechaza.
- Riesgo medio: aprobacion individual (un identificador por mensaje). Nunca va en paquetes.
- Al ejecutar se revalida en vivo: huella del programa (nombre, version y desinstalador), desinstalador identico al aprobado, sin procesos ni servicios.
- Se guarda el inventario completo de programas y el conteo de dispositivos con error.
- Despues se valida:
  - el programa ya no figura;
  - **ningun otro programa desaparecio**, salvo sus propios componentes (mismo nombre o dentro de su carpeta);
  - no aumentaron los dispositivos con error.
- Ante regresion: detenerse e informar. La reversion es reinstalar desde el instalador oficial, o Restaurar sistema (`rstrui.exe`) al punto verificado, lo que recupera registro y sistema pero no los datos de la aplicacion.

## Nunca
- Borrar carpetas de programas en lugar de usar su desinstalador.
- Desinstalar aplicaciones de la Tienda o del sistema (`Remove-AppxPackage` esta prohibido).
- Desinstalar en lote o con aprobaciones generales.
- Proponer programas con "uso desconocido".
