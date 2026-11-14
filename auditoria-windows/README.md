# Auditoría de seguridad de un equipo Windows

Script para revisar la seguridad de un equipo Windows desde un USB. Lanza todas las comprobaciones de una vez y guarda los resultados en el propio USB.

> **Solo lectura.** El script no cambia ninguna configuración, no abre ni lista archivos de clientes y no guarda la clave de recuperación de BitLocker. Lo único opcional es el análisis rápido de Defender, que puede poner en cuarentena una amenaza si la encuentra.

> **Solo con permiso por escrito** del dueño del equipo.

## Archivos

| Archivo | Para qué sirve |
|---------|----------------|
| `EJECUTAR-AUDITORIA.bat` | Doble clic aquí. Pide permisos de administrador y lanza el script |
| `auditoria.ps1` | El script con todas las comprobaciones |

## Preparar el USB

1. Descarga la carpeta `auditoria-windows` (en GitHub: **Code > Download ZIP**) y descomprímela.
2. Copia `EJECUTAR-AUDITORIA.bat` y `auditoria.ps1` a la raíz del USB o a una carpeta del USB, **los dos juntos**.
3. Si descargaste el ZIP de internet, en tu equipo haz clic derecho en `auditoria.ps1` > **Propiedades** > marca **Desbloquear** > Aceptar.

## Usarlo en el equipo del cliente

1. Conecta el USB con el cliente delante. Que él inicie sesión.
2. Doble clic en `EJECUTAR-AUDITORIA.bat` > **Sí** en la ventana de permisos.
   - Si su cuenta no es administradora, Windows pedirá usuario y contraseña de un administrador: que los escriba él.
3. El script hace dos preguntas:
   - **Ruta de la carpeta de clientes** (ej. `C:\Users\Ana\Documents\Clientes`). Solo revisa *quién tiene acceso*, no mira los archivos. Enter para omitir.
   - **¿Análisis rápido de Defender?** `s` o `n`. Tarda entre 5 y 15 minutos.
4. Espera a que salga el **RESUMEN** en colores y pulsa una tecla.
5. Expulsa el USB de forma segura.

Si Windows SmartScreen o el antivirus bloquean el `.bat`, abre **PowerShell como administrador** y ejecuta:

```powershell
cd E:\            # la letra de tu USB
powershell -ExecutionPolicy Bypass -File .\auditoria.ps1
```

## Resultados

Se crean en `resultados\NOMBREPC_fecha\` dentro del USB:

| Archivo | Contenido |
|---------|-----------|
| `00-RESUMEN.txt` | **Empieza por aquí.** Todos los hallazgos ordenados de más a menos grave |
| `00-resumen.csv` | Lo mismo, para abrir en Excel y hacer el informe |
| `01-sistema-actualizaciones.txt` | Versión de Windows y parches |
| `02-cuentas-contrasenas.txt` | Usuarios, administradores, política de contraseñas |
| `03-cifrado-disco.txt` | BitLocker, TPM, Secure Boot |
| `04-antivirus-firewall.txt` | Defender, amenazas, firewall, UAC |
| `05-red.txt` | IP, puertos abiertos, carpetas compartidas, SMBv1, escritorio remoto |
| `06-permisos-carpetas-clientes.txt` | Quién tiene acceso a la carpeta de clientes |
| `07-programas.txt` | Inicio, tareas programadas, software, programas de control remoto |
| `08-copias-seguridad.txt` | Puntos de restauración, OneDrive/Dropbox |
| `09-bloqueo-pantalla.txt` | Bloqueo automático |
| `10-analisis-antivirus.txt` | Solo si se lanzó el análisis rápido |
| `99-consola-completa.txt` | Todo lo que salió por pantalla |

### Qué significa cada estado

| Estado | Significado |
|--------|-------------|
| `MAL` | Arreglar cuanto antes |
| `REVISAR` | Puede estar bien si es intencionado. Preguntar al cliente |
| `MANUAL` | El script no puede comprobarlo, hay que hacerlo a mano o preguntando |
| `ERROR` | El script no pudo comprobarlo |
| `OK` | Correcto |

## Después del script

- **Desde tu equipo**, con la IP que aparece en `05-red.txt`: `nmap -sV IP_DEL_CLIENTE` (solo esa IP).
- Revisa a mano todo lo marcado como `MANUAL`.
- Antes de compartir los resultados con nadie (o pegarlos en una IA), quita nombres de usuario, rutas con nombres de clientes y cualquier dato personal.
- Arregla los problemas **junto al cliente** y con una copia de seguridad hecha.

## Limitaciones

- Pensado para Windows 10/11 con PowerShell 5.1 (el que viene de serie).
- Si el script se lanza con una cuenta de administrador distinta de la del cliente, los datos de "bloqueo de pantalla", "Historial de archivos" y `winget` son los de esa cuenta.
- No sustituye a una auditoría profesional si los datos son muy sensibles (médicos, legales, financieros).
