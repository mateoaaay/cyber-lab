# auditor-red-casa

Herramienta que revisa la red de casa en busca de los fallos por los que podría colarse alguien, aplica sola los arreglos que se pueden automatizar y deja un informe con lo que hay que cambiar a mano.

> **Proyecto personal de aprendizaje.** No es un producto ni una herramienta profesional de seguridad: no sustituye a una auditoría real y no detecta todos los fallos posibles. Ver [Estado del proyecto](#estado-del-proyecto).

Python 3 sin dependencias externas; solo necesita `nmap` instalado. Pensada para ejecutarse en Linux (Kali o Ubuntu) conectado a la red que se quiere auditar.

## Uso

```bash
sudo apt install nmap
```

```bash
sudo python3 auditor.py
```

```bash
sudo python3 auditor.py --arreglar
```

| Orden | Qué hace |
|-------|----------|
| `sudo python3 auditor.py` | Solo detecta y genera el informe. No cambia nada. |
| `sudo python3 auditor.py --aprender` | Guarda los dispositivos conectados ahora como «conocidos». |
| `sudo python3 auditor.py --arreglar` | Aplica los arreglos automáticos preguntando uno a uno. |
| `sudo python3 auditor.py --arreglar --si` | Los aplica todos sin preguntar. |
| `--red 192.168.1.0/24` | Escanea esa red en vez de la detectada. |
| `--sin-red`, `--sin-upnp`, `--sin-equipo` | Se salta una parte de la revisión. |

Sin `sudo` funciona, pero no ve las MAC de los dispositivos ni puede revisar el cortafuegos y SSH.

El informe se guarda en `informes/` y el inventario en `conocidos.json`. Los dos contienen datos de tu red y están en `.gitignore`.

## Qué detecta y qué arregla

| Comprobación | Dónde | Arreglo |
|--------------|-------|---------|
| Dispositivo conectado que no está en el inventario | Red | Manual (cambiar contraseña WiFi, desactivar WPS) |
| Telnet, FTP, SMB, RDP, VNC, ADB, TR-069, MQTT, RTSP abiertos | Cada equipo | Manual (se indica qué desactivar) |
| Panel de administración del router por HTTP | Router | Manual |
| UPnP activado | Router | Manual (desactivarlo en el panel) |
| Puertos abiertos hacia internet mediante UPnP | Router | **Automático**: se pide al router que los cierre y se comprueba |
| Cortafuegos `ufw` desactivado | Este equipo | **Automático**: lo activa bloqueando lo entrante (mantiene SSH si está en uso) |
| Telnet o FTP a la escucha | Este equipo | **Automático**: para y deshabilita el servicio y su socket |
| SSH permite root con contraseña | Este equipo | **Automático**: `PermitRootLogin prohibit-password` en un fichero aparte |
| WiFi abierta, WEP o WPA1 | WiFi | Manual |

## Lo que no puede hacer

La configuración interna del router (contraseña de administrador, WPS, cifrado WiFi, firmware, administración remota) no se puede leer ni cambiar de forma genérica: cada fabricante tiene su propio panel. Por eso cada informe termina con una lista de comprobación manual del router.

Tampoco puede cambiar la configuración de otros equipos de la red (un Windows, una cámara): los detecta y explica qué desactivar, pero el cambio hay que hacerlo en ese equipo.

Los puertos cerrados por UPnP pueden volver a abrirse si el dispositivo lo pide de nuevo; la solución definitiva es desactivar UPnP en el router.

## Cómo deshacer los arreglos

| Arreglo | Deshacer |
|---------|----------|
| Cortafuegos activado | `sudo ufw disable` |
| Servicio parado | `sudo systemctl enable --now <unidad>` |
| SSH root | `sudo rm /etc/ssh/sshd_config.d/00-auditor-red-casa.conf && sudo systemctl reload ssh` |
| Puerto UPnP cerrado | El dispositivo lo vuelve a pedir solo, o se abre a mano en el router |

## Que se ejecute solo

Para una revisión diaria a las 20:00 con arreglo automático, añade esta línea con `sudo crontab -e` (cambia la ruta):

```
0 20 * * * cd /ruta/a/cyber-lab/auditor-red-casa && python3 auditor.py --arreglar --si >> /var/log/auditor-red-casa.log 2>&1
```

## Estado del proyecto

- **Qué es:** un proyecto de aprendizaje dentro de mi laboratorio personal, para practicar redes, `nmap`, UPnP y endurecimiento básico de Linux.
- **Qué no es:** una herramienta profesional. Se ofrece tal cual, sin garantías; revisa siempre lo que va a cambiar antes de usar `--arreglar`.
- **Probado en:** una única red doméstica (router Livebox de Orange) desde una VM de Ubuntu Server 24.04 en modo bridged. En otros routers puede comportarse distinto.
- **Cómo se ha hecho:** el código se escribió con ayuda de un asistente de IA (Claude). Mi parte ha sido montar el entorno, ejecutarlo contra mi red, interpretar los resultados y estudiar el código para poder explicarlo y ampliarlo.
- **Pendiente:** añadir comprobaciones propias, documentar una ejecución real como lab y probarlo en más routers.

Un ejemplo del informe que genera, con datos ficticios: [ejemplo-informe.md](ejemplo-informe.md).

## Estructura

| Fichero | Contenido |
|---------|-----------|
| `auditor.py` | Punto de entrada |
| `auditor/red.py` | Detección de la red, nmap, puertos de riesgo, inventario |
| `auditor/upnp.py` | Descubrimiento SSDP y órdenes SOAP al router |
| `auditor/equipo.py` | Cortafuegos, servicios, SSH y WiFi del equipo local |
| `auditor/cli.py` | Opciones, salida por pantalla, arreglos e informe |
| `tests/` | Pruebas con salidas de ejemplo y un router UPnP simulado |

```bash
python3 -m unittest discover -s tests
```

## Aviso

Solo acepta redes privadas de tamaño doméstico y está hecha para auditar la red propia. No se escanea ninguna red sin autorización de su dueño.
