# Monitor de la red de casa

App para el móvil de la gente de casa, con su icono en la pantalla de inicio. Al abrirla te hace un análisis de la red de casa:

- **La red:** nombre del Wi-Fi, router y cuántos dispositivos hay conectados.
- **Velocidad de internet:** test real de bajada y subida en Mb/s, comparado con lo que tienes contratado.
- **Cada dispositivo:** si está conectado, a qué velocidad va ahora y cuánto ha gastado hoy.
- **Fallos ahora mismo:** con un "Cómo arreglarlo" en cada uno.
- **Análisis y recomendaciones:** nota de 0 a 100 de la red y qué mejorar.

<img src="img/movil.png" alt="La app en un iPhone (modo demo)" width="320">

## Qué hace

| Parte | Cómo lo mide | Cada cuánto |
|---|---|---|
| Velocidad de internet | Descarga 25 MB y sube 8 MB a `speed.cloudflare.com` (unos 33 MB por test) | 3 h y con el botón "Medir ahora" |
| Nombre del Wi-Fi | `iwgetid`/`nmcli` (Linux), `networksetup` (macOS), `netsh` (Windows) | al arrancar |
| UPnP del router | Búsqueda SSDP en la red local | 30 min |
| Latencia a internet y al router | `ping` a `1.1.1.1` (o `8.8.8.8`) y al router | 5 s |
| DNS | Tiempo en resolver `www.google.com` | 5 s |
| Cortes | % de pings a internet sin respuesta en 5 min | 5 s |
| Dispositivos conectados | Barrido de ping de la subred + tabla ARP | 60 s |
| Puertos peligrosos | Conexión TCP a 21, 23, 139, 445, 3389, 5900 en cada dispositivo | 10 min |
| Consumo por dispositivo | Captura de paquetes con `scapy` (opcional, ver abajo) | continuo |

**Fallos que detecta:** router caído, sin internet, DNS caído, conexión inestable, internet lento, Wi-Fi saturado, velocidad muy por debajo de lo contratado, dispositivo nuevo desconocido y puertos peligrosos abiertos. Cada uno trae un "Cómo arreglarlo".

**El análisis** revisa la última hora y da una nota de 0 a 100. Mira la estabilidad, el ping, la calidad del Wi-Fi, el DNS, la velocidad frente a la contratada, los puertos peligrosos, el UPnP del router y si todos los dispositivos están identificados. Cada punto mejorable trae un "Qué hacer".

**Solo para la gente de casa:**
- Rechaza cualquier conexión que no venga de una IP privada (de la red local).
- Pide una contraseña común para la familia, una sola vez por móvil: la sesión dura un año.
- Frena los intentos de contraseña a lo bruto (1 s tras cada fallo, 60 s tras 5 fallos).
- **No abras el puerto en el router.** La app está pensada para no salir de casa.

## Probarla sin tocar nada (modo demo)

```bash
cd monitor-red-casa
MONITOR_CLAVE=prueba python3 app.py --demo
```

Abre <http://localhost:8080> y entra con `prueba`. La velocidad se mide sola a los 20 s. A los 30 s aparece un "intruso" con Telnet abierto. Cada 3 minutos el Wi-Fi simulado se satura 40 s, para que veas los avisos.

## Instalarla en casa

Necesita un equipo que esté siempre encendido y conectado a la red de casa. Lo ideal es una Raspberry Pi; un PC también sirve. Solo hace falta Python 3.9 o superior, sin librerías extra.

```bash
git clone https://github.com/mateoaaay/cyber-lab.git
cd cyber-lab/monitor-red-casa
sudo python3 app.py
```

La primera vez imprime la **contraseña de la familia** (queda guardada en `datos/clave.txt`) y la dirección a abrir, p. ej. `http://192.168.1.50:8080`.

### Ponerla en el móvil de cada uno, con icono

1. Conecta el móvil al Wi-Fi de casa y abre la dirección (p. ej. `http://192.168.1.50:8080`).
2. Entra con la contraseña de la familia.
3. Añade el icono:
   - **iPhone (Safari):** botón Compartir → **Añadir a pantalla de inicio**. Se abre a pantalla completa, como una app.
   - **Android (Chrome):** menú ⋮ → **Añadir a pantalla de inicio**. Al ir por HTTP, Chrome la abre como una pestaña sin barra de app, pero con su icono.

> Para que el móvil siempre encuentre la app, dale al equipo una **IP fija** en el router ("reserva DHCP"). Si la IP cambia, el icono deja de funcionar.

Fuera de casa la app no funciona, a propósito: solo responde dentro de la red local.

Opciones de `config.json` (copia `config.ejemplo.json`). Todas son opcionales:

| Campo | Para qué |
|---|---|
| `clave` | Elegir tú la contraseña (también vale la variable `MONITOR_CLAVE`) |
| `velocidad_contratada` | Mb/s de bajada de tu tarifa, p. ej. `600`. Sirve para avisar si te dan menos |
| `horas_entre_tests` | Cada cuánto medir la velocidad (por defecto `3`) |
| `nombre_red` | Nombre del Wi-Fi a mostrar, si el equipo va por cable y no lo detecta |
| `router` | IP del router, si no la detecta solo |
| `subred` | Subred a vigilar, p. ej. `192.168.1.0/24` (por defecto, la /24 del equipo) |
| `interfaz` | Interfaz donde capturar tráfico, p. ej. `eth0` o `wlan0` |

Pon nombre a cada dispositivo tocándolo en la lista ("Móvil de Ana", "Tele del salón"…). Así, si aparece uno que nadie reconoce, salta el aviso de **dispositivo nuevo**.

### Arrancarla sola al encender (Raspberry Pi / Linux)

`/etc/systemd/system/monitor-casa.service`:

```ini
[Unit]
Description=Monitor de la red de casa
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/home/pi/cyber-lab/monitor-red-casa
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now monitor-casa
```

## Consumo por dispositivo

Este es el punto delicado, y conviene entenderlo. En una red de casa, el tráfico del móvil de tu hermano va del móvil al router. **No pasa por el equipo donde corre la app**, así que no se puede medir desde ahí. Hay tres formas de conseguirlo:

1. **El equipo está "en medio"** (lo más fiable). Por ejemplo, una Raspberry Pi hace de punto de acceso Wi-Fi o de router, o el equipo va conectado a un switch gestionable con *port mirroring* del puerto del router. Entonces:
   ```bash
   sudo pip install scapy
   sudo python3 app.py
   ```
2. **Usar las estadísticas del router.** Muchos routers (OpenWrt, ASUS, UniFi, Fritz!Box…) ya cuentan el consumo por dispositivo. Se puede añadir una fuente que lea de ahí: dime qué router tienes y la preparo.
3. **Sin nada de lo anterior:** la app sigue funcionando. Con `scapy` instalado solo verá el consumo del propio equipo. Sin `scapy`, la sección de consumo muestra un aviso y lo demás (fallos, dispositivos, latencia) va igual.

Capturar paquetes necesita permisos de administrador; por eso se ejecuta con `sudo`.

## Archivos

| Archivo | Qué hay |
|---|---|
| `app.py` | Arranque y opciones |
| `monitor.py` | Mediciones periódicas, historial y reglas de fallos |
| `red.py` | Ping, router, DNS, ARP y puertos (Linux, macOS y Windows) |
| `trafico.py` | Contador de consumo con `scapy` |
| `servidor.py` | Servidor web, contraseña y filtro de IPs de casa |
| `demo.py` | Red simulada para `--demo` |
| `static/` | La web (HTML, CSS y JS, sin dependencias externas) |
| `datos/` | Contraseña, secreto de sesión, nombres y consumo de hoy (no se sube a git) |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limitaciones

- La web va por HTTP dentro de casa, sin HTTPS. Basta para una red doméstica de confianza; no la expongas a internet.
- Los móviles con **MAC privada** pueden cambiarla y aparecer como "nuevos". En el móvil, desactiva la MAC privada solo para el Wi-Fi de casa.
- El historial vive en memoria: al reiniciar la app se pierde la última hora de gráfica. Los nombres y el consumo de hoy sí se guardan.
- Cada test de velocidad gasta unos 33 MB, unos 260 MB al día con el intervalo por defecto. Si tienes datos limitados (4G/5G en casa), sube `horas_entre_tests`.
- El test mide la velocidad **del equipo donde corre la app**. Si va por Wi-Fi, saldrá menos de lo contratado: para comparar con la tarifa, mejor conectarlo por cable al router.
