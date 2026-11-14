"""Sondas de red reales: ping, router, DNS, tabla ARP y puertos.

Solo usa la biblioteca estándar y los comandos del sistema (ping, ip/route, arp),
así que funciona en Linux (Raspberry Pi incluida), macOS y Windows.
"""

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

SISTEMA = platform.system()

# Puertos que no deberían estar abiertos en un equipo normal de casa.
PUERTOS_PELIGROSOS = {
    21: "FTP (contraseñas en claro)",
    23: "Telnet (contraseñas en claro)",
    139: "NetBIOS (compartición antigua de Windows)",
    445: "SMB (carpetas compartidas)",
    3389: "Escritorio remoto de Windows",
    5900: "VNC (control remoto)",
}

_RE_TIEMPO = re.compile(r"(?:time|tiempo)\s*[=<]\s*([\d.,]+)\s*ms?", re.IGNORECASE)
_RE_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RE_MAC = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")


# --------------------------------------------------------------------- parsers
def parsear_ping(texto):
    """Devuelve los milisegundos de una respuesta de ping, o None."""
    m = _RE_TIEMPO.search(texto)
    if not m:
        return None
    return float(m.group(1).replace(",", "."))


def normalizar_mac(mac):
    partes = re.split(r"[:-]", mac.strip().lower())
    return ":".join(p.zfill(2) for p in partes)


def mac_es_privada(mac):
    """Los móviles modernos usan MACs aleatorias ("privadas"): bit 0x02 activo."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def parsear_arp(texto):
    """Lee la salida de `arp -a` (macOS, Windows, Linux) -> {ip: mac}."""
    resultado = {}
    for linea in texto.splitlines():
        ip = _RE_IP.search(linea)
        mac = _RE_MAC.search(linea)
        if not ip or not mac:
            continue
        mac_n = normalizar_mac(mac.group(1))
        if mac_n in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac_n.startswith("01:00:5e"):
            continue  # difusión / multicast, no son dispositivos
        resultado[ip.group(1)] = mac_n
    return resultado


def parsear_proc_arp(texto):
    """Lee /proc/net/arp de Linux -> {ip: mac}, ignorando entradas incompletas."""
    resultado = {}
    for linea in texto.splitlines()[1:]:
        campos = linea.split()
        if len(campos) < 4:
            continue
        ip, _hw, flags, mac = campos[:4]
        if flags == "0x0" or mac == "00:00:00:00:00:00":
            continue
        resultado[ip] = normalizar_mac(mac)
    return resultado


def parsear_gateway(texto):
    """Saca la IP del router de `ip route`, `route -n get default` o `route print`."""
    for patron in (
        r"default via (\d+\.\d+\.\d+\.\d+)",          # Linux
        r"gateway:\s*(\d+\.\d+\.\d+\.\d+)",           # macOS
        r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)",  # Windows
    ):
        m = re.search(patron, texto, re.MULTILINE)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------- sondas
def _ejecutar(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return r.returncode, r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return -1, ""


class SondasReales:
    """Todo lo que el monitor necesita preguntar a la red de verdad."""

    modo = "real"

    def __init__(self, config):
        self.config = config
        self._nombres = {}

    # -- identidad del propio equipo
    def ip_local(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))  # no envía nada, solo elige la interfaz
            return s.getsockname()[0]
        except OSError:
            return None
        finally:
            s.close()

    def subred(self):
        if self.config.get("subred"):
            return ipaddress.ip_network(self.config["subred"], strict=False)
        ip = self.ip_local()
        if not ip:
            return None
        return ipaddress.ip_network(f"{ip}/24", strict=False)

    def gateway(self):
        if self.config.get("router"):
            return self.config["router"]
        if SISTEMA == "Linux":
            _, out = _ejecutar(["ip", "route", "show", "default"])
        elif SISTEMA == "Darwin":
            _, out = _ejecutar(["route", "-n", "get", "default"])
        else:
            _, out = _ejecutar(["route", "print", "0.0.0.0"])
        return parsear_gateway(out)

    # -- medidas
    def ping(self, host, timeout=1.0):
        if SISTEMA == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        elif SISTEMA == "Darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
        codigo, out = _ejecutar(cmd, timeout=timeout + 2)
        if codigo != 0:
            return None
        return parsear_ping(out)

    def dns(self, dominio="www.google.com"):
        """Milisegundos que tarda en resolver un nombre, o None si falla."""
        inicio = time.perf_counter()
        try:
            socket.getaddrinfo(dominio, 443, proto=socket.IPPROTO_TCP)
        except OSError:
            return None
        return (time.perf_counter() - inicio) * 1000

    # -- dispositivos
    def tabla_arp(self):
        if SISTEMA == "Linux":
            try:
                with open("/proc/net/arp", encoding="ascii") as f:
                    return parsear_proc_arp(f.read())
            except OSError:
                pass
        _, out = _ejecutar(["arp", "-a"], timeout=10)
        return parsear_arp(out)

    def barrido(self, subred):
        """Hace ping a toda la subred para que los equipos aparezcan en la tabla ARP."""
        hosts = [str(h) for h in subred.hosts()][:1024]
        vivos = set()
        with ThreadPoolExecutor(max_workers=64) as pool:
            for host, ms in zip(hosts, pool.map(lambda h: self.ping(h, 1.0), hosts)):
                if ms is not None:
                    vivos.add(host)
        return vivos

    def nombre(self, ip):
        if ip not in self._nombres:
            try:
                self._nombres[ip] = socket.gethostbyaddr(ip)[0].split(".")[0]
            except (OSError, UnicodeError):
                self._nombres[ip] = ""
        return self._nombres[ip]

    def nombre_wifi(self):
        return self.config.get("nombre_red") or nombre_wifi()

    def velocidad(self):
        return test_velocidad()

    def upnp(self, router):
        return upnp_responde(router)

    def puertos_abiertos(self, ip, puertos=PUERTOS_PELIGROSOS):
        abiertos = []
        for puerto in puertos:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                if s.connect_ex((ip, puerto)) == 0:
                    abiertos.append(puerto)
        return abiertos


# ------------------------------------------------- nombre del Wi-Fi, velocidad, UPnP
def parsear_ssid(texto):
    """Saca el nombre del Wi-Fi de iwgetid, nmcli, networksetup o netsh."""
    for patron in (
        r"^yes:(.+)$",                                  # nmcli -t -f active,ssid
        r"Current Wi-Fi Network:\s*(.+)$",              # macOS networksetup
        r"^\s*SSID\s*:\s*(.+)$",                        # Windows netsh (no BSSID)
    ):
        m = re.search(patron, texto, re.MULTILINE)
        if m:
            return m.group(1).strip()
    linea = texto.strip().splitlines()[0] if texto.strip() else ""
    return linea or None                                # iwgetid -r: solo el nombre


def nombre_wifi():
    if SISTEMA == "Linux":
        for cmd in (["iwgetid", "-r"], ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]):
            codigo, out = _ejecutar(cmd)
            if codigo == 0 and out.strip():
                return parsear_ssid(out)
    elif SISTEMA == "Darwin":
        for interfaz in ("en0", "en1"):
            codigo, out = _ejecutar(["networksetup", "-getairportnetwork", interfaz])
            if codigo == 0 and "Current Wi-Fi Network" in out:
                return parsear_ssid(out)
    else:
        codigo, out = _ejecutar(["netsh", "wlan", "show", "interfaces"])
        if codigo == 0:
            return parsear_ssid(out)
    return None


URL_BAJADA = "https://speed.cloudflare.com/__down?bytes={}"
URL_SUBIDA = "https://speed.cloudflare.com/__up"


def test_velocidad(bytes_bajada=25_000_000, bytes_subida=8_000_000, limite=15):
    """Mide la velocidad real de internet descargando y subiendo datos a Cloudflare.

    Gasta unos 33 MB por medición. Devuelve (bajada_mbps, subida_mbps).
    """
    import urllib.request

    cabeceras = {"User-Agent": "monitor-red-casa"}

    def medir_bajada():
        inicio, total = time.perf_counter(), 0
        req = urllib.request.Request(URL_BAJADA.format(bytes_bajada), headers=cabeceras)
        with urllib.request.urlopen(req, timeout=limite) as r:
            while True:
                trozo = r.read(65536)
                if not trozo:
                    break
                total += len(trozo)
                if time.perf_counter() - inicio > limite:
                    break
        return total * 8 / (time.perf_counter() - inicio) / 1e6

    def medir_subida():
        datos = b"0" * bytes_subida
        req = urllib.request.Request(URL_SUBIDA, data=datos, method="POST",
                                     headers=dict(cabeceras, **{"Content-Type": "application/octet-stream"}))
        inicio = time.perf_counter()
        with urllib.request.urlopen(req, timeout=limite * 2) as r:
            r.read()
        return len(datos) * 8 / (time.perf_counter() - inicio) / 1e6

    return medir_bajada(), medir_subida()


def upnp_responde(router, espera=2.0):
    """True si el router contesta a una búsqueda UPnP (SSDP) en la red local."""
    mensaje = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n').encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
        s.settimeout(0.5)
        try:
            s.sendto(mensaje, ("239.255.255.250", 1900))
        except OSError:
            return None
        fin = time.time() + espera
        while time.time() < fin:
            try:
                _datos, (ip, _puerto) = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return None
            if ip == router:
                return True
    return False
