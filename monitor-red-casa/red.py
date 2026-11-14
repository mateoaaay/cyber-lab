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

    def puertos_abiertos(self, ip, puertos=PUERTOS_PELIGROSOS):
        abiertos = []
        for puerto in puertos:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                if s.connect_ex((ip, puerto)) == 0:
                    abiertos.append(puerto)
        return abiertos
