"""Descubrimiento de equipos y escaneo de puertos de riesgo con nmap."""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .modelo import Hallazgo

MAX_DIRECCIONES = 1024  # no escanear redes mayores que un /22 por accidente

# puerto -> (gravedad, qué es, por qué importa, qué hacer)
PUERTOS_RIESGO: dict[int, tuple[str, str, str, str]] = {
    21: ("media", "FTP", "transfiere usuario, contraseña y ficheros sin cifrar",
         "Desactiva FTP en ese equipo y usa SFTP (SSH) en su lugar."),
    23: ("alta", "Telnet", "administración remota sin cifrar; es lo primero que prueban las botnets",
         "Desactiva Telnet en ese equipo; si necesitas acceso remoto usa SSH."),
    2323: ("alta", "Telnet (puerto alternativo)", "típico de dispositivos IoT con contraseña de fábrica",
           "Desactiva Telnet o actualiza el firmware; si no se puede, aísla el dispositivo en la red de invitados."),
    135: ("media", "RPC de Windows", "servicio interno de Windows expuesto a toda la red",
          "Pon la red como 'Privada' solo si te fías de todos los equipos; si no, márcala como 'Pública' en Windows."),
    139: ("media", "NetBIOS", "compartición de ficheros antigua de Windows",
          "Desactiva 'Compartir archivos e impresoras' si no lo usas."),
    445: ("media", "SMB (carpetas compartidas)", "cualquiera dentro de la red puede intentar entrar a las carpetas compartidas",
          "Desactiva la compartición si no la usas, o exige usuario y contraseña y desactiva SMBv1."),
    3389: ("media", "Escritorio remoto (RDP)", "objetivo habitual de ataques de fuerza bruta",
           "Desactiva Escritorio remoto si no lo usas; nunca lo abras hacia internet."),
    5900: ("media", "VNC", "control remoto que a menudo va sin cifrar o sin contraseña",
           "Desactiva VNC o ponle contraseña fuerte y úsalo solo a través de SSH/VPN."),
    5555: ("alta", "ADB de Android", "da control total del dispositivo sin contraseña",
           "Desactiva 'Depuración por red/ADB' en los ajustes de desarrollador del dispositivo."),
    7547: ("media", "TR-069 (gestión remota del operador)", "ha tenido vulnerabilidades graves en muchos routers",
           "Comprueba que el firmware del router está actualizado; si el router es tuyo y no del operador, desactiva TR-069."),
    1883: ("baja", "MQTT", "mensajería de domótica que suele ir sin autenticación",
           "Configura usuario y contraseña en el broker MQTT."),
    554: ("baja", "RTSP (vídeo de cámara)", "el vídeo de la cámara puede verse desde cualquier equipo de la red",
          "Pon contraseña al flujo RTSP o desactívalo en la cámara."),
    22: ("info", "SSH", "acceso remoto cifrado; es correcto si lo has activado tú",
         "Si no lo usas, desactívalo. Si lo usas, entra con claves en vez de contraseña."),
}
# puertos que solo se consideran un problema en el router
PUERTOS_ROUTER: dict[int, tuple[str, str, str, str]] = {
    80: ("baja", "Panel del router por HTTP", "la contraseña de administración viaja sin cifrar por la red",
         "Entra al panel por HTTPS si el router lo permite y cambia la contraseña de administrador de fábrica."),
    8080: ("baja", "Panel del router por HTTP (8080)", "la contraseña de administración viaja sin cifrar por la red",
           "Entra al panel por HTTPS si el router lo permite y cambia la contraseña de administrador de fábrica."),
}


class ErrorRed(Exception):
    pass


@dataclass
class Puerto:
    numero: int
    servicio: str = ""
    version: str = ""


@dataclass
class Equipo:
    ip: str
    mac: str = ""
    fabricante: str = ""
    nombre: str = ""
    puertos: list[Puerto] = field(default_factory=list)

    @property
    def clave(self) -> str:
        """Identificador para el inventario: la MAC si se conoce, si no la IP."""
        return self.mac.lower() if self.mac else f"ip:{self.ip}"

    def etiqueta(self) -> str:
        extra = " · ".join(x for x in (self.nombre, self.fabricante, self.mac) if x)
        return f"{self.ip} ({extra})" if extra else self.ip


@dataclass
class RedLocal:
    red: ipaddress.IPv4Network
    puerta_enlace: str = ""
    interfaz: str = ""
    mi_ip: str = ""


def _ejecutar(cmd: list[str], timeout: int = 900) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise ErrorRed(f"No se encuentra el programa '{cmd[0]}'. Instálalo (p. ej. sudo apt install {cmd[0]}).")
    except subprocess.TimeoutExpired:
        raise ErrorRed(f"'{' '.join(cmd[:2])}' ha tardado demasiado y se ha cancelado.")
    if r.returncode != 0:
        raise ErrorRed(f"'{' '.join(cmd)}' ha fallado: {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout


def validar_red(texto: str) -> ipaddress.IPv4Network:
    """Solo se aceptan redes privadas y de tamaño doméstico: esta herramienta es para TU red."""
    try:
        red = ipaddress.ip_network(texto, strict=False)
    except ValueError as e:
        raise ErrorRed(f"'{texto}' no es una red válida (ejemplo: 192.168.1.0/24): {e}")
    if red.version != 4:
        raise ErrorRed("Solo se admite IPv4.")
    if not red.is_private or red.is_loopback or red.is_link_local:
        raise ErrorRed(f"{red} no es una red privada. Esta herramienta solo audita redes domésticas propias.")
    if red.num_addresses > MAX_DIRECCIONES:
        raise ErrorRed(f"{red} es demasiado grande ({red.num_addresses} direcciones). Indica una red más pequeña con --red.")
    return red


def detectar_red() -> RedLocal:
    """Averigua la red, la interfaz y el router a partir de la ruta por defecto."""
    rutas = json.loads(_ejecutar(["ip", "-j", "-4", "route", "show", "default"]) or "[]")
    if not rutas:
        raise ErrorRed("No hay ruta por defecto: ¿estás conectado a la red? Puedes indicarla con --red.")
    interfaz = rutas[0]["dev"]
    puerta = rutas[0].get("gateway", "")
    dirs = json.loads(_ejecutar(["ip", "-j", "-4", "addr", "show", "dev", interfaz]) or "[]")
    try:
        info = dirs[0]["addr_info"][0]
    except (IndexError, KeyError):
        raise ErrorRed(f"La interfaz {interfaz} no tiene dirección IPv4.")
    red = validar_red(f"{info['local']}/{info['prefixlen']}")
    return RedLocal(red=red, puerta_enlace=puerta, interfaz=interfaz, mi_ip=info["local"])


def interpretar_nmap(xml: str) -> list[Equipo]:
    """Convierte la salida XML de nmap (-oX -) en una lista de equipos encendidos."""
    equipos = []
    for host in ET.fromstring(xml).iter("host"):
        estado = host.find("status")
        if estado is not None and estado.get("state") != "up":
            continue
        eq = Equipo(ip="")
        for d in host.findall("address"):
            if d.get("addrtype") == "ipv4":
                eq.ip = d.get("addr", "")
            elif d.get("addrtype") == "mac":
                eq.mac = d.get("addr", "")
                eq.fabricante = d.get("vendor", "")
        nombre = host.find("hostnames/hostname")
        if nombre is not None:
            eq.nombre = nombre.get("name", "")
        for p in host.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            srv = p.find("service")
            version = ""
            if srv is not None:
                version = " ".join(x for x in (srv.get("product"), srv.get("version")) if x)
            eq.puertos.append(Puerto(int(p.get("portid", "0")), srv.get("name", "") if srv is not None else "", version))
        if eq.ip:
            equipos.append(eq)
    return equipos


def descubrir_equipos(red: ipaddress.IPv4Network) -> list[Equipo]:
    """Barrido de descubrimiento (sin puertos). Con sudo, nmap usa ARP y devuelve MAC y fabricante."""
    return interpretar_nmap(_ejecutar(["nmap", "-sn", "-oX", "-", str(red)]))


def escanear_puertos(equipos: list[Equipo]) -> None:
    """Mira solo los puertos de la lista de riesgo y rellena equipo.puertos."""
    if not equipos:
        return
    puertos = ",".join(str(p) for p in sorted({**PUERTOS_RIESGO, **PUERTOS_ROUTER}))
    xml = _ejecutar(["nmap", "-Pn", "-sV", "--version-light", "--open", "-p", puertos, "-oX", "-"]
                    + [e.ip for e in equipos])
    por_ip = {e.ip: e for e in interpretar_nmap(xml)}
    for e in equipos:
        if e.ip in por_ip:
            e.puertos = por_ip[e.ip].puertos


def hallazgos_puertos(equipos: list[Equipo], puerta_enlace: str) -> list[Hallazgo]:
    res = []
    for e in equipos:
        es_router = e.ip == puerta_enlace
        for p in e.puertos:
            regla = PUERTOS_RIESGO.get(p.numero) or (PUERTOS_ROUTER.get(p.numero) if es_router else None)
            if not regla:
                continue
            gravedad, nombre, motivo, consejo = regla
            if es_router and gravedad == "media":
                gravedad = "alta"  # en el router afecta a toda la casa
            visto = f"Puerto {p.numero}/tcp abierto"
            if p.version or p.servicio:
                visto += f" ({p.version or p.servicio})"
            res.append(Hallazgo(
                codigo=f"PUERTO-{p.numero}", gravedad=gravedad,
                titulo=f"{nombre} accesible en {'el router' if es_router else 'un equipo'}",
                objetivo=e.etiqueta(), detalle=f"{visto}: {motivo}.", recomendacion=consejo))
    return res


# ---------- Inventario de dispositivos conocidos ----------

def cargar_inventario(ruta: Path) -> dict:
    if not ruta.exists():
        return {}
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar_inventario(ruta: Path, equipos: list[Equipo], previo: dict) -> dict:
    """Marca como conocidos todos los equipos presentes (se usa con --aprender)."""
    inv = dict(previo)
    for e in equipos:
        anterior = inv.get(e.clave, {})
        inv[e.clave] = {
            "nombre": anterior.get("nombre") or e.nombre or e.fabricante or "",
            "ip": e.ip,
            "fabricante": e.fabricante,
            "primera_vez": anterior.get("primera_vez", date.today().isoformat()),
        }
    ruta.write_text(json.dumps(inv, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return inv


def hallazgos_inventario(equipos: list[Equipo], inventario: dict, mi_ip: str) -> list[Hallazgo]:
    otros = [e for e in equipos if e.ip != mi_ip]
    if not inventario:
        lista = "\n".join(f"  - {e.etiqueta()}" for e in otros) or "  (ninguno)"
        return [Hallazgo(
            codigo="INVENTARIO-VACIO", gravedad="info",
            titulo="Todavía no hay inventario de dispositivos conocidos", objetivo="red",
            detalle=f"Equipos conectados ahora mismo:\n{lista}",
            recomendacion="Revisa la lista. Si todos son tuyos, ejecuta de nuevo con --aprender; "
                          "a partir de ahí se avisará de cualquier dispositivo nuevo.")]
    res = []
    for e in otros:
        if e.clave in inventario:
            continue
        res.append(Hallazgo(
            codigo="DISPOSITIVO-NUEVO", gravedad="alta",
            titulo="Dispositivo que no está en tu inventario", objetivo=e.etiqueta(),
            detalle="Se ha conectado a tu red un equipo que no habías marcado como conocido.",
            recomendacion="Si es tuyo, ejecuta con --aprender. Si no lo reconoces: cambia la contraseña "
                          "del WiFi (WPA2/WPA3, 16+ caracteres), desactiva WPS y revisa la lista de "
                          "clientes en el panel del router."))
    return res


def nmap_disponible() -> bool:
    return shutil.which("nmap") is not None
