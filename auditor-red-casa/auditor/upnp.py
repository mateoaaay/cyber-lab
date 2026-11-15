"""UPnP en el router: lista los puertos abiertos hacia internet y permite cerrarlos.

UPnP IGD deja que cualquier programa de la red (un juego, una cámara, o un malware)
pida al router que abra un puerto hacia internet sin contraseña. Aquí usamos ese
mismo protocolo para ver qué hay abierto y para cerrarlo (DeletePortMapping).
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from xml.sax.saxutils import escape

from .modelo import Hallazgo

SSDP = ("239.255.255.250", 1900)
ST_IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
MAX_MAPEOS = 200

# Peticiones directas a la LAN: nunca a través de un proxy del sistema.
_abrir = urllib.request.build_opener(urllib.request.ProxyHandler({})).open


class ErrorUPnP(Exception):
    pass


@dataclass
class Servicio:
    control_url: str
    tipo: str


@dataclass
class Mapeo:
    puerto_externo: int
    protocolo: str
    cliente: str
    puerto_interno: int
    descripcion: str = ""
    host_remoto: str = ""


def _es_local(url: str) -> bool:
    try:
        return ipaddress.ip_address(urllib.parse.urlsplit(url).hostname or "").is_private
    except ValueError:
        return False


def descubrir_igd(timeout: float = 3.0) -> list[str]:
    """Pregunta por multidifusión (SSDP) si hay un router con UPnP. Devuelve las URL de descripción."""
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           f"HOST: {SSDP[0]}:{SSDP[1]}\r\n"
           'MAN: "ssdp:discover"\r\n'
           "MX: 2\r\n"
           f"ST: {ST_IGD}\r\n\r\n").encode()
    urls: list[str] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(msg, SSDP)
            while True:
                datos, _ = s.recvfrom(4096)
                for linea in datos.decode(errors="replace").split("\r\n"):
                    if linea.lower().startswith("location:"):
                        url = linea.split(":", 1)[1].strip()
                        if _es_local(url) and url not in urls:
                            urls.append(url)
        except (socket.timeout, OSError):
            pass
    return urls


def _local(etiqueta: str) -> str:
    return etiqueta.rsplit("}", 1)[-1]


def obtener_servicio(url_descripcion: str) -> Servicio | None:
    """Busca en la descripción del router el servicio que gestiona los puertos (WANIP/WANPPP)."""
    try:
        with _abrir(url_descripcion, timeout=5) as r:
            raiz = ET.fromstring(r.read())
    except (urllib.error.URLError, OSError, ET.ParseError) as e:
        raise ErrorUPnP(f"No se pudo leer {url_descripcion}: {e}")
    base = url_descripcion
    for el in raiz.iter():
        if _local(el.tag) == "URLBase" and el.text:
            base = el.text.strip()
    for el in raiz.iter():
        if _local(el.tag) != "service":
            continue
        campos = {_local(h.tag): (h.text or "").strip() for h in el}
        tipo = campos.get("serviceType", "")
        if "WANIPConnection" in tipo or "WANPPPConnection" in tipo:
            control = urllib.parse.urljoin(base, campos.get("controlURL", ""))
            if _es_local(control):
                return Servicio(control, tipo)
    return None


def _soap(srv: Servicio, accion: str, args: dict[str, str]) -> dict[str, str]:
    cuerpo_args = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args.items())
    cuerpo = ('<?xml version="1.0"?>'
              '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
              's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
              f'<u:{accion} xmlns:u="{srv.tipo}">{cuerpo_args}</u:{accion}>'
              '</s:Body></s:Envelope>').encode()
    pet = urllib.request.Request(srv.control_url, data=cuerpo, headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{srv.tipo}#{accion}"',
    })
    try:
        with _abrir(pet, timeout=5) as r:
            raiz = ET.fromstring(r.read())
    except urllib.error.HTTPError as e:
        raise ErrorUPnP(f"El router rechazó {accion} (HTTP {e.code})")
    except (urllib.error.URLError, OSError, ET.ParseError) as e:
        raise ErrorUPnP(f"Fallo al hablar con el router: {e}")
    for el in raiz.iter():
        if _local(el.tag) == f"{accion}Response":
            return {_local(h.tag): (h.text or "") for h in el}
    return {}


def listar_mapeos(srv: Servicio) -> list[Mapeo]:
    """Recorre la tabla de puertos abiertos del router hasta que se acaba."""
    mapeos = []
    for i in range(MAX_MAPEOS):
        try:
            r = _soap(srv, "GetGenericPortMappingEntry", {"NewPortMappingIndex": str(i)})
        except ErrorUPnP:
            break  # el router responde con error cuando el índice ya no existe
        if not r.get("NewExternalPort"):
            break
        mapeos.append(Mapeo(
            puerto_externo=int(r["NewExternalPort"]), protocolo=r.get("NewProtocol", "TCP"),
            cliente=r.get("NewInternalClient", ""), puerto_interno=int(r.get("NewInternalPort") or 0),
            descripcion=r.get("NewPortMappingDescription", ""), host_remoto=r.get("NewRemoteHost", "")))
    return mapeos


def borrar_mapeo(srv: Servicio, m: Mapeo) -> None:
    _soap(srv, "DeletePortMapping", {
        "NewRemoteHost": m.host_remoto, "NewExternalPort": str(m.puerto_externo), "NewProtocol": m.protocolo})


def _arreglo_borrar(srv: Servicio, m: Mapeo):
    def aplicar() -> str:
        borrar_mapeo(srv, m)
        if any(x.puerto_externo == m.puerto_externo and x.protocolo == m.protocolo for x in listar_mapeos(srv)):
            raise ErrorUPnP("el router aceptó la orden pero el puerto sigue abierto")
        return f"Cerrado el puerto {m.puerto_externo}/{m.protocolo} en el router (comprobado)."
    return aplicar


def hallazgos_upnp(urls: list[str] | None = None) -> list[Hallazgo]:
    res = []
    for url in (descubrir_igd() if urls is None else urls):
        try:
            srv = obtener_servicio(url)
        except ErrorUPnP:
            continue
        if not srv:
            continue
        router = urllib.parse.urlsplit(url).hostname or "router"
        res.append(Hallazgo(
            codigo="UPNP-ACTIVO", gravedad="media", titulo="El router tiene UPnP activado", objetivo=router,
            detalle="Cualquier programa o dispositivo de tu red puede abrir puertos hacia internet "
                    "sin pedirte permiso ni contraseña.",
            recomendacion="Entra al panel del router y desactiva UPnP (suele estar en NAT, Avanzado o "
                          "Reenvío de puertos). Si una consola o un juego lo necesita, abre solo ese puerto a mano."))
        for m in listar_mapeos(srv):
            res.append(Hallazgo(
                codigo="UPNP-MAPEO", gravedad="alta", titulo="Puerto abierto hacia internet mediante UPnP",
                objetivo=f"{router} → {m.cliente}",
                detalle=f"Internet puede llegar al puerto {m.puerto_interno} de {m.cliente} a través del puerto "
                        f"{m.puerto_externo}/{m.protocolo} del router"
                        + (f" (lo pidió: «{m.descripcion}»)." if m.descripcion else "."),
                recomendacion="Ciérralo si no sabes qué es. Mientras UPnP siga activado, el dispositivo puede volver a abrirlo.",
                arreglo=_arreglo_borrar(srv, m),
                arreglo_desc=f"Pedir al router que cierre el puerto {m.puerto_externo}/{m.protocolo}"))
    return res
