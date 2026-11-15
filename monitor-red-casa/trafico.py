"""Consumo de datos por dispositivo, capturando paquetes con scapy (opcional).

Importante: solo se cuenta el tráfico que llega a la tarjeta de red de este equipo.
En una red de casa normal (switch / Wi-Fi) eso es casi solo el tráfico propio.
Para ver el de TODOS los dispositivos, este equipo tiene que estar "en medio":
  - es el router o el punto de acceso (p. ej. una Raspberry Pi haciendo de AP), o
  - está conectado a un puerto con "port mirroring" en un switch gestionable.
Ver README.md, sección "Consumo por dispositivo".
"""

import ipaddress
import threading
from collections import defaultdict


class ContadorTrafico:
    def __init__(self, subred, interfaz=None):
        self.subred = subred
        self.interfaz = interfaz
        self._lock = threading.Lock()
        self._bytes = defaultdict(lambda: [0, 0])  # ip -> [bajada, subida]
        self._sniffer = None
        self.error = None

    @property
    def activo(self):
        return self._sniffer is not None

    def iniciar(self):
        try:
            from scapy.all import AsyncSniffer  # noqa: import opcional
        except ImportError:
            self.error = "scapy no está instalado (pip install scapy)"
            return False
        try:
            self._sniffer = AsyncSniffer(filter="ip", prn=self._paquete, store=False,
                                         iface=self.interfaz)
            self._sniffer.start()
        except Exception as e:  # sin permisos de administrador, interfaz mala...
            self._sniffer = None
            self.error = f"No se pudo capturar tráfico: {e}. ¿Lo ejecutas con sudo?"
            return False
        return True

    def _es_local(self, ip):
        try:
            return ipaddress.ip_address(ip) in self.subred
        except ValueError:
            return False

    def _paquete(self, paquete):
        from scapy.all import IP
        if IP not in paquete:
            return
        origen, destino = paquete[IP].src, paquete[IP].dst
        tam = len(paquete)
        local_o, local_d = self._es_local(origen), self._es_local(destino)
        if local_o == local_d:
            return  # tráfico interno o ajeno: no es consumo de internet
        with self._lock:
            if local_d:
                self._bytes[destino][0] += tam
            else:
                self._bytes[origen][1] += tam

    def totales(self):
        """{ip: (bytes_bajada, bytes_subida)} acumulados desde el arranque."""
        with self._lock:
            return {ip: tuple(v) for ip, v in self._bytes.items()}
