"""Red de casa simulada para probar la app sin tocar ninguna red real.

Ejecuta `python3 app.py --demo`. A los ~30 s aparece un dispositivo desconocido
con Telnet abierto y de vez en cuando el Wi-Fi se satura, para ver los avisos.
"""

import ipaddress
import math
import random
import time

SUBRED = ipaddress.ip_network("192.168.1.0/24")
ROUTER = "192.168.1.1"

# mac, ip, nombre en casa, nombre de red, Mbit/s medio bajada, subida, puertos abiertos
EQUIPOS = [
    ("a4:91:b1:10:00:01", "192.168.1.1", "Router", "router", 0, 0, []),
    ("3c:22:fb:10:00:10", "192.168.1.10", "Portátil", "portatil", 4, 1.2, []),
    ("da:11:4e:10:00:11", "192.168.1.11", "Móvil", "", 1.5, 0.3, []),
    ("ca:5d:20:10:00:12", "192.168.1.12", "Móvil 2", "", 0.8, 0.2, []),
    ("70:2a:d5:10:00:20", "192.168.1.20", "Smart TV salón", "tv-salon", 18, 0.4, []),
    ("00:d9:d1:10:00:21", "192.168.1.21", "Consola", "consola", 6, 0.8, []),
    ("f0:27:2d:10:00:30", "192.168.1.30", "Altavoz", "", 0.3, 0.05, []),
    ("b8:27:eb:10:00:40", "192.168.1.40", "Ordenador sobremesa", "sobremesa", 2, 0.5, [445]),
]
INTRUSO = ("5e:8a:01:10:00:66", "192.168.1.66", "", "", 3, 2.5, [23])
INICIO = time.time()


class SondasDemo:
    modo = "demo"

    def __init__(self):
        self._t0 = time.time()

    def _equipos(self):
        visibles = list(EQUIPOS)
        if time.time() - self._t0 > 30:
            visibles.append(INTRUSO)
        return visibles

    def ip_local(self):
        return "192.168.1.10"

    def subred(self):
        return SUBRED

    def gateway(self):
        return ROUTER

    def _saturado(self):
        # Cada 3 minutos, 40 s de Wi-Fi saturado.
        return (time.time() - self._t0) % 180 > 140

    def ping(self, host, timeout=1.0):
        if host == ROUTER:
            base = 25 + random.random() * 30 if self._saturado() else 2 + random.random() * 3
            return round(base, 1)
        if random.random() < 0.02:
            return None
        base = 18 + 6 * math.sin(time.time() / 40) + random.random() * 6
        if self._saturado():
            base += 120 + random.random() * 80
        return round(base, 1)

    def dns(self, dominio=""):
        return round(8 + random.random() * 12, 1)

    def barrido(self, subred):
        return {e[1] for e in self._equipos()}

    def tabla_arp(self):
        return {e[1]: e[0] for e in self._equipos()}

    def nombre(self, ip):
        return next((e[3] for e in self._equipos() if e[1] == ip), "")

    def puertos_abiertos(self, ip, puertos=None):
        return next((list(e[6]) for e in self._equipos() if e[1] == ip), [])


class ContadorDemo:
    activo = True
    error = None

    def __init__(self, sondas):
        self.sondas = sondas
        self._totales = {}
        self._ultimo = time.time()

    def totales(self):
        ahora = time.time()
        dt = ahora - self._ultimo
        self._ultimo = ahora
        for _mac, ip, _n, _r, bajada, subida, _p in self.sondas._equipos():
            # Ráfagas: el consumo sube y baja de forma creíble.
            factor = max(0.0, 1 + 0.8 * math.sin(ahora / 23 + hash(ip) % 7) + random.gauss(0, 0.25))
            b, s = self._totales.get(ip, (0, 0))
            self._totales[ip] = (b + bajada * factor * 1e6 / 8 * dt,
                                 s + subida * factor * 1e6 / 8 * dt)
        return {ip: (int(b), int(s)) for ip, (b, s) in self._totales.items()}


def conocidos():
    return {mac: nombre for mac, _ip, nombre, *_ in EQUIPOS}
