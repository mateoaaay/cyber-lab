"""Núcleo del monitor: mide la red cada pocos segundos, detecta fallos y
lleva la cuenta de los dispositivos y su consumo."""

import ipaddress
import json
import logging
import os
import threading
import time
from collections import deque

from red import PUERTOS_PELIGROSOS, mac_es_privada

log = logging.getLogger("monitor")

NIVELES = {"critico": 0, "alto": 1, "medio": 2, "info": 3}


def _media(valores):
    valores = [v for v in valores if v is not None]
    return sum(valores) / len(valores) if valores else None


class Monitor:
    def __init__(self, sondas, contador=None, ruta_dispositivos=None,
                 conocidos=None, intervalos=None):
        self.sondas = sondas
        self.contador = contador
        self.ruta = ruta_dispositivos
        self.intervalos = {"salud": 5, "barrido": 60, "puertos": 600}
        self.intervalos.update(intervalos or {})

        self._lock = threading.Lock()
        self.historial = deque(maxlen=720)          # 1 h a 5 s: (ts, router, internet, dns)
        self.dispositivos = {}                      # mac -> info
        self.alertas = {}                           # id -> alerta activa
        self.recientes = deque(maxlen=30)           # alertas ya resueltas
        self.red = {"ip_local": None, "router": None, "subred": None}
        self._ultimo_trafico = (time.time(), {})

        self.registro = self._cargar_registro(conocidos)
        # Si es la primera vez que se ejecuta, no avisamos de "dispositivo nuevo":
        # todo es nuevo. Los que aparezcan después sí generan aviso.
        self._aprendiendo = not self.registro

    # ------------------------------------------------------------ persistencia
    def _cargar_registro(self, conocidos):
        if conocidos is not None:
            return {mac: {"nombre": n, "primera_vez": time.time()} for mac, n in conocidos.items()}
        if self.ruta and os.path.exists(self.ruta):
            try:
                with open(self.ruta, encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, ValueError) as e:
                log.warning("No se pudo leer %s: %s", self.ruta, e)
        return {}

    def _guardar_registro(self):
        if not self.ruta:
            return
        tmp = self.ruta + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.registro, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.ruta)

    def poner_nombre(self, mac, nombre):
        nombre = nombre.strip()[:40]
        with self._lock:
            if mac not in self.registro and mac not in self.dispositivos:
                return False
            self.registro.setdefault(mac, {"primera_vez": time.time()})["nombre"] = nombre
            self._guardar_registro()
            self._evaluar_alertas()
        return True

    # ------------------------------------------------------------------ bucles
    def iniciar(self):
        self._detectar_red()
        for objetivo, intervalo in ((self._tick_salud, "salud"),
                                    (self._tick_barrido, "barrido"),
                                    (self._tick_puertos, "puertos")):
            threading.Thread(target=self._bucle, args=(objetivo, intervalo),
                             daemon=True).start()

    def _bucle(self, funcion, clave):
        if clave == "puertos":
            time.sleep(min(20, self.intervalos["barrido"]))  # espera al primer barrido
        while True:
            inicio = time.time()
            try:
                funcion()
            except Exception:
                log.exception("Fallo en la tarea %s", clave)
            time.sleep(max(1, self.intervalos[clave] - (time.time() - inicio)))

    def _detectar_red(self):
        subred = self.sondas.subred()
        self.red = {"ip_local": self.sondas.ip_local(), "router": self.sondas.gateway(),
                    "subred": str(subred) if subred else None}
        self._subred = subred
        log.info("Red detectada: %s", self.red)

    def _tick_salud(self):
        if not self.red["router"]:
            self._detectar_red()
        router = self.sondas.ping(self.red["router"]) if self.red["router"] else None
        internet = self.sondas.ping("1.1.1.1")
        if internet is None:
            internet = self.sondas.ping("8.8.8.8")
        dns = self.sondas.dns()
        with self._lock:
            self.historial.append((time.time(), router, internet, dns))
            self._actualizar_trafico()
            self._evaluar_alertas()

    def _tick_barrido(self):
        if self._subred is None:
            self._detectar_red()
            if self._subred is None:
                return
        vivos = self.sondas.barrido(self._subred)
        arp = self.sondas.tabla_arp()
        ahora = time.time()
        with self._lock:
            for ip, mac in arp.items():
                if self._subred and not self._en_subred(ip):
                    continue
                d = self.dispositivos.get(mac)
                if d is None:
                    d = self.dispositivos[mac] = {
                        "mac": mac, "ip": ip, "nombre_red": "", "puertos": [],
                        "bajada_bps": 0, "subida_bps": 0, "bajada_total": 0, "subida_total": 0,
                    }
                d["ip"] = ip
                # Estar en la tabla ARP (o responder al ping) = se ha comunicado hace poco.
                d["ultima_vez"] = ahora
                if mac not in self.registro:
                    self.registro[mac] = {"nombre": "", "primera_vez": ahora,
                                          "nuevo": not self._aprendiendo}
                    self._guardar_registro()
            if self._aprendiendo and self.dispositivos:
                self._aprendiendo = False
            self._evaluar_alertas()
        # La resolución de nombres puede tardar: fuera del lock.
        for d in list(self.dispositivos.values()):
            if not d["nombre_red"]:
                d["nombre_red"] = self.sondas.nombre(d["ip"])
        log.debug("Barrido: %d vivos, %d en ARP", len(vivos), len(arp))

    def _tick_puertos(self):
        for mac, d in list(self.dispositivos.items()):
            if not self._en_linea(d) or d["ip"] == self.red["ip_local"]:
                continue
            abiertos = self.sondas.puertos_abiertos(d["ip"])
            with self._lock:
                d["puertos"] = abiertos
        with self._lock:
            self._evaluar_alertas()

    # --------------------------------------------------------------- utilidades
    def _en_subred(self, ip):
        try:
            return ipaddress.ip_address(ip) in self._subred
        except ValueError:
            return False

    def _en_linea(self, d):
        return time.time() - d.get("ultima_vez", 0) < max(180, 3 * self.intervalos["barrido"])

    def _actualizar_trafico(self):
        if not self.contador or not getattr(self.contador, "activo", False):
            return
        ahora, totales = time.time(), self.contador.totales()
        antes_ts, antes = self._ultimo_trafico
        dt = max(ahora - antes_ts, 0.001)
        por_ip = {d["ip"]: d for d in self.dispositivos.values()}
        for d in self.dispositivos.values():
            d["bajada_bps"] = d["subida_bps"] = 0
        for ip, (bajada, subida) in totales.items():
            d = por_ip.get(ip)
            if not d:
                continue
            b0, s0 = antes.get(ip, (bajada, subida))
            d["bajada_bps"] = max(0, bajada - b0) * 8 / dt
            d["subida_bps"] = max(0, subida - s0) * 8 / dt
            d["bajada_total"], d["subida_total"] = bajada, subida
        self._ultimo_trafico = (ahora, totales)

    # ------------------------------------------------------------------ fallos
    def _evaluar_alertas(self):
        """Calcula qué fallos hay AHORA. Los que desaparecen pasan a 'recientes'."""
        nuevas = {}

        def alerta(id_, nivel, titulo, detalle, consejo):
            nuevas[id_] = {"id": id_, "nivel": nivel, "titulo": titulo,
                           "detalle": detalle, "consejo": consejo}

        h = list(self.historial)
        ult = h[-3:]
        if len(ult) == 3 and all(r is None for _, r, _, _ in ult):
            alerta("router", "critico", "El router no responde",
                   f"El router ({self.red['router']}) no contesta desde hace 15 s.",
                   "Comprueba que está encendido y las luces. Apágalo 30 s y vuelve a "
                   "encenderlo. Si este equipo va por Wi-Fi, mira que siga conectado.")
        elif len(ult) == 3 and all(i is None for _, _, i, _ in ult):
            alerta("internet", "critico", "Sin conexión a internet",
                   "El router responde, pero no se llega a internet.",
                   "Mira la luz de internet/WAN del router. Reinicia el router y, si "
                   "sigue igual, la ONT/fibra. Si persiste, es una avería de tu "
                   "proveedor: llama a su soporte.")
        elif len(ult) >= 2 and all(d is None for _, _, _, d in ult[-2:]):
            alerta("dns", "alto", "Las webs no cargan (fallo de DNS)",
                   "Hay internet, pero no se pueden traducir nombres como google.com.",
                   "En el router, cambia los servidores DNS a 1.1.1.1 y 9.9.9.9 "
                   "(o 8.8.8.8). Reiniciar el router suele arreglarlo temporalmente.")

        ventana = h[-60:]  # últimos 5 minutos
        if len(ventana) >= 12 and "internet" not in nuevas and "router" not in nuevas:
            perdidos = sum(1 for _, _, i, _ in ventana if i is None)
            pct = 100 * perdidos / len(ventana)
            if pct >= 5:
                alerta("perdida", "medio", f"Conexión inestable ({pct:.0f}% de cortes)",
                       "Se pierden paquetes hacia internet en los últimos 5 minutos.",
                       "Suele notarse en videollamadas y juegos. Reinicia el router; si "
                       "pasa a menudo, revisa el cable de la fibra/ADSL o avisa al proveedor.")
        reciente = h[-12:]  # último minuto
        lat_int = _media(i for _, _, i, _ in reciente)
        lat_rou = _media(r for _, r, _, _ in reciente)
        if lat_int is not None and lat_int > 150:
            alerta("latencia", "medio", "Internet va lento",
                   f"La latencia media a internet es de {lat_int:.0f} ms (lo normal: < 50 ms).",
                   "Mira abajo qué dispositivo está gastando más ahora mismo: una descarga "
                   "o una copia en la nube satura la conexión.")
        if lat_rou is not None and lat_rou > 30:
            alerta("wifi", "medio", "El Wi-Fi va saturado o con mala señal",
                   f"El router tarda {lat_rou:.0f} ms en responder (lo normal: < 10 ms).",
                   "Acerca este equipo al router o usa cable. Cambia el canal Wi-Fi en el "
                   "router, o usa la banda de 5 GHz.")

        sin_nombre = 0
        for mac, d in self.dispositivos.items():
            if not self._en_linea(d):
                continue
            reg = self.registro.get(mac, {})
            nombre = reg.get("nombre") or d["nombre_red"] or d["ip"]
            if not reg.get("nombre"):
                sin_nombre += 1
                if reg.get("nuevo") and time.time() - reg.get("primera_vez", 0) < 86400:
                    alerta(f"nuevo:{mac}", "medio", "Dispositivo nuevo en la red",
                           f"{nombre} ({d['ip']}, {mac}) se ha conectado por primera vez.",
                           "Si es de alguien de casa, ponle nombre en la lista. Si nadie lo "
                           "reconoce, cambia la contraseña del Wi-Fi.")
            for p in d.get("puertos", []):
                alerta(f"puerto:{mac}:{p}", "alto",
                       f"{nombre}: puerto {p} abierto",
                       f"{PUERTOS_PELIGROSOS.get(p, 'Servicio')} accesible desde la red de casa.",
                       "Si no lo usas, desactívalo en ese equipo (o en el router si es el "
                       "router). Si lo usas, pon una contraseña fuerte y no lo abras a internet.")
        if sin_nombre:
            alerta("sin_nombre", "info", f"{sin_nombre} dispositivo(s) sin nombre",
                   "Ponerles nombre ayuda a detectar intrusos.",
                   "Toca el nombre de cada dispositivo en la lista para cambiarlo.")

        ahora = time.time()
        for id_, a in nuevas.items():
            a["desde"] = self.alertas.get(id_, {}).get("desde", ahora)
        for id_, a in self.alertas.items():
            if id_ not in nuevas and a["nivel"] != "info":
                self.recientes.appendleft(dict(a, hasta=ahora))
        self.alertas = nuevas

    # ------------------------------------------------------------------ estado
    def estado(self):
        with self._lock:
            h = list(self.historial)
            ultimo = h[-1] if h else (None, None, None, None)
            ventana = h[-60:]
            perdida = (100 * sum(1 for x in ventana if x[2] is None) / len(ventana)) if ventana else None
            disp = []
            for mac, d in self.dispositivos.items():
                reg = self.registro.get(mac, {})
                disp.append({
                    "mac": mac, "ip": d["ip"], "nombre": reg.get("nombre", ""),
                    "nombre_red": d["nombre_red"], "en_linea": self._en_linea(d),
                    "privada": mac_es_privada(mac), "es_router": d["ip"] == self.red["router"],
                    "es_este_equipo": d["ip"] == self.red["ip_local"],
                    "puertos": [{"puerto": p, "desc": PUERTOS_PELIGROSOS.get(p, "")}
                                for p in d.get("puertos", [])],
                    "bajada_bps": d["bajada_bps"], "subida_bps": d["subida_bps"],
                    "bajada_total": d["bajada_total"], "subida_total": d["subida_total"],
                    "primera_vez": reg.get("primera_vez"), "ultima_vez": d.get("ultima_vez"),
                })
            disp.sort(key=lambda x: (not x["en_linea"], -(x["bajada_bps"] + x["subida_bps"]),
                                     -(x["bajada_total"] + x["subida_total"]), x["ip"]))
            alertas = sorted(self.alertas.values(), key=lambda a: (NIVELES[a["nivel"]], a["desde"]))
            peor = alertas[0]["nivel"] if alertas else None
            if peor == "critico":
                resumen = ("problema", alertas[0]["titulo"])
            elif peor in ("alto", "medio"):
                n = sum(1 for a in alertas if a["nivel"] != "info")
                resumen = ("aviso", f"{n} cosa(s) a revisar")
            else:
                resumen = ("ok", "Todo funciona bien")
            trafico = {"activo": bool(self.contador and getattr(self.contador, "activo", False)),
                       "mensaje": getattr(self.contador, "error", None) if self.contador else
                       "Medición de consumo desactivada"}
            return {
                "modo": self.sondas.modo,
                "actualizado": ultimo[0],
                "red": self.red,
                "resumen": {"estado": resumen[0], "texto": resumen[1]},
                "actual": {"router_ms": ultimo[1], "internet_ms": ultimo[2], "dns_ms": ultimo[3],
                           "perdida_pct": perdida,
                           "en_linea": sum(1 for d in disp if d["en_linea"])},
                "historial": [[round(t), r, i, dn] for t, r, i, dn in h[-120:]],
                "alertas": alertas,
                "recientes": list(self.recientes)[:10],
                "dispositivos": disp,
                "trafico": trafico,
            }
