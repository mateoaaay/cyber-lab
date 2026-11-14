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
                 conocidos=None, intervalos=None, ruta_consumo=None, opciones=None):
        self.sondas = sondas
        self.contador = contador
        self.ruta = ruta_dispositivos
        self.ruta_consumo = ruta_consumo
        self.opciones = opciones or {}
        self.intervalos = {"salud": 5, "barrido": 60, "puertos": 600, "router": 1800,
                           "velocidad": 3600 * float(self.opciones.get("horas_entre_tests", 3))}
        self.intervalos.update(intervalos or {})
        self.velocidad = {"bajada": None, "subida": None, "ts": None,
                          "midiendo": False, "error": None}
        self.historial_velocidad = deque(maxlen=56)  # ~1 semana de tests
        self.upnp = None
        self.hoy = self._cargar_consumo()
        self._guardado_consumo = 0

        self._lock = threading.Lock()
        self.historial = deque(maxlen=720)          # 1 h a 5 s: (ts, router, internet, dns)
        self.dispositivos = {}                      # mac -> info
        self.alertas = {}                           # id -> alerta activa
        self.recientes = deque(maxlen=30)           # alertas ya resueltas
        self.red = {"ip_local": None, "router": None, "subred": None, "wifi": None}
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

    def _cargar_consumo(self):
        vacio = {"fecha": time.strftime("%Y-%m-%d"), "consumo": {}}
        if self.ruta_consumo and os.path.exists(self.ruta_consumo):
            try:
                with open(self.ruta_consumo, encoding="utf-8") as f:
                    datos = json.load(f)
                if datos.get("fecha") == vacio["fecha"]:
                    return datos
            except (OSError, ValueError):
                pass
        return vacio

    def _guardar_consumo(self):
        if not self.ruta_consumo:
            return
        tmp = self.ruta_consumo + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.hoy, f)
        os.replace(tmp, self.ruta_consumo)
        self._guardado_consumo = time.time()

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
                                    (self._tick_puertos, "puertos"),
                                    (self._tick_router, "router"),
                                    (self._tick_velocidad, "velocidad")):
            threading.Thread(target=self._bucle, args=(objetivo, intervalo),
                             daemon=True).start()

    def _bucle(self, funcion, clave):
        if clave in ("puertos", "velocidad"):
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
                    "subred": str(subred) if subred else None,
                    "wifi": self.sondas.nombre_wifi()}
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

    def _tick_router(self):
        if self.red["router"]:
            resultado = self.sondas.upnp(self.red["router"])
            with self._lock:
                self.upnp = resultado
                self._evaluar_alertas()

    def _tick_velocidad(self):
        self._medir_velocidad()

    def medir_velocidad_ahora(self):
        """Lanza un test de velocidad en segundo plano (como mucho 1 por minuto)."""
        with self._lock:
            if self.velocidad["midiendo"] or time.time() - (self.velocidad["ts"] or 0) < 60:
                return False
            self.velocidad["midiendo"] = True
        threading.Thread(target=self._medir_velocidad, daemon=True).start()
        return True

    def _medir_velocidad(self):
        with self._lock:
            self.velocidad["midiendo"] = True
        try:
            bajada, subida = self.sondas.velocidad()
            error = None
        except Exception as e:  # sin internet, proxy, etc.
            bajada = subida = None
            error = f"No se pudo medir: {e}"
            log.warning(error)
        with self._lock:
            self.velocidad.update({"bajada": bajada, "subida": subida, "ts": time.time(),
                                   "midiendo": False, "error": error})
            if bajada is not None:
                self.historial_velocidad.append((time.time(), bajada, subida))
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
            db, ds = max(0, bajada - b0), max(0, subida - s0)
            d["bajada_bps"] = db * 8 / dt
            d["subida_bps"] = ds * 8 / dt
            d["bajada_total"], d["subida_total"] = bajada, subida
            dia = self.hoy["consumo"].setdefault(d["mac"], [0, 0])
            dia[0] += db
            dia[1] += ds
        self._ultimo_trafico = (ahora, totales)
        hoy = time.strftime("%Y-%m-%d")
        if self.hoy["fecha"] != hoy:
            self.hoy = {"fecha": hoy, "consumo": {}}
        if ahora - self._guardado_consumo > 60:
            self._guardar_consumo()

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

        contratada = self.opciones.get("velocidad_contratada")
        v = self.velocidad
        if contratada and v["bajada"] is not None and v["bajada"] < 0.5 * contratada:
            alerta("velocidad", "medio", "La velocidad está muy por debajo de lo contratado",
                   f"Último test: {v['bajada']:.0f} Mb/s de bajada; tienes contratados {contratada:.0f}.",
                   "Repite la medición con cable. Si con cable también sale baja, reinicia el "
                   "router; si sigue así, reclama a tu proveedor con estas mediciones.")

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

    # ---------------------------------------------------------------- análisis
    def _analisis(self, disp):
        """Revisión completa de la red con una nota de 0 a 100 y recomendaciones."""
        items = []

        def item(estado, titulo, detalle, consejo="", peso=0):
            items.append({"estado": estado, "titulo": titulo, "detalle": detalle,
                          "consejo": consejo, "peso": peso})

        h = list(self.historial)  # última hora
        if len(h) >= 12:
            perdida = 100 * sum(1 for x in h if x[2] is None) / len(h)
            minutos = len(h) * self.intervalos["salud"] / 60
            item("ok" if perdida < 1 else "mejorar" if perdida < 5 else "mal",
                 "Estabilidad de la conexión",
                 f"{perdida:.1f}% de cortes en los últimos {minutos:.0f} min.",
                 "Muchos cortes suelen ser del router o de la línea. Reinicia el router; si "
                 "continúa, revisa el cable de fibra/ADSL y avisa a tu proveedor.", 20)
            lat = _media(x[2] for x in h)
            if lat is not None:
                item("ok" if lat < 50 else "mejorar" if lat < 100 else "mal",
                     "Rapidez de respuesta de internet (ping)",
                     f"{lat:.0f} ms de media (bueno: menos de 50 ms).",
                     "Un ping alto se nota en juegos y videollamadas. Suele subir cuando alguien "
                     "descarga o sube algo grande: mira quién consume más.", 15)
            lat_r = _media(x[1] for x in h)
            if lat_r is not None:
                item("ok" if lat_r < 10 else "mejorar" if lat_r < 30 else "mal",
                     "Calidad del Wi-Fi",
                     f"El router responde en {lat_r:.0f} ms de media (bueno: menos de 10 ms).",
                     "Pon el router en un sitio alto y despejado, lejos de microondas y del "
                     "suelo. Usa la banda de 5 GHz cerca del router y cable para la tele y la "
                     "consola. En casas grandes, un sistema Wi-Fi mesh ayuda.", 15)
            dns = [x[3] for x in h]
            fallos = sum(1 for x in dns if x is None)
            media_dns = _media(dns)
            if media_dns is not None or fallos:
                malo = fallos > len(dns) * 0.05 or (media_dns or 999) > 150
                item("mal" if malo else "mejorar" if (media_dns or 0) > 60 else "ok",
                     "DNS (traducir nombres de webs)",
                     f"{media_dns or 0:.0f} ms de media, {fallos} fallos.",
                     "Pon en el router los DNS 1.1.1.1 y 9.9.9.9: suelen ser más rápidos que "
                     "los del proveedor y bloquean webs maliciosas (9.9.9.9).", 10)
        else:
            item("info", "Analizando la conexión", "Hacen falta un par de minutos de datos.")

        v, contratada = self.velocidad, self.opciones.get("velocidad_contratada")
        if v["bajada"] is not None:
            texto = f"{v['bajada']:.0f} Mb/s de bajada y {v['subida']:.0f} Mb/s de subida."
            if contratada:
                r = v["bajada"] / contratada
                item("ok" if r >= 0.8 else "mejorar" if r >= 0.5 else "mal", "Velocidad de internet",
                     f"{texto} Contratado: {contratada:.0f} Mb/s ({100 * r:.0f}%).",
                     "Por Wi-Fi es normal perder velocidad. Si con cable tampoco llega al 80%, "
                     "reinicia el router y, si sigue, reclama al proveedor.", 15)
            else:
                item("ok" if v["bajada"] >= 100 else "mejorar" if v["bajada"] >= 25 else "mal",
                     "Velocidad de internet",
                     f"{texto} Con 100 Mb/s o más va sobrada para varias teles en 4K a la vez.",
                     "Indica tu velocidad contratada en config.json (velocidad_contratada) para "
                     "comprobar si te dan lo que pagas.", 15)
        elif v["error"]:
            item("info", "Velocidad de internet", v["error"])
        else:
            item("info", "Velocidad de internet", "Pendiente de la primera medición.")

        con_puertos = [d for d in disp if d["puertos"] and d["en_linea"]]
        item("mal" if con_puertos else "ok", "Puertos peligrosos abiertos",
             ("; ".join(f"{d['nombre'] or d['ip']}: " + ", ".join(str(p["puerto"]) for p in d["puertos"])
                        for d in con_puertos)) if con_puertos else
             "Ningún equipo tiene abiertos Telnet, FTP, SMB, escritorio remoto ni VNC.",
             "Desactiva en cada equipo los servicios que no uses (compartir carpetas, escritorio "
             "remoto…). Si es el router, hazlo desde su panel de administración.", 15)

        if self.upnp is not None:
            item("mejorar" if self.upnp else "ok", "UPnP en el router",
                 "Está activado: cualquier programa de casa puede abrir puertos hacia internet "
                 "sin preguntar." if self.upnp else "Está desactivado.",
                 "Entra al panel del router y desactiva UPnP. Si alguna consola deja de "
                 "funcionar online, vuelve a activarlo o abre solo sus puertos a mano.", 5)

        en_linea = [d for d in disp if d["en_linea"]]
        sin_nombre = [d for d in en_linea if not d["nombre"]]
        item("mejorar" if sin_nombre else "ok", "Dispositivos identificados",
             f"{len(en_linea) - len(sin_nombre)} de {len(en_linea)} conectados tienen nombre.",
             "Pon nombre a cada dispositivo: si aparece uno que nadie conoce, cambia la "
             "contraseña del Wi-Fi (WPA2/WPA3, mínimo 12 caracteres).", 5)

        total_hoy = sum(d["hoy_bajada"] + d["hoy_subida"] for d in disp)
        if total_hoy > 0:
            top = max(disp, key=lambda d: d["hoy_bajada"] + d["hoy_subida"])
            pct = 100 * (top["hoy_bajada"] + top["hoy_subida"]) / total_hoy
            item("info", "Quién más ha gastado hoy",
                 f"{top['nombre'] or top['nombre_red'] or top['ip']}: {pct:.0f}% del consumo de hoy.")

        nota = 100
        for it in items:
            nota -= it["peso"] if it["estado"] == "mal" else it["peso"] / 2 if it["estado"] == "mejorar" else 0
        nota = max(0, round(nota))
        orden = {"mal": 0, "mejorar": 1, "info": 2, "ok": 3}
        items.sort(key=lambda it: orden[it["estado"]])
        return {"nota": nota, "etiqueta": "Buena" if nota >= 85 else "Mejorable" if nota >= 60 else "Mala",
                "items": items}

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
                    "hoy_bajada": self.hoy["consumo"].get(mac, [0, 0])[0],
                    "hoy_subida": self.hoy["consumo"].get(mac, [0, 0])[1],
                    "primera_vez": reg.get("primera_vez"), "ultima_vez": d.get("ultima_vez"),
                })
            disp.sort(key=lambda x: (not x["en_linea"], -(x["bajada_bps"] + x["subida_bps"]),
                                     -(x["hoy_bajada"] + x["hoy_subida"]), x["ip"]))
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
                "velocidad": dict(self.velocidad,
                                  contratada=self.opciones.get("velocidad_contratada")),
                "historial_velocidad": [[round(t), b, s_] for t, b, s_ in self.historial_velocidad],
                "uso": {"bajada_bps": sum(d["bajada_bps"] for d in disp),
                        "subida_bps": sum(d["subida_bps"] for d in disp),
                        "hoy": sum(d["hoy_bajada"] + d["hoy_subida"] for d in disp)},
                "analisis": self._analisis(disp),
            }
