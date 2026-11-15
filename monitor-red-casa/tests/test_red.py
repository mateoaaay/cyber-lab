import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from red import (mac_es_privada, parsear_arp, parsear_gateway, parsear_ping,
                 parsear_proc_arp, parsear_ssid)
from servidor import Autenticacion, ip_de_casa


class TestParsers(unittest.TestCase):
    def test_ping_linux(self):
        self.assertEqual(parsear_ping("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=14.2 ms"), 14.2)

    def test_ping_windows_es(self):
        self.assertEqual(parsear_ping("Respuesta desde 8.8.8.8: bytes=32 tiempo=23ms TTL=117"), 23)
        self.assertEqual(parsear_ping("Respuesta desde 192.168.1.1: bytes=32 tiempo<1m TTL=64"), 1)

    def test_ping_sin_respuesta(self):
        self.assertIsNone(parsear_ping("Host de destino inaccesible."))

    def test_gateway(self):
        self.assertEqual(parsear_gateway("default via 192.168.1.1 dev wlan0 proto dhcp"), "192.168.1.1")
        self.assertEqual(parsear_gateway("   route to: default\n    gateway: 10.0.0.1\n"), "10.0.0.1")
        win = "Destino de red   Máscara de red   Puerta de enlace   Interfaz  Métrica\n" \
              "          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.20     25\n"
        self.assertEqual(parsear_gateway(win), "192.168.0.1")

    def test_arp_macos_y_windows(self):
        mac = "? (192.168.1.20) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n" \
              "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
        self.assertEqual(parsear_arp(mac), {"192.168.1.20": "00:1a:2b:3c:4d:5e"})
        win = "  192.168.1.1           a4-91-b1-10-00-01     dinámico\n" \
              "  224.0.0.22            01-00-5e-00-00-16     estático\n"
        self.assertEqual(parsear_arp(win), {"192.168.1.1": "a4:91:b1:10:00:01"})

    def test_proc_arp(self):
        texto = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                 "192.168.1.1      0x1         0x2         a4:91:b1:10:00:01     *        wlan0\n"
                 "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n")
        self.assertEqual(parsear_proc_arp(texto), {"192.168.1.1": "a4:91:b1:10:00:01"})

    def test_ssid(self):
        self.assertEqual(parsear_ssid("yes:MiFibra-A3F2\nno:Vecino\n"), "MiFibra-A3F2")
        self.assertEqual(parsear_ssid("Current Wi-Fi Network: Casa\n"), "Casa")
        self.assertEqual(parsear_ssid("    SSID   : Casa 5G\n    BSSID  : aa:bb:cc:dd:ee:ff\n"), "Casa 5G")
        self.assertEqual(parsear_ssid("Casa\n"), "Casa")

    def test_mac_privada(self):
        self.assertTrue(mac_es_privada("da:11:4e:10:00:11"))
        self.assertFalse(mac_es_privada("a4:91:b1:10:00:01"))


class TestSeguridad(unittest.TestCase):
    def test_solo_red_de_casa(self):
        for ip in ("192.168.1.5", "10.0.0.2", "172.16.4.4", "127.0.0.1", "::1", "fe80::1"):
            self.assertTrue(ip_de_casa(ip), ip)
        for ip in ("8.8.8.8", "81.45.2.1", "basura"):
            self.assertFalse(ip_de_casa(ip), ip)

    def test_tokens(self):
        auth = Autenticacion("clave-familia", b"secreto")
        token = auth.crear_token()
        self.assertTrue(auth.token_valido(token))
        self.assertFalse(auth.token_valido(token[:-1] + ("0" if token[-1] != "0" else "1")))
        self.assertFalse(Autenticacion("x", b"otro").token_valido(token))
        caducado = f"{int(time.time()) - 1}." + token.split(".")[1]
        self.assertFalse(auth.token_valido(caducado))

    def test_clave_y_freno(self):
        auth = Autenticacion("clave-familia", b"s")
        self.assertFalse(auth.comprobar_clave("192.168.1.5", "mala"))
        # Justo después de un fallo hay que esperar, aunque se acierte.
        self.assertFalse(auth.comprobar_clave("192.168.1.5", "clave-familia"))
        self.assertTrue(auth.comprobar_clave("192.168.1.6", "clave-familia"))


class TestMonitor(unittest.TestCase):
    def test_alertas_router_caido(self):
        from monitor import Monitor

        class Sondas:
            modo = "test"

        m = Monitor(Sondas(), conocidos={})
        m.red = {"router": "192.168.1.1", "ip_local": "192.168.1.10", "subred": "192.168.1.0/24"}
        for i in range(3):
            m.historial.append((time.time() + i, None, None, None))
        m._evaluar_alertas()
        self.assertIn("router", m.alertas)
        self.assertNotIn("internet", m.alertas)  # un solo aviso, el de la causa
        m.historial.append((time.time() + 5, 2.0, 20.0, 10.0))
        m._evaluar_alertas()
        self.assertNotIn("router", m.alertas)
        self.assertEqual(m.recientes[0]["id"], "router")


class TestAnalisis(unittest.TestCase):
    def _monitor(self, **opciones):
        from monitor import Monitor

        class Sondas:
            modo = "test"

        m = Monitor(Sondas(), conocidos={}, opciones=opciones)
        m.red = {"router": "192.168.1.1", "ip_local": "192.168.1.10", "subred": "192.168.1.0/24", "wifi": "Casa"}
        return m

    def test_red_sana_saca_buena_nota(self):
        m = self._monitor(velocidad_contratada=600)
        for i in range(60):
            m.historial.append((time.time() + i, 3.0, 20.0, 10.0))
        m.velocidad.update(bajada=560, subida=280, ts=time.time())
        m.upnp = False
        an = m.estado()["analisis"]
        self.assertEqual(an["nota"], 100)
        self.assertEqual(an["etiqueta"], "Buena")

    def test_problemas_bajan_la_nota_y_salen_primero(self):
        m = self._monitor(velocidad_contratada=600)
        for i in range(60):
            m.historial.append((time.time() + i, 40.0, None if i % 5 == 0 else 180.0, 10.0))
        m.velocidad.update(bajada=200, subida=50, ts=time.time())
        m.upnp = True
        m._evaluar_alertas()
        estado = m.estado()
        an = estado["analisis"]
        self.assertLess(an["nota"], 60)
        self.assertEqual(an["items"][0]["estado"], "mal")
        self.assertIn("velocidad", {a["id"] for a in estado["alertas"]})

    def test_medir_velocidad_no_se_repite_enseguida(self):
        m = self._monitor()
        m.velocidad["ts"] = time.time()
        self.assertFalse(m.medir_velocidad_ahora())


if __name__ == "__main__":
    unittest.main()
