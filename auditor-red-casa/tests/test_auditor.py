"""Pruebas sin red real: salidas de ejemplo y un router UPnP simulado."""
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor import equipo, red, upnp  # noqa: E402

NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
 <address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="Sagemcom"/>
 <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lighttpd"/></port>
        <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host>
<host><status state="up"/><address addr="192.168.1.50" addrtype="ipv4"/>
 <address addr="AA:BB:CC:00:00:02" addrtype="mac" vendor="Espressif"/>
 <hostnames><hostname name="camara"/></hostnames>
 <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
        <port protocol="tcp" portid="445"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.99" addrtype="ipv4"/></host>
</nmaprun>"""

SRV = "urn:schemas-upnp-org:service:WANIPConnection:1"


class RouterFalso(BaseHTTPRequestHandler):
    mapeos = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        cuerpo = (f"<root xmlns='urn:schemas-upnp-org:device-1-0'><device><serviceList><service>"
                  f"<serviceType>{SRV}</serviceType><controlURL>/ctl</controlURL>"
                  f"</service></serviceList></device></root>").encode()
        self.send_response(200); self.end_headers(); self.wfile.write(cuerpo)

    def do_POST(self):
        datos = self.rfile.read(int(self.headers["Content-Length"])).decode()
        accion = self.headers["SOAPAction"].strip('"').split("#")[1]
        campo = lambda n: datos.split(f"<{n}>")[1].split(f"</{n}>")[0]
        if accion == "GetGenericPortMappingEntry":
            i = int(campo("NewPortMappingIndex"))
            if i >= len(self.mapeos):
                self.send_response(500); self.end_headers(); return
            ext, proto, cli, inte = self.mapeos[i]
            interior = (f"<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort>"
                        f"<NewProtocol>{proto}</NewProtocol><NewInternalPort>{inte}</NewInternalPort>"
                        f"<NewInternalClient>{cli}</NewInternalClient>"
                        f"<NewPortMappingDescription>cam &amp; p2p</NewPortMappingDescription>")
        else:
            ext, proto = int(campo("NewExternalPort")), campo("NewProtocol")
            type(self).mapeos = [m for m in self.mapeos if (m[0], m[1]) != (ext, proto)]
            interior = ""
        cuerpo = (f"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>"
                  f"<u:{accion}Response xmlns:u='{SRV}'>{interior}</u:{accion}Response></s:Body></s:Envelope>").encode()
        self.send_response(200); self.end_headers(); self.wfile.write(cuerpo)


class TestRed(unittest.TestCase):
    def test_interpreta_nmap(self):
        eqs = red.interpretar_nmap(NMAP_XML)
        self.assertEqual([e.ip for e in eqs], ["192.168.1.1", "192.168.1.50"])
        self.assertEqual([p.numero for p in eqs[0].puertos], [80, 23])
        self.assertEqual([p.numero for p in eqs[1].puertos], [80])  # el cerrado no cuenta
        self.assertEqual(eqs[1].nombre, "camara")

    def test_hallazgos_puertos(self):
        hs = red.hallazgos_puertos(red.interpretar_nmap(NMAP_XML), "192.168.1.1")
        self.assertEqual(sorted(h.codigo for h in hs), ["PUERTO-23", "PUERTO-80"])  # el 80 solo en el router
        self.assertEqual(next(h for h in hs if h.codigo == "PUERTO-23").gravedad, "alta")

    def test_solo_redes_privadas_y_pequenas(self):
        self.assertEqual(str(red.validar_red("192.168.1.37/24")), "192.168.1.0/24")
        for mala in ("8.8.8.0/24", "10.0.0.0/8", "127.0.0.0/24", "hola"):
            with self.assertRaises(red.ErrorRed):
                red.validar_red(mala)

    def test_inventario(self, ):
        import tempfile
        eqs = red.interpretar_nmap(NMAP_XML)
        self.assertEqual(red.hallazgos_inventario(eqs, {}, "192.168.1.10")[0].codigo, "INVENTARIO-VACIO")
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "c.json"
            inv = red.guardar_inventario(ruta, eqs[:1], {})
            self.assertEqual(json.loads(ruta.read_text()), inv)
        hs = red.hallazgos_inventario(eqs, inv, "192.168.1.10")
        self.assertEqual(len(hs), 1)
        self.assertIn("192.168.1.50", hs[0].objetivo)


class TestUPnP(unittest.TestCase):
    def setUp(self):
        RouterFalso.mapeos = [(8080, "TCP", "192.168.1.50", 80), (5000, "UDP", "192.168.1.60", 5000)]
        self.srv = HTTPServer(("127.0.0.1", 0), RouterFalso)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/desc.xml"

    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()

    def test_lista_y_cierra_puertos(self):
        hs = upnp.hallazgos_upnp([self.url])
        self.assertEqual([h.codigo for h in hs], ["UPNP-ACTIVO", "UPNP-MAPEO", "UPNP-MAPEO"])
        self.assertFalse(hs[0].automatico)
        self.assertIn("cam & p2p", hs[1].detalle)
        self.assertIn("8080/TCP", hs[1].arreglo())
        self.assertEqual(RouterFalso.mapeos, [(5000, "UDP", "192.168.1.60", 5000)])

    def test_router_anunciado_dos_veces_no_duplica(self):
        hs = upnp.hallazgos_upnp([self.url, self.url.replace("desc.xml", "desc2.xml")])
        self.assertEqual([h.codigo for h in hs], ["UPNP-ACTIVO", "UPNP-MAPEO", "UPNP-MAPEO"])

    def test_ignora_descripciones_fuera_de_la_lan(self):
        self.assertFalse(upnp._es_local("http://8.8.8.8/desc.xml"))
        self.assertTrue(upnp._es_local("http://192.168.1.1:5000/desc.xml"))


class TestEquipo(unittest.TestCase):
    def test_interpreta_ss(self):
        salida = ('LISTEN 0 128 0.0.0.0:23 0.0.0.0:* users:(("inetd",pid=812,fd=4))\n'
                  'LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n'
                  'LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=900,fd=3))\n')
        self.assertEqual(equipo.interpretar_ss(salida), [("0.0.0.0", 23, 812), ("127.0.0.1", 631, None), ("::", 22, 900)])

    def test_interpreta_nmcli(self):
        self.assertEqual(equipo.interpretar_nmcli("no:Vecino:WPA2\nyes:Casa:WPA1 WPA2\n"), ("Casa", "WPA1 WPA2"))
        self.assertIsNone(equipo.interpretar_nmcli("no:Vecino:WPA2\n"))


if __name__ == "__main__":
    unittest.main()
