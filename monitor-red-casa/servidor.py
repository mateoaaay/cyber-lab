"""Servidor web de la app. Solo acepta conexiones desde la red de casa y pide
una contraseña común para la familia."""

import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

log = logging.getLogger("servidor")

ESTATICOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
DURACION_SESION = 30 * 24 * 3600  # 30 días: en casa no queremos login a diario
ARCHIVOS_PUBLICOS = {"/estilo.css", "/favicon.svg", "/login.js"}


class Autenticacion:
    def __init__(self, clave, secreto):
        self._clave = hashlib.sha256(clave.encode()).digest()
        self._secreto = secreto
        self._fallos = {}

    def comprobar_clave(self, ip, intento):
        # Freno simple contra quien pruebe contraseñas a lo bruto.
        n, hasta = self._fallos.get(ip, (0, 0))
        if time.time() < hasta:
            return False
        ok = hmac.compare_digest(hashlib.sha256(intento.encode()).digest(), self._clave)
        if ok:
            self._fallos.pop(ip, None)
        else:
            n += 1
            self._fallos[ip] = (n, time.time() + (60 if n >= 5 else 1))
        return ok

    def crear_token(self):
        caduca = str(int(time.time()) + DURACION_SESION)
        firma = hmac.new(self._secreto, caduca.encode(), hashlib.sha256).hexdigest()
        return f"{caduca}.{firma}"

    def token_valido(self, token):
        try:
            caduca, firma = token.split(".", 1)
            esperado = hmac.new(self._secreto, caduca.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(firma, esperado) and int(caduca) > time.time()
        except (ValueError, AttributeError):
            return False


def ip_de_casa(ip):
    try:
        dir_ = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(dir_, "ipv4_mapped", None):
        dir_ = dir_.ipv4_mapped
    return dir_.is_private or dir_.is_loopback or dir_.is_link_local


def crear_servidor(monitor, auth, host="0.0.0.0", puerto=8080):
    class Manejador(BaseHTTPRequestHandler):
        server_version = "MonitorCasa"
        sys_version = ""

        def log_message(self, formato, *args):
            log.debug("%s %s", self.client_address[0], formato % args)

        # -------------------------------------------------------- respuestas
        def _cabeceras_seguras(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")

        def _enviar(self, codigo, cuerpo, tipo="text/plain; charset=utf-8", extra=None):
            datos = cuerpo if isinstance(cuerpo, bytes) else cuerpo.encode()
            self.send_response(codigo)
            self.send_header("Content-Type", tipo)
            self.send_header("Content-Length", str(len(datos)))
            self.send_header("Cache-Control", "no-store")
            self._cabeceras_seguras()
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(datos)

        def _json(self, obj, codigo=200):
            self._enviar(codigo, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

        def _redirigir(self, destino, extra=None):
            self.send_response(303)
            self.send_header("Location", destino)
            self.send_header("Content-Length", "0")
            self._cabeceras_seguras()
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _estatico(self, nombre):
            ruta = os.path.join(ESTATICOS, nombre)
            try:
                with open(ruta, "rb") as f:
                    datos = f.read()
            except OSError:
                return self._enviar(404, "No encontrado")
            tipo = mimetypes.guess_type(ruta)[0] or "application/octet-stream"
            if tipo.startswith("text/") or tipo.endswith("javascript"):
                tipo += "; charset=utf-8"
            self._enviar(200, datos, tipo)

        # ------------------------------------------------------------ control
        def _permitido(self):
            if not ip_de_casa(self.client_address[0]):
                self._enviar(403, "Solo accesible desde la red de casa.")
                return False
            return True

        def _sesion_ok(self):
            for trozo in self.headers.get("Cookie", "").split(";"):
                nombre, _, valor = trozo.strip().partition("=")
                if nombre == "sesion" and auth.token_valido(valor):
                    return True
            return False

        def _leer_cuerpo(self, maximo=4096):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(min(n, maximo)).decode("utf-8", "replace")

        # -------------------------------------------------------------- rutas
        def do_GET(self):
            if not self._permitido():
                return
            ruta = self.path.split("?", 1)[0]
            if ruta == "/login":
                return self._estatico("login.html")
            if ruta in ARCHIVOS_PUBLICOS:
                return self._estatico(ruta.lstrip("/"))
            if not self._sesion_ok():
                if ruta.startswith("/api/"):
                    return self._json({"error": "sesion"}, 401)
                return self._redirigir("/login")
            if ruta == "/":
                return self._estatico("index.html")
            if ruta == "/app.js":
                return self._estatico("app.js")
            if ruta == "/api/estado":
                return self._json(monitor.estado())
            self._enviar(404, "No encontrado")

        def do_POST(self):
            if not self._permitido():
                return
            ruta = self.path.split("?", 1)[0]
            if ruta == "/login":
                datos = parse_qs(self._leer_cuerpo())
                intento = (datos.get("clave") or [""])[0]
                if auth.comprobar_clave(self.client_address[0], intento):
                    cookie = (f"sesion={auth.crear_token()}; Max-Age={DURACION_SESION}; "
                              "Path=/; HttpOnly; SameSite=Strict")
                    return self._redirigir("/", {"Set-Cookie": cookie})
                time.sleep(1)
                return self._redirigir("/login?error=1")
            if ruta == "/logout":
                return self._redirigir("/login", {"Set-Cookie": "sesion=; Max-Age=0; Path=/"})
            if not self._sesion_ok():
                return self._json({"error": "sesion"}, 401)
            if ruta == "/api/nombre":
                if not self.headers.get("Content-Type", "").startswith("application/json"):
                    return self._json({"error": "tipo"}, 415)
                try:
                    datos = json.loads(self._leer_cuerpo())
                    ok = monitor.poner_nombre(str(datos["mac"]), str(datos.get("nombre", "")))
                except (ValueError, KeyError, TypeError):
                    return self._json({"error": "datos"}, 400)
                return self._json({"ok": ok}, 200 if ok else 404)
            self._enviar(404, "No encontrado")

    return ThreadingHTTPServer((host, puerto), Manejador)
