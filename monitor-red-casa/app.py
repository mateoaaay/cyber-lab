#!/usr/bin/env python3
"""Monitor de la red de casa.

    python3 app.py --demo          # prueba con una red simulada
    sudo python3 app.py            # red real (sudo hace falta para medir consumo)

Luego abre http://<ip-de-este-equipo>:8080 desde cualquier móvil o PC de casa.
"""

import argparse
import json
import logging
import os
import secrets
import sys

from monitor import Monitor
from servidor import Autenticacion, crear_servidor

AQUI = os.path.dirname(os.path.abspath(__file__))
DATOS = os.path.join(AQUI, "datos")


def leer_config(ruta):
    if ruta and os.path.exists(ruta):
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)
    return {}


def secreto_persistente(nombre, generar):
    """Lee un valor de datos/<nombre> o lo crea la primera vez."""
    os.makedirs(DATOS, exist_ok=True)
    ruta = os.path.join(DATOS, nombre)
    if os.path.exists(ruta):
        with open(ruta, "rb") as f:
            return f.read().strip(), False
    valor = generar()
    with open(ruta, "wb") as f:
        f.write(valor)
    try:
        os.chmod(ruta, 0o600)
    except OSError:
        pass
    return valor, True


def main():
    p = argparse.ArgumentParser(description="Monitor de la red de casa")
    p.add_argument("--demo", action="store_true", help="usar una red simulada")
    p.add_argument("--puerto", type=int, default=8080)
    p.add_argument("--host", default="0.0.0.0", help="dirección donde escuchar")
    p.add_argument("--config", default=os.path.join(AQUI, "config.json"))
    p.add_argument("--sin-trafico", action="store_true", help="no medir consumo (sin scapy)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = leer_config(args.config)

    if args.demo:
        from demo import ContadorDemo, SondasDemo, conocidos
        sondas = SondasDemo()
        contador = ContadorDemo(sondas)
        monitor = Monitor(sondas, contador, conocidos=conocidos(),
                          intervalos={"salud": 2, "barrido": 10, "puertos": 15})
    else:
        from red import SondasReales
        from trafico import ContadorTrafico
        sondas = SondasReales(config)
        contador = None
        if not args.sin_trafico:
            subred = sondas.subred()
            if subred:
                contador = ContadorTrafico(subred, config.get("interfaz"))
                if not contador.iniciar():
                    logging.warning(contador.error)
        os.makedirs(DATOS, exist_ok=True)
        monitor = Monitor(sondas, contador, ruta_dispositivos=os.path.join(DATOS, "dispositivos.json"))

    clave = config.get("clave") or os.environ.get("MONITOR_CLAVE")
    nueva = False
    if not clave:
        valor, nueva = secreto_persistente("clave.txt", lambda: secrets.token_urlsafe(8).encode())
        clave = valor.decode()
    secreto, _ = secreto_persistente("secreto.bin", lambda: secrets.token_hex(32).encode())

    monitor.iniciar()
    servidor = crear_servidor(monitor, Autenticacion(clave, secreto), args.host, args.puerto)
    ip = "localhost" if args.demo else (monitor.red.get("ip_local") or "localhost")
    print(f"\n  Monitor de red de casa {'(DEMO) ' if args.demo else ''}en marcha")
    print(f"  Ábrelo desde cualquier dispositivo de casa: http://{ip}:{args.puerto}")
    if nueva:
        print(f"  Contraseña para la familia (guardada en datos/clave.txt): {clave}")
    print("  Ctrl+C para parar.\n")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nHasta luego.")
        sys.exit(0)


if __name__ == "__main__":
    main()
