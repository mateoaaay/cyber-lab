"""Línea de órdenes: detectar → mostrar → arreglar → informe."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import equipo, red, upnp
from .modelo import Hallazgo, ordenar

RAIZ = Path(__file__).resolve().parent.parent
CHECKLIST_ROUTER = [
    "Cambiar la contraseña de administrador del router (la de fábrica está en internet).",
    "WiFi en WPA2-AES o WPA3 con contraseña propia de 16+ caracteres.",
    "Desactivar WPS (el botón/PIN de emparejamiento rápido).",
    "Desactivar la administración remota desde internet (WAN).",
    "Actualizar el firmware del router.",
    "Poner los dispositivos IoT (bombillas, cámaras, enchufes) en la red de invitados.",
]
COLOR = {"alta": "\033[91m", "media": "\033[93m", "baja": "\033[96m", "info": "\033[90m"}


def _c(texto: str, gravedad: str) -> str:
    return f"{COLOR[gravedad]}{texto}\033[0m" if sys.stdout.isatty() else texto


def recoger(args, avisos: list[str]) -> list[Hallazgo]:
    hallazgos: list[Hallazgo] = []

    if not args.sin_red:
        if not red.nmap_disponible():
            avisos.append("nmap no está instalado: se omite el escaneo de la red (sudo apt install nmap).")
        else:
            try:
                local = red.detectar_red()
                if args.red:
                    local.red = red.validar_red(args.red)
                print(f"[*] Red: {local.red} · router: {local.puerta_enlace or '?'} · interfaz: {local.interfaz}")
                print("[*] Buscando equipos conectados...")
                equipos = red.descubrir_equipos(local.red)
                print(f"[*] {len(equipos)} equipos encendidos. Revisando puertos de riesgo...")
                red.escanear_puertos([e for e in equipos if e.ip != local.mi_ip])
                inventario = red.cargar_inventario(args.inventario)
                if args.aprender:
                    inventario = red.guardar_inventario(
                        args.inventario, [e for e in equipos if e.ip != local.mi_ip], inventario)
                    print(f"[*] Inventario guardado en {args.inventario} ({len(inventario)} dispositivos).")
                hallazgos += red.hallazgos_inventario(equipos, inventario, local.mi_ip)
                hallazgos += red.hallazgos_puertos(equipos, local.puerta_enlace)
            except red.ErrorRed as e:
                avisos.append(f"Escaneo de red omitido: {e}")

    if not args.sin_upnp:
        print("[*] Preguntando al router por UPnP...")
        hallazgos += upnp.hallazgos_upnp()

    if not args.sin_equipo:
        print("[*] Revisando este equipo...")
        hallazgos += equipo.hallazgos_equipo()

    if not equipo.es_root():
        avisos.append("Ejecutado sin sudo: no se ven las MAC de los dispositivos ni se puede revisar "
                      "o arreglar el cortafuegos y SSH de este equipo.")
    return ordenar(hallazgos)


def mostrar(hallazgos: list[Hallazgo]) -> None:
    print()
    if not hallazgos:
        print("No se ha detectado ningún fallo con las comprobaciones disponibles.")
        return
    for i, h in enumerate(hallazgos, 1):
        marca = "arreglo automático" if h.automatico else "arreglo manual"
        print(f"{i:>2}. {_c('[' + h.gravedad.upper() + ']', h.gravedad)} {h.titulo}  ({marca})")
        print(f"    Dónde: {h.objetivo}")
        for linea in h.detalle.splitlines():
            print(f"    {linea}")
        print(f"    Qué hacer: {h.recomendacion}")
        print()


def arreglar(hallazgos: list[Hallazgo], sin_preguntar: bool) -> None:
    candidatos = [h for h in hallazgos if h.automatico]
    if not candidatos:
        print("[*] Ninguno de los fallos encontrados tiene arreglo automático.")
        return
    print(f"[*] {len(candidatos)} fallos con arreglo automático.\n")
    for h in candidatos:
        print(f"→ {h.titulo} ({h.objetivo})\n  Acción: {h.arreglo_desc}")
        if not sin_preguntar:
            try:
                resp = input("  ¿Aplicar? [s/N] ").strip().lower()
            except EOFError:
                resp = ""
            if resp not in ("s", "si", "sí", "y"):
                h.estado = "omitido"
                print("  Omitido.\n")
                continue
        try:
            h.resultado = h.arreglo()
            h.estado = "arreglado"
            print(f"  ✔ {h.resultado}\n")
        except Exception as e:  # un arreglo que falla no debe parar los demás
            h.estado, h.resultado = "fallo", str(e)
            print(f"  ✘ No se pudo arreglar: {e}\n")


def escribir_informe(hallazgos: list[Hallazgo], avisos: list[str], carpeta: Path) -> Path:
    carpeta.mkdir(parents=True, exist_ok=True)
    ahora = datetime.now()
    ruta = carpeta / f"informe-{ahora:%Y-%m-%d_%H%M%S}.md"
    L = [f"# Informe de seguridad de la red — {ahora:%d/%m/%Y %H:%M}", ""]
    cuenta = {g: sum(h.gravedad == g for h in hallazgos) for g in ("alta", "media", "baja", "info")}
    L += [f"**Resumen:** {cuenta['alta']} altos · {cuenta['media']} medios · {cuenta['baja']} bajos · "
          f"{cuenta['info']} informativos · {sum(h.estado == 'arreglado' for h in hallazgos)} arreglados automáticamente", ""]
    for a in avisos:
        L.append(f"> Aviso: {a}")
    L += ["", "## Hallazgos", ""]
    for h in hallazgos:
        L += [f"### [{h.gravedad.upper()}] {h.titulo}", "",
              f"- **Dónde:** {h.objetivo}", f"- **Detalle:** {h.detalle}",
              f"- **Qué hacer:** {h.recomendacion}", f"- **Estado:** {h.estado}" + (f" — {h.resultado}" if h.resultado else ""), ""]
    L += ["## Revisión manual del router", "",
          "Esto no se puede comprobar ni cambiar desde fuera del router; hazlo en su panel de administración:", ""]
    L += [f"- [ ] {x}" for x in CHECKLIST_ROUTER]
    ruta.write_text("\n".join(L) + "\n", encoding="utf-8")
    return ruta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="auditor.py",
        description="Detecta fallos de seguridad en TU red doméstica y arregla los que se pueden arreglar solos.")
    p.add_argument("--arreglar", action="store_true", help="aplicar los arreglos automáticos (pregunta uno a uno)")
    p.add_argument("--si", action="store_true", help="con --arreglar: no preguntar, aplicarlos todos")
    p.add_argument("--aprender", action="store_true", help="marcar como conocidos todos los dispositivos conectados ahora")
    p.add_argument("--red", help="red a escanear en formato CIDR (por defecto, la de la interfaz principal)")
    p.add_argument("--sin-red", action="store_true", help="no escanear los equipos de la red")
    p.add_argument("--sin-upnp", action="store_true", help="no consultar UPnP en el router")
    p.add_argument("--sin-equipo", action="store_true", help="no revisar este equipo")
    p.add_argument("--inventario", type=Path, default=RAIZ / "conocidos.json", help="fichero de dispositivos conocidos")
    p.add_argument("--informes", type=Path, default=RAIZ / "informes", help="carpeta donde guardar el informe")
    args = p.parse_args(argv)

    avisos: list[str] = []
    hallazgos = recoger(args, avisos)
    mostrar(hallazgos)
    for a in avisos:
        print(f"[!] {a}")
    if args.arreglar:
        arreglar(hallazgos, args.si)
    elif any(h.automatico for h in hallazgos):
        print("[*] Hay fallos con arreglo automático: vuelve a ejecutar con --arreglar para aplicarlos.")
    ruta = escribir_informe(hallazgos, avisos, args.informes)
    print(f"[*] Informe guardado en {ruta}")
    graves = [h for h in hallazgos if h.gravedad == "alta" and h.estado != "arreglado"]
    return 1 if graves else 0
