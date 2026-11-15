"""Comprobaciones y arreglos en el propio equipo Linux desde el que se ejecuta el auditor."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .modelo import Hallazgo

SERVICIOS_INSEGUROS = {23: "Telnet", 21: "FTP"}
SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/00-auditor-red-casa.conf")


class ErrorArreglo(Exception):
    pass


def es_root() -> bool:
    return os.geteuid() == 0


def _run(cmd: list[str], comprobar: bool = False) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        if comprobar:
            raise ErrorArreglo(f"no se pudo ejecutar {' '.join(cmd)}: {e}")
        return subprocess.CompletedProcess(cmd, 127, "", str(e))
    if comprobar and r.returncode != 0:
        raise ErrorArreglo(f"{' '.join(cmd)} → {r.stderr.strip() or r.stdout.strip()}")
    return r


def interpretar_ss(salida: str) -> list[tuple[str, int, int | None]]:
    """De `ss -H -tlnp` saca (dirección, puerto, pid) de cada servicio a la escucha."""
    res = []
    for linea in salida.splitlines():
        campos = linea.split()
        if len(campos) < 4:
            continue
        direccion, _, puerto = campos[3].rpartition(":")
        if not puerto.isdigit():
            continue
        pid = re.search(r"pid=(\d+)", linea)
        res.append((direccion.strip("[]"), int(puerto), int(pid.group(1)) if pid else None))
    return res


def _solo_local(direccion: str) -> bool:
    return direccion.startswith("127.") or direccion == "::1"


def _escuchas() -> list[tuple[str, int, int | None]]:
    return interpretar_ss(_run(["ss", "-H", "-tlnp"]).stdout)


# ---------- Cortafuegos ----------

def _arreglo_ufw(ssh_abierto: bool):
    def aplicar() -> str:
        hecho = []
        if ssh_abierto:  # no cortar la sesión SSH con la que quizá se está trabajando
            _run(["ufw", "allow", "22/tcp"], comprobar=True)
            hecho.append("permitido SSH (22/tcp)")
        _run(["ufw", "default", "deny", "incoming"], comprobar=True)
        _run(["ufw", "default", "allow", "outgoing"], comprobar=True)
        _run(["ufw", "--force", "enable"], comprobar=True)
        if "inactive" in _run(["ufw", "status"]).stdout:
            raise ErrorArreglo("ufw sigue inactivo tras activarlo")
        hecho.append("cortafuegos activado: se bloquea lo entrante, se permite lo saliente")
        return "; ".join(hecho).capitalize() + "."
    return aplicar


def comprobar_cortafuegos() -> list[Hallazgo]:
    if not shutil.which("ufw"):
        if es_root() and shutil.which("nft") and _run(["nft", "list", "ruleset"]).stdout.strip():
            return []  # hay reglas nftables propias: no tocamos nada
        return [Hallazgo(
            codigo="FW-AUSENTE", gravedad="baja", titulo="Este equipo no tiene un cortafuegos sencillo instalado",
            objetivo="este equipo", detalle="No se ha encontrado ufw.",
            recomendacion="Instálalo con `sudo apt install ufw` y vuelve a ejecutar el auditor con --arreglar.")]
    if not es_root():
        return []  # `ufw status` necesita root; se avisa de forma general en la CLI
    if "inactive" not in _run(["ufw", "status"]).stdout:
        return []
    ssh = any(p == 22 and not _solo_local(d) for d, p, _ in _escuchas())
    return [Hallazgo(
        codigo="FW-INACTIVO", gravedad="media", titulo="El cortafuegos de este equipo está desactivado",
        objetivo="este equipo", detalle="ufw está instalado pero inactivo: cualquier servicio que abras queda expuesto a la red.",
        recomendacion="sudo ufw default deny incoming && sudo ufw enable",
        arreglo=_arreglo_ufw(ssh),
        arreglo_desc="Activar ufw bloqueando conexiones entrantes" + (" (manteniendo SSH permitido)" if ssh else ""))]


# ---------- Servicios inseguros a la escucha ----------

def _unidad_de(pid: int | None) -> str:
    if pid is None:
        return ""
    unidad = _run(["ps", "-o", "unit=", "-p", str(pid)]).stdout.strip()
    return unidad if unidad.endswith((".service", ".socket")) else ""


def _arreglo_parar(unidad: str, puerto: int):
    def aplicar() -> str:
        unidades = [unidad]
        socket_unidad = unidad.rsplit(".", 1)[0] + ".socket"
        if unidad.endswith(".service") and _run(["systemctl", "cat", socket_unidad]).returncode == 0:
            unidades.append(socket_unidad)  # si no, systemd lo relanza por activación de socket
        _run(["systemctl", "disable", "--now", *unidades], comprobar=True)
        if any(p == puerto and not _solo_local(d) for d, p, _ in _escuchas()):
            raise ErrorArreglo(f"el puerto {puerto} sigue abierto tras parar {unidad}")
        return f"Parado y deshabilitado {', '.join(unidades)}; el puerto {puerto} ya está cerrado."
    return aplicar


def comprobar_servicios() -> list[Hallazgo]:
    res = []
    vistos = set()
    for direccion, puerto, pid in _escuchas():
        if puerto not in SERVICIOS_INSEGUROS or _solo_local(direccion) or puerto in vistos:
            continue
        vistos.add(puerto)
        nombre = SERVICIOS_INSEGUROS[puerto]
        unidad = _unidad_de(pid) if es_root() else ""
        res.append(Hallazgo(
            codigo=f"SERVICIO-{puerto}", gravedad="alta", titulo=f"Este equipo ofrece {nombre} a la red",
            objetivo="este equipo",
            detalle=f"Hay un servicio {nombre} escuchando en {direccion}:{puerto}; las contraseñas viajan sin cifrar.",
            recomendacion=f"Para y deshabilita el servicio ({'sudo systemctl disable --now ' + unidad if unidad else 'localízalo con sudo ss -tlnp'}).",
            arreglo=_arreglo_parar(unidad, puerto) if unidad else None,
            arreglo_desc=f"Parar y deshabilitar {unidad}" if unidad else ""))
    return res


# ---------- SSH ----------

def _arreglo_ssh_root():
    def aplicar() -> str:
        SSHD_DROPIN.write_text("# Creado por auditor-red-casa. Bórralo para deshacer el cambio.\n"
                               "PermitRootLogin prohibit-password\n", encoding="utf-8")
        if _run(["sshd", "-t"]).returncode != 0:
            SSHD_DROPIN.unlink()
            raise ErrorArreglo("la configuración resultante no era válida; cambio deshecho")
        if "permitrootlogin yes" in _run(["sshd", "-T"]).stdout.lower():
            SSHD_DROPIN.unlink()
            raise ErrorArreglo("tu sshd_config no carga sshd_config.d; cambio deshecho, edítalo a mano")
        for unidad in ("ssh", "sshd"):
            if _run(["systemctl", "reload", unidad]).returncode == 0:
                break
        return f"root ya no puede entrar por SSH con contraseña (solo con clave). Cambio en {SSHD_DROPIN}."
    return aplicar


def comprobar_ssh() -> list[Hallazgo]:
    if not (es_root() and shutil.which("sshd") and SSHD_DROPIN.parent.is_dir()):
        return []
    if not any(p == 22 for _, p, _ in _escuchas()):
        return []
    if "permitrootlogin yes" not in _run(["sshd", "-T"]).stdout.lower():
        return []
    return [Hallazgo(
        codigo="SSH-ROOT", gravedad="media", titulo="SSH permite entrar como root con contraseña",
        objetivo="este equipo", detalle="`PermitRootLogin yes`: quien adivine la contraseña de root controla el equipo entero.",
        recomendacion="Pon `PermitRootLogin prohibit-password` (o `no`) en la configuración de sshd.",
        arreglo=_arreglo_ssh_root(),
        arreglo_desc="Poner PermitRootLogin prohibit-password y recargar sshd")]


# ---------- WiFi a la que está conectado este equipo ----------

def interpretar_nmcli(salida: str) -> tuple[str, str] | None:
    """De `nmcli -t -f ACTIVE,SSID,SECURITY dev wifi` saca (ssid, seguridad) de la red activa."""
    for linea in salida.splitlines():
        partes = linea.split(":")
        if len(partes) >= 3 and partes[0] in ("yes", "sí", "si"):
            return ":".join(partes[1:-1]), partes[-1].strip()
    return None


def comprobar_wifi() -> list[Hallazgo]:
    if not shutil.which("nmcli"):
        return []
    activa = interpretar_nmcli(_run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"]).stdout)
    if not activa:
        return []
    ssid, seg = activa
    protocolos = set(seg.upper().split())
    consejo = ("En el panel del router, pon la seguridad WiFi en WPA2-AES o WPA3, con una contraseña "
               "nueva de 16+ caracteres, y desactiva WPS.")
    if not protocolos or protocolos == {"--"}:
        return [Hallazgo("WIFI-ABIERTA", "alta", "Tu WiFi no tiene contraseña", f"WiFi «{ssid}»",
                         "Cualquiera que esté cerca puede conectarse y ver el tráfico sin cifrar.", consejo)]
    if "WEP" in protocolos:
        return [Hallazgo("WIFI-WEP", "alta", "Tu WiFi usa WEP", f"WiFi «{ssid}»",
                         "WEP se rompe en minutos con herramientas gratuitas.", consejo)]
    if "WPA1" in protocolos or "WPA" in protocolos:
        return [Hallazgo("WIFI-WPA1", "media", "Tu WiFi todavía acepta WPA (versión 1, TKIP)", f"WiFi «{ssid}»",
                         f"Seguridad anunciada: {seg}. WPA/TKIP está obsoleto.", consejo)]
    return []


def hallazgos_equipo() -> list[Hallazgo]:
    return comprobar_cortafuegos() + comprobar_servicios() + comprobar_ssh() + comprobar_wifi()
