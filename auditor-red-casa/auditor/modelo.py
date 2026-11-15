"""Modelo de datos común: un Hallazgo es un fallo detectado, con o sin arreglo automático."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

GRAVEDADES = ["alta", "media", "baja", "info"]


@dataclass
class Hallazgo:
    codigo: str            # identificador corto, p. ej. "UPNP-MAPEO"
    gravedad: str          # alta | media | baja | info
    titulo: str
    objetivo: str          # a qué equipo o servicio afecta
    detalle: str           # qué se ha visto exactamente
    recomendacion: str     # qué hacer a mano si no hay arreglo automático
    arreglo: Optional[Callable[[], str]] = None  # devuelve un texto con lo que hizo
    arreglo_desc: str = ""                       # qué hará el arreglo, para pedir confirmación
    estado: str = "pendiente"                    # pendiente | arreglado | fallo | omitido
    resultado: str = ""

    @property
    def automatico(self) -> bool:
        return self.arreglo is not None


def ordenar(hallazgos: list[Hallazgo]) -> list[Hallazgo]:
    return sorted(hallazgos, key=lambda h: (GRAVEDADES.index(h.gravedad), h.objetivo, h.codigo))
