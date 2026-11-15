#!/usr/bin/env python3
"""Genera web-demo/index.html: la app entera en un solo archivo, con la red
simulada de demo-navegador.js. Se puede abrir con doble clic o publicar en
GitHub Pages para compartir un link.

    python3 web-demo/construir.py            # página completa
    python3 web-demo/construir.py --fragmento salida.html   # sin <html>/<head>
"""

import os
import re
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(AQUI, "..", "static")
REPO = "https://github.com/mateoaaay/cyber-lab/tree/claude/sharp-curie-yuf4eo/monitor-red-casa"


def leer(*ruta):
    with open(os.path.join(*ruta), encoding="utf-8") as f:
        return f.read()


AVISO = f"""
  <section class="aviso-demo">
    <b>Esto es una demo con una red de casa simulada.</b>
    Los datos se inventan en tu navegador; no se mira tu red. Para analizar la red de tu casa de
    verdad, la app se instala en un ordenador de casa: <a href="{REPO}" target="_blank" rel="noopener">instrucciones</a>.
  </section>
"""

CSS_EXTRA = """
.pagina { padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); }
.aviso-demo { font-size: 14px; background: var(--superficie); border: 1px dashed var(--eje); border-radius: 12px; padding: 12px 14px; margin-bottom: 16px; color: var(--tinta-2); }
.aviso-demo b { color: var(--tinta); }
.aviso-demo a { color: var(--acento); }
"""


def construir(fragmento=False):
    html = leer(STATIC, "index.html")
    cuerpo = re.search(r"<body>(.*)</body>", html, re.S).group(1)
    cuerpo = re.sub(r'\s*<script src="/app.js"></script>', "", cuerpo)
    # En la demo no hay sesión que cerrar.
    cuerpo = re.sub(r'<form method="post" action="/logout">.*?</form>',
                    '<span class="tenue">Demo · datos simulados</span>', cuerpo, flags=re.S)
    cuerpo = cuerpo.replace("</header>", "</header>\n" + AVISO, 1)
    estilos = leer(STATIC, "estilo.css") + CSS_EXTRA
    scripts = leer(AQUI, "demo-navegador.js") + "\n" + leer(STATIC, "app.js")
    cabeza = ('<title>Red de casa</title>\n'
              '<meta name="claude:viewport-fit-sides" content="cover">\n'
              f"<style>\n{estilos}\n</style>\n")
    contenido = f"{cuerpo.strip()}\n<script>\n{scripts}\n</script>\n"
    if fragmento:
        return cabeza + contenido
    return ("<!doctype html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n"
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            f"{cabeza}</head>\n<body>\n{contenido}</body>\n</html>\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fragmento":
        with open(sys.argv[2], "w", encoding="utf-8") as f:
            f.write(construir(fragmento=True))
    else:
        with open(os.path.join(AQUI, "index.html"), "w", encoding="utf-8") as f:
            f.write(construir())
