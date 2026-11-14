"use strict";

const NIVEL = { critico: "Crítico", alto: "Importante", medio: "Aviso", info: "Info" };
const ICONOS = {
  ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  aviso: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M12 6v8M12 18.5v.01"/></svg>',
  problema: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M7 7l10 10M17 7L7 17"/></svg>',
};
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

// Crea elementos con textContent: los nombres vienen de la red y no son de fiar.
function el(tag, props = {}, ...hijos) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  for (const h of hijos.flat()) if (h != null) e.append(h.nodeType ? h : String(h));
  return e;
}
function svg(tag, attrs = {}) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

const ms = (v) => (v == null ? null : v < 10 ? v.toFixed(1) : Math.round(v).toString());
function velocidad(bps) {
  if (!bps || bps < 1000) return "0 kb/s";
  if (bps < 1e6) return `${Math.round(bps / 1e3)} kb/s`;
  return `${(bps / 1e6).toFixed(bps < 1e7 ? 1 : 0)} Mb/s`;
}
function bytes(b) {
  if (!b) return "0 MB";
  if (b < 1e9) return `${(b / 1e6).toFixed(b < 1e7 ? 1 : 0)} MB`;
  return `${(b / 1e9).toFixed(2)} GB`;
}
function hace(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "hace un momento";
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return `hace ${Math.round(s / 86400)} días`;
}
function hora(ts) {
  return new Date(ts * 1000).toLocaleTimeString("es", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function valorCifra(id, texto, unidad) {
  const nodo = $(id);
  nodo.replaceChildren(texto ?? "–");
  if (texto != null && unidad) nodo.append(el("small", {}, unidad));
}

// ------------------------------------------------------------------ cabecera
function pintarResumen(d) {
  $("demo").hidden = d.modo !== "demo";
  const r = d.red;
  $("red").textContent = r.router
    ? `Router ${r.router} · red ${r.subred ?? "?"} · actualizado ${d.actualizado ? hora(d.actualizado) : "–"}`
    : "No se encuentra el router";
  const est = d.resumen.estado;
  $("estado").dataset.estado = est;
  $("estado-icono").innerHTML = ICONOS[est]; // contenido fijo, no viene de la red
  $("estado-titulo").textContent = d.resumen.texto;
  const graves = d.alertas.filter((a) => a.nivel !== "info");
  $("estado-sub").textContent =
    est === "ok" ? "Internet, Wi-Fi y DNS responden con normalidad." : graves.map((a) => a.titulo).join(" · ");

  const a = d.actual;
  valorCifra("c-internet", a.internet_ms == null ? "Sin respuesta" : ms(a.internet_ms), a.internet_ms == null ? "" : "ms");
  valorCifra("c-router", a.router_ms == null ? "Sin respuesta" : ms(a.router_ms), a.router_ms == null ? "" : "ms");
  valorCifra("c-perdida", a.perdida_pct == null ? null : Math.round(a.perdida_pct).toString(), "%");
  valorCifra("c-dns", a.dns_ms == null ? "Falla" : ms(a.dns_ms), a.dns_ms == null ? "" : "ms");
  valorCifra("c-disp", String(a.en_linea));
}

// ------------------------------------------------------------------- gráfica
let puntos = [];
function pintarGrafica(historial) {
  const caja = $("svg");
  const W = caja.clientWidth || 600, H = 200;
  const M = { izq: 34, der: 62, arr: 8, aba: 22 };
  const ahora = historial.length ? historial[historial.length - 1][0] : Date.now() / 1000;
  const t0 = ahora - 600;
  const datos = historial.filter((p) => p[0] >= t0);
  const maximo = Math.max(20, ...datos.flatMap((p) => [p[1] ?? 0, p[2] ?? 0]));
  const paso = [5, 10, 20, 25, 50, 100, 200, 250, 500, 1000].find((s) => maximo / s <= 4) || 1000;
  const yMax = Math.ceil(maximo / paso) * paso;
  const x = (t) => M.izq + ((t - t0) / 600) * (W - M.izq - M.der);
  const y = (v) => M.arr + (1 - v / yMax) * (H - M.arr - M.aba);

  caja.setAttribute("viewBox", `0 0 ${W} ${H}`);
  caja.replaceChildren();
  for (let v = 0; v <= yMax; v += paso) {
    caja.append(svg("line", { class: v === 0 ? "base" : "rejilla", x1: M.izq, x2: W - M.der, y1: y(v), y2: y(v) }));
    const t = svg("text", { class: "eje", x: M.izq - 6, y: y(v) + 4, "text-anchor": "end" });
    t.textContent = v;
    caja.append(t);
  }
  for (const [min, ancla] of [[10, "start"], [5, "middle"], [0, "end"]]) {
    const t = svg("text", { class: "eje", x: x(ahora - min * 60), y: H - 4, "text-anchor": ancla });
    t.textContent = min ? `-${min} min` : "ahora";
    caja.append(t);
  }
  const series = [
    { idx: 2, clase: "c2", nombre: "Internet" },
    { idx: 1, clase: "c1", nombre: "Router" },
  ];
  const etiquetas = [];
  for (const s of series) {
    let d = "", dentro = false, ultimo = null;
    for (const p of datos) {
      const v = p[s.idx];
      if (v == null) { dentro = false; continue; } // hueco = sin respuesta
      d += `${dentro ? "L" : "M"}${x(p[0]).toFixed(1)},${y(v).toFixed(1)}`;
      dentro = true;
      ultimo = p;
    }
    caja.append(svg("path", { class: `linea ${s.clase}`, d }));
    if (ultimo) etiquetas.push({ s, yv: y(ultimo[s.idx]), v: ultimo[s.idx] });
  }
  // Etiquetas directas al final de cada línea, separadas si se pisan.
  etiquetas.sort((a, b) => a.yv - b.yv);
  for (let i = 1; i < etiquetas.length; i++) {
    if (etiquetas[i].yv - etiquetas[i - 1].yv < 14) etiquetas[i].yv = etiquetas[i - 1].yv + 14;
  }
  for (const e of etiquetas) {
    const t = svg("text", { class: "etq", x: W - M.der + 6, y: Math.min(H - M.aba, e.yv) + 4 });
    t.textContent = `${e.s.nombre} ${ms(e.v)}`;
    caja.append(t);
  }
  const cruz = svg("line", { class: "cruz", y1: M.arr, y2: H - M.aba, visibility: "hidden" });
  caja.append(cruz);
  const marcas = series.map((s) => {
    const c = svg("circle", { class: `punto ${s.clase}`, r: 4, visibility: "hidden" });
    caja.append(c);
    return c;
  });
  puntos = { datos, x, y, series, cruz, marcas, M, W };
}

function moverCursor(ev) {
  const { datos, x, y, series, cruz, marcas, M, W } = puntos;
  if (!datos || !datos.length) return;
  const caja = $("svg").getBoundingClientRect();
  const px = ((ev.clientX - caja.left) / caja.width) * W;
  if (px < M.izq || px > W - M.der) return ocultarCursor();
  let mejor = datos[0];
  for (const p of datos) if (Math.abs(x(p[0]) - px) < Math.abs(x(mejor[0]) - px)) mejor = p;
  const cx = x(mejor[0]);
  cruz.setAttribute("x1", cx); cruz.setAttribute("x2", cx); cruz.setAttribute("visibility", "visible");
  series.forEach((s, i) => {
    const v = mejor[s.idx];
    if (v == null) return marcas[i].setAttribute("visibility", "hidden");
    marcas[i].setAttribute("cx", cx); marcas[i].setAttribute("cy", y(v));
    marcas[i].setAttribute("visibility", "visible");
  });
  const tip = $("tooltip");
  tip.replaceChildren(
    el("b", {}, hora(mejor[0])),
    ...series.map((s) => el("div", { class: `fila ${s.clase}` },
      `${s.nombre}: ${mejor[s.idx] == null ? "sin respuesta" : ms(mejor[s.idx]) + " ms"}`)),
    el("div", {}, `DNS: ${mejor[3] == null ? "falla" : ms(mejor[3]) + " ms"}`),
  );
  tip.style.display = "block";
  const izq = (cx / W) * caja.width;
  tip.style.left = `${Math.min(izq + 12, caja.width - tip.offsetWidth)}px`;
  tip.style.top = "8px";
}
function ocultarCursor() {
  if (!puntos.cruz) return;
  puntos.cruz.setAttribute("visibility", "hidden");
  puntos.marcas.forEach((m) => m.setAttribute("visibility", "hidden"));
  $("tooltip").style.display = "none";
}

// ------------------------------------------------------------------- fallos
function pintarAlertas(alertas, recientes) {
  const lista = $("alertas");
  lista.replaceChildren(
    ...(alertas.length
      ? alertas.map((a) =>
          el("li", { class: "alerta", "data-nivel": a.nivel },
            el("div", { class: "t" }, el("span", {}, a.titulo), el("span", { class: "nivel" }, NIVEL[a.nivel])),
            el("div", { class: "d" }, a.detalle, " ", el("span", { class: "tenue" }, `(${hace(a.desde)})`)),
            el("details", {}, el("summary", {}, "Cómo arreglarlo"), el("p", {}, a.consejo))))
      : [el("li", { class: "vacio" }, "No hay ningún fallo ahora mismo.")]),
  );
  // Conservar desplegados los "Cómo arreglarlo" abiertos entre refrescos.
  lista.querySelectorAll("details").forEach((det, i) => {
    const id = alertas[i]?.id;
    det.open = abiertos.has(id);
    det.addEventListener("toggle", () => (det.open ? abiertos.add(id) : abiertos.delete(id)));
  });
  $("recientes").hidden = !recientes.length;
  $("recientes-lista").replaceChildren(
    ...recientes.map((a) => el("li", {}, `${a.titulo} — resuelto ${hace(a.hasta)}`)),
  );
}
const abiertos = new Set();

// -------------------------------------------------------------- dispositivos
let editando = false;
function pintarDispositivos(lista, trafico) {
  if (editando) return; // no pisar lo que alguien está escribiendo
  const aviso = $("aviso-trafico");
  aviso.hidden = trafico.activo;
  aviso.textContent = trafico.activo ? "" :
    `El consumo por dispositivo no está disponible: ${trafico.mensaje || "desactivado"}. ` +
    "Mira el README para activarlo.";
  const max = Math.max(1, ...lista.map((d) => d.bajada_bps + d.subida_bps));

  $("dispositivos").replaceChildren(...lista.map((d) => {
    const titulo = d.nombre || d.nombre_red || "Sin nombre";
    const boton = el("button", { class: d.nombre ? "" : "sin", title: "Cambiar nombre", onclick: () => editar(boton, d) }, titulo);
    const chips = [];
    if (d.es_router) chips.push(el("span", { class: "chip" }, "router"));
    if (d.es_este_equipo) chips.push(el("span", { class: "chip" }, "este equipo"));
    for (const p of d.puertos) chips.push(el("span", { class: "chip peligro", title: p.desc }, `puerto ${p.puerto}`));
    const meta = [d.ip, d.mac, d.privada ? "MAC privada (móvil/tablet)" : null,
                  d.en_linea ? null : `visto ${hace(d.ultima_vez)}`].filter(Boolean).join(" · ");

    const barra = el("div", { class: "barra", title: `Bajada ${velocidad(d.bajada_bps)} · Subida ${velocidad(d.subida_bps)}` });
    const b = el("i", { class: "b" }), s = el("i", { class: "s" });
    b.style.width = `${(d.bajada_bps / max) * 100}%`;
    s.style.width = `${(d.subida_bps / max) * 100}%`;
    barra.append(b, s);

    return el("div", { class: `disp${d.en_linea ? "" : " apagado"}` },
      el("div", { class: "quien" },
        el("div", { class: "nom" }, el("span", { class: `punto-linea${d.en_linea ? " on" : ""}`, title: d.en_linea ? "Conectado" : "Desconectado" }), boton, ...chips),
        el("div", { class: "meta" }, meta)),
      el("div", { class: "barra-wrap" }, trafico.activo ? barra : null),
      el("div", { class: "consumo" },
        trafico.activo ? [el("div", {}, `↓ ${velocidad(d.bajada_bps)}`), el("div", {}, `↑ ${velocidad(d.subida_bps)}`),
                          el("div", { class: "total" }, `${bytes(d.bajada_total + d.subida_total)} en total`)]
                       : el("span", { class: "tenue" }, "–")));
  }));
}

function editar(boton, d) {
  editando = true;
  const input = el("input", { value: d.nombre, maxlength: 40, placeholder: "Ej.: Móvil de Ana", "aria-label": "Nombre del dispositivo" });
  let hecho = false;
  const terminar = async (guardar) => {
    if (hecho) return;
    hecho = true;
    if (guardar) {
      await fetch("/api/nombre", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mac: d.mac, nombre: input.value }) });
    }
    editando = false;
    actualizar();
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") terminar(true);
    if (e.key === "Escape") terminar(false);
  });
  input.addEventListener("blur", () => terminar(true));
  boton.replaceWith(input);
  input.focus();
  input.select();
}

// ------------------------------------------------------------------- bucle
let ultimo = null;
async function actualizar() {
  try {
    const r = await fetch("/api/estado", { cache: "no-store" });
    if (r.status === 401) return (location.href = "/login");
    const d = await r.json();
    ultimo = d;
    pintarResumen(d);
    pintarGrafica(d.historial);
    pintarAlertas(d.alertas, d.recientes);
    pintarDispositivos(d.dispositivos, d.trafico);
  } catch (e) {
    $("estado").dataset.estado = "problema";
    $("estado-icono").innerHTML = ICONOS.problema;
    $("estado-titulo").textContent = "No se puede contactar con el monitor";
    $("estado-sub").textContent = "¿Está encendido el equipo que lo ejecuta? ¿Sigues conectado al Wi-Fi de casa?";
  }
}

$("grafica").addEventListener("pointermove", moverCursor);
$("grafica").addEventListener("pointerleave", ocultarCursor);
window.addEventListener("resize", () => ultimo && pintarGrafica(ultimo.historial));
actualizar();
setInterval(actualizar, 3000);
