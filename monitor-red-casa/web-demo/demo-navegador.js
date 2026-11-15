// Red de casa simulada que corre entera en el navegador, para compartir la app
// con un link. Sustituye a fetch() para las rutas /api/* y genera los mismos
// datos que el servidor Python (ver demo.py y monitor.py).
"use strict";

(() => {
  const AHORA = () => Date.now() / 1000;
  const T0 = AHORA();
  const ROUTER = "192.168.1.1";
  const CONTRATADA = 600;
  // mac, ip, nombre, nombre de red, Mb/s bajada, Mb/s subida, puertos abiertos
  const EQUIPOS = [
    ["a4:91:b1:10:00:01", "192.168.1.1", "Router", "router", 0, 0, []],
    ["3c:22:fb:10:00:10", "192.168.1.10", "Portátil", "portatil", 4, 1.2, []],
    ["da:11:4e:10:00:11", "192.168.1.11", "Móvil de Ana", "", 1.5, 0.3, []],
    ["ca:5d:20:10:00:12", "192.168.1.12", "Móvil de Luis", "", 0.8, 0.2, []],
    ["70:2a:d5:10:00:20", "192.168.1.20", "Smart TV salón", "tv-salon", 18, 0.4, []],
    ["00:d9:d1:10:00:21", "192.168.1.21", "Consola", "consola", 6, 0.8, []],
    ["f0:27:2d:10:00:30", "192.168.1.30", "Altavoz", "", 0.3, 0.05, []],
    ["b8:27:eb:10:00:40", "192.168.1.40", "Ordenador sobremesa", "sobremesa", 2, 0.5, [445]],
  ];
  const INTRUSO = ["5e:8a:01:10:00:66", "192.168.1.66", "", "", 3, 2.5, [23]];
  const DESC = { 21: "FTP (contraseñas en claro)", 23: "Telnet (contraseñas en claro)",
    139: "NetBIOS (compartición antigua de Windows)", 445: "SMB (carpetas compartidas)",
    3389: "Escritorio remoto de Windows", 5900: "VNC (control remoto)" };
  const NIVELES = { critico: 0, alto: 1, medio: 2, info: 3 };

  const nombres = Object.fromEntries(EQUIPOS.map((e) => [e[0], e[2]]));
  const hoy = Object.fromEntries(EQUIPOS.map((e) => [e[0], [e[4] * 3e6 * 60, e[5] * 3e6 * 60]]));
  const historial = [];
  let alertas = {};
  const recientes = [];
  const intrusoDesde = T0 + 30;
  const velocidad = { bajada: 538, subida: 287, ts: T0 - 12 * 60, midiendo: false, error: null };
  const uso = {};

  const media = (xs) => { const v = xs.filter((x) => x != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };
  const saturado = (t) => (t - T0 + 90) % 180 > 140; // cada 3 min, 40 s de Wi-Fi saturado
  const equipos = (t = AHORA()) => (t >= intrusoDesde ? [...EQUIPOS, INTRUSO] : EQUIPOS);

  function muestra(t) {
    const sat = saturado(t);
    const router = +(sat ? 25 + Math.random() * 30 : 2 + Math.random() * 3).toFixed(1);
    let internet = Math.random() < 0.02 ? null
      : 18 + 6 * Math.sin(t / 40) + Math.random() * 6 + (sat ? 120 + Math.random() * 80 : 0);
    if (internet != null) internet = +internet.toFixed(1);
    return [t, router, internet, +(8 + Math.random() * 12).toFixed(1)];
  }
  // 10 minutos de historia ya rellenos, para que la gráfica no salga vacía.
  for (let t = T0 - 600; t < T0; t += 5) historial.push(muestra(t));

  function trafico(t, dt) {
    for (const [mac, ip, , , b, s] of equipos(t)) {
      const f = Math.max(0, 1 + 0.8 * Math.sin(t / 23 + (parseInt(ip.split(".")[3], 10) % 7)) + (Math.random() - 0.5) * 0.5);
      uso[mac] = [b * f * 1e6, s * f * 1e6];
      const h = (hoy[mac] ??= [0, 0]);
      h[0] += (uso[mac][0] / 8) * dt;
      h[1] += (uso[mac][1] / 8) * dt;
    }
  }

  function evaluar() {
    const nuevas = {};
    const al = (id, nivel, titulo, detalle, consejo) => (nuevas[id] = { id, nivel, titulo, detalle, consejo });
    const reciente = historial.slice(-12);
    const latI = media(reciente.map((x) => x[2])), latR = media(reciente.map((x) => x[1]));
    if (latI != null && latI > 150)
      al("latencia", "medio", "Internet va lento", `La latencia media a internet es de ${Math.round(latI)} ms (lo normal: < 50 ms).`,
        "Mira abajo qué dispositivo está gastando más ahora mismo: una descarga o una copia en la nube satura la conexión.");
    if (latR != null && latR > 30)
      al("wifi", "medio", "El Wi-Fi va saturado o con mala señal", `El router tarda ${Math.round(latR)} ms en responder (lo normal: < 10 ms).`,
        "Acerca este equipo al router o usa cable. Cambia el canal Wi-Fi en el router, o usa la banda de 5 GHz.");
    let sinNombre = 0;
    for (const [mac, ip, , red, , , puertos] of equipos()) {
      const nombre = nombres[mac] || red || ip;
      if (!nombres[mac]) {
        sinNombre++;
        if (mac === INTRUSO[0])
          al(`nuevo:${mac}`, "medio", "Dispositivo nuevo en la red", `${nombre} (${ip}, ${mac}) se ha conectado por primera vez.`,
            "Si es de alguien de casa, ponle nombre en la lista. Si nadie lo reconoce, cambia la contraseña del Wi-Fi.");
      }
      for (const p of puertos)
        al(`puerto:${mac}:${p}`, "alto", `${nombre}: puerto ${p} abierto`, `${DESC[p]} accesible desde la red de casa.`,
          "Si no lo usas, desactívalo en ese equipo (o en el router si es el router). Si lo usas, pon una contraseña fuerte y no lo abras a internet.");
    }
    if (sinNombre)
      al("sin_nombre", "info", `${sinNombre} dispositivo(s) sin nombre`, "Ponerles nombre ayuda a detectar intrusos.",
        "Toca el nombre de cada dispositivo en la lista para cambiarlo.");
    const ahora = AHORA();
    for (const [id, a] of Object.entries(nuevas)) a.desde = alertas[id]?.desde ?? ahora;
    for (const [id, a] of Object.entries(alertas))
      if (!nuevas[id] && a.nivel !== "info") recientes.unshift({ ...a, hasta: ahora });
    recientes.length = Math.min(recientes.length, 10);
    alertas = nuevas;
  }

  function analisis(disp) {
    const items = [];
    const it = (estado, titulo, detalle, consejo = "", peso = 0) => items.push({ estado, titulo, detalle, consejo, peso });
    const h = historial.slice(-720);
    const perdida = (100 * h.filter((x) => x[2] == null).length) / h.length;
    it(perdida < 1 ? "ok" : perdida < 5 ? "mejorar" : "mal", "Estabilidad de la conexión",
      `${perdida.toFixed(1)}% de cortes en los últimos ${Math.round((h.length * 5) / 60)} min.`,
      "Muchos cortes suelen ser del router o de la línea. Reinicia el router; si continúa, revisa el cable de fibra/ADSL y avisa a tu proveedor.", 20);
    const lat = media(h.map((x) => x[2]));
    it(lat < 50 ? "ok" : lat < 100 ? "mejorar" : "mal", "Rapidez de respuesta de internet (ping)",
      `${Math.round(lat)} ms de media (bueno: menos de 50 ms).`,
      "Un ping alto se nota en juegos y videollamadas. Suele subir cuando alguien descarga o sube algo grande: mira quién consume más.", 15);
    const latR = media(h.map((x) => x[1]));
    it(latR < 10 ? "ok" : latR < 30 ? "mejorar" : "mal", "Calidad del Wi-Fi",
      `El router responde en ${Math.round(latR)} ms de media (bueno: menos de 10 ms).`,
      "Pon el router en un sitio alto y despejado, lejos de microondas y del suelo. Usa la banda de 5 GHz cerca del router y cable para la tele y la consola. En casas grandes, un sistema Wi-Fi mesh ayuda.", 15);
    const dns = media(h.map((x) => x[3]));
    it(dns > 60 ? "mejorar" : "ok", "DNS (traducir nombres de webs)", `${Math.round(dns)} ms de media, 0 fallos.`,
      "Pon en el router los DNS 1.1.1.1 y 9.9.9.9.", 10);
    const r = velocidad.bajada / CONTRATADA;
    it(r >= 0.8 ? "ok" : r >= 0.5 ? "mejorar" : "mal", "Velocidad de internet",
      `${Math.round(velocidad.bajada)} Mb/s de bajada y ${Math.round(velocidad.subida)} Mb/s de subida. Contratado: ${CONTRATADA} Mb/s (${Math.round(100 * r)}%).`,
      "Por Wi-Fi es normal perder velocidad. Si con cable tampoco llega al 80%, reinicia el router y, si sigue, reclama al proveedor.", 15);
    const conPuertos = disp.filter((d) => d.puertos.length && d.en_linea);
    it(conPuertos.length ? "mal" : "ok", "Puertos peligrosos abiertos",
      conPuertos.map((d) => `${d.nombre || d.ip}: ${d.puertos.map((p) => p.puerto).join(", ")}`).join("; "),
      "Desactiva en cada equipo los servicios que no uses (compartir carpetas, escritorio remoto…). Si es el router, hazlo desde su panel de administración.", 15);
    it("mejorar", "UPnP en el router", "Está activado: cualquier programa de casa puede abrir puertos hacia internet sin preguntar.",
      "Entra al panel del router y desactiva UPnP. Si alguna consola deja de funcionar online, vuelve a activarlo o abre solo sus puertos a mano.", 5);
    const sin = disp.filter((d) => d.en_linea && !d.nombre).length;
    it(sin ? "mejorar" : "ok", "Dispositivos identificados", `${disp.length - sin} de ${disp.length} conectados tienen nombre.`,
      "Pon nombre a cada dispositivo: si aparece uno que nadie conoce, cambia la contraseña del Wi-Fi (WPA2/WPA3, mínimo 12 caracteres).", 5);
    const total = disp.reduce((a, d) => a + d.hoy_bajada + d.hoy_subida, 0);
    const top = disp.reduce((a, d) => (d.hoy_bajada + d.hoy_subida > a.hoy_bajada + a.hoy_subida ? d : a));
    it("info", "Quién más ha gastado hoy", `${top.nombre || top.ip}: ${Math.round((100 * (top.hoy_bajada + top.hoy_subida)) / total)}% del consumo de hoy.`);
    let nota = 100;
    for (const x of items) nota -= x.estado === "mal" ? x.peso : x.estado === "mejorar" ? x.peso / 2 : 0;
    nota = Math.max(0, Math.round(nota));
    const orden = { mal: 0, mejorar: 1, info: 2, ok: 3 };
    items.sort((a, b) => orden[a.estado] - orden[b.estado]);
    return { nota, etiqueta: nota >= 85 ? "Buena" : nota >= 60 ? "Mejorable" : "Mala", items };
  }

  function estado() {
    const disp = equipos().map(([mac, ip, , red, , , puertos]) => ({
      mac, ip, nombre: nombres[mac] || "", nombre_red: red, en_linea: true,
      privada: (parseInt(mac.slice(0, 2), 16) & 2) !== 0, es_router: ip === ROUTER, es_este_equipo: ip === "192.168.1.10",
      puertos: puertos.map((p) => ({ puerto: p, desc: DESC[p] })),
      bajada_bps: uso[mac]?.[0] ?? 0, subida_bps: uso[mac]?.[1] ?? 0,
      hoy_bajada: hoy[mac]?.[0] ?? 0, hoy_subida: hoy[mac]?.[1] ?? 0,
      primera_vez: mac === INTRUSO[0] ? intrusoDesde : T0 - 86400 * 30, ultima_vez: AHORA(),
    }));
    disp.sort((a, b) => b.bajada_bps + b.subida_bps - (a.bajada_bps + a.subida_bps));
    const lista = Object.values(alertas).sort((a, b) => NIVELES[a.nivel] - NIVELES[b.nivel] || a.desde - b.desde);
    const peor = lista[0]?.nivel;
    const graves = lista.filter((a) => a.nivel !== "info").length;
    const ultimo = historial[historial.length - 1];
    const ventana = historial.slice(-60);
    return {
      modo: "demo", actualizado: ultimo[0],
      red: { ip_local: "192.168.1.10", router: ROUTER, subred: "192.168.1.0/24", wifi: "MiFibra-A3F2" },
      resumen: peor === "critico" ? { estado: "problema", texto: lista[0].titulo }
        : graves ? { estado: "aviso", texto: `${graves} cosa(s) a revisar` } : { estado: "ok", texto: "Todo funciona bien" },
      actual: { router_ms: ultimo[1], internet_ms: ultimo[2], dns_ms: ultimo[3],
        perdida_pct: (100 * ventana.filter((x) => x[2] == null).length) / ventana.length, en_linea: disp.length },
      historial: historial.slice(-120).map((x) => [Math.round(x[0]), x[1], x[2], x[3]]),
      alertas: lista, recientes, dispositivos: disp,
      trafico: { activo: true, mensaje: null },
      velocidad: { ...velocidad, contratada: CONTRATADA },
      uso: { bajada_bps: disp.reduce((a, d) => a + d.bajada_bps, 0), subida_bps: disp.reduce((a, d) => a + d.subida_bps, 0),
        hoy: disp.reduce((a, d) => a + d.hoy_bajada + d.hoy_subida, 0) },
      analisis: analisis(disp),
    };
  }

  let ultimoTick = AHORA();
  function tick() {
    const t = AHORA();
    historial.push(muestra(t));
    if (historial.length > 720) historial.shift();
    trafico(t, t - ultimoTick);
    ultimoTick = t;
    evaluar();
  }
  tick();
  setInterval(tick, 2000);

  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
  const fetchReal = window.fetch.bind(window);
  window.fetch = async (url, opciones = {}) => {
    const ruta = String(url);
    if (ruta.startsWith("/api/estado")) return json(estado());
    if (ruta.startsWith("/api/velocidad")) {
      if (velocidad.midiendo || AHORA() - velocidad.ts < 60) return json({ ok: false });
      velocidad.midiendo = true;
      setTimeout(() => {
        const lento = saturado(AHORA()) ? 0.45 : 1;
        Object.assign(velocidad, { bajada: lento * (480 + Math.random() * 80), subida: lento * (250 + Math.random() * 50),
          ts: AHORA(), midiendo: false });
      }, 4000);
      return json({ ok: true });
    }
    if (ruta.startsWith("/api/nombre")) {
      const d = JSON.parse(opciones.body || "{}");
      nombres[d.mac] = String(d.nombre || "").trim().slice(0, 40);
      evaluar();
      return json({ ok: true });
    }
    return fetchReal(url, opciones);
  };
})();
