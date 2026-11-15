# Informe de seguridad de la red — ejemplo

> Ejemplo con **datos ficticios** (IP, nombres y MAC inventados) para mostrar el formato del informe. Los informes reales se guardan en `informes/` y no se suben al repositorio.

**Resumen:** 2 altos · 2 medios · 1 bajos · 0 informativos · 2 arreglados automáticamente

## Hallazgos

### [ALTA] Puerto abierto hacia internet mediante UPnP

- **Dónde:** 192.168.1.1 → 192.168.1.40
- **Detalle:** Internet puede llegar al puerto 50000 de 192.168.1.40 a través del puerto 50000/UDP del router (lo pidió: «SmartTV streaming»).
- **Qué hacer:** Ciérralo si no sabes qué es. Mientras UPnP siga activado, el dispositivo puede volver a abrirlo.
- **Estado:** arreglado — Cerrado el puerto 50000/UDP en el router (comprobado).

### [ALTA] Dispositivo que no está en tu inventario

- **Dónde:** 192.168.1.77 (portatil-desconocido · Ejemplo Corp · 02:00:00:AA:BB:01)
- **Detalle:** Se ha conectado a tu red un equipo que no habías marcado como conocido.
- **Qué hacer:** Si es tuyo, ejecuta con --aprender. Si no lo reconoces: cambia la contraseña del WiFi (WPA2/WPA3, 16+ caracteres), desactiva WPS y revisa la lista de clientes en el panel del router.
- **Estado:** pendiente

### [MEDIA] El router tiene UPnP activado

- **Dónde:** 192.168.1.1
- **Detalle:** Cualquier programa o dispositivo de tu red puede abrir puertos hacia internet sin pedirte permiso ni contraseña.
- **Qué hacer:** Entra al panel del router y desactiva UPnP (suele estar en NAT, Avanzado o Reenvío de puertos). Si una consola o un juego lo necesita, abre solo ese puerto a mano.
- **Estado:** pendiente

### [MEDIA] El cortafuegos de este equipo está desactivado

- **Dónde:** este equipo
- **Detalle:** ufw está instalado pero inactivo: cualquier servicio que abras queda expuesto a la red.
- **Qué hacer:** sudo ufw default deny incoming && sudo ufw enable
- **Estado:** arreglado — Permitido ssh (22/tcp); cortafuegos activado: se bloquea lo entrante, se permite lo saliente.

### [BAJA] Panel del router por HTTP accesible en el router

- **Dónde:** 192.168.1.1 (router · Ejemplo Networks · 02:00:00:AA:BB:00)
- **Detalle:** Puerto 80/tcp abierto (http): la contraseña de administración viaja sin cifrar por la red.
- **Qué hacer:** Entra al panel por HTTPS si el router lo permite y cambia la contraseña de administrador de fábrica.
- **Estado:** pendiente

## Revisión manual del router

Esto no se puede comprobar ni cambiar desde fuera del router; hazlo en su panel de administración:

- [ ] Cambiar la contraseña de administrador del router (la de fábrica está en internet).
- [ ] WiFi en WPA2-AES o WPA3 con contraseña propia de 16+ caracteres.
- [ ] Desactivar WPS (el botón/PIN de emparejamiento rápido).
- [ ] Desactivar la administración remota desde internet (WAN).
- [ ] Actualizar el firmware del router.
- [ ] Poner los dispositivos IoT (bombillas, cámaras, enchufes) en la red de invitados.
