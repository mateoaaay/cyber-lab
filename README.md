# cyber-lab

Laboratorio personal de ciberseguridad y redes montado en VMware Workstation Pro. Cada lab documenta una práctica completa: predicción previa, pasos ejecutados, capturas como evidencia y conclusiones.

## Habilidades que se trabajan

- Administración básica de Linux (Ubuntu Server y Kali Linux)
- Servicios y `systemd` (SSH, activación por socket)
- Redes en virtualización: NAT, Host-only, DHCP
- Reconocimiento de red con `nmap`
- Documentación técnica y gestión de snapshots

## Entorno

| Rol | Sistema | Redes |
|-----|---------|-------|
| Host | Portátil con VMware Workstation Pro 17.6.4 | VMnet1 (Host-only) |
| Atacante | Kali Linux 2026.2 | NAT + Host-only (`192.168.163.128`) |
| Víctima | Ubuntu Server 24.04 | NAT + Host-only (`192.168.163.129`) |

Red del lab: Host-only VMnet1, `192.168.163.0/24`, aislada de internet.

## Labs

| Lab | Tema | Estado |
|-----|------|--------|
| [Lab 0](lab-00-ssh/) | SSH en Ubuntu Server y snapshot base | Completado |
| [Lab 1](lab-01-nmap-descubrimiento/) | nmap: descubrimiento de equipos | Completado |
| [Lab 2](lab-02-nmap-puertos-servicios/) | nmap: puertos, servicios y versiones | Completado |
| Lab 3 | Wireshark básico | Pendiente |
| Lab 4 | nmap visto desde Wireshark | Pendiente |
| Lab 5 | Tráfico en claro frente a cifrado | Pendiente |
| Lab 6 | Writeup final | Pendiente |

## Método de cada lab

1. Escribir una predicción antes de ejecutar nada.
2. Ejecutar los pasos y capturar la evidencia.
3. Comparar el resultado con la predicción y explicar por qué.

## Aviso

Todas las prácticas se realizan en un entorno aislado y sobre máquinas propias. No se escanea ni se ataca ningún sistema sin autorización.

## Autor

Mateo Ayala · ayalamateo456@gmail.com
