"""
Escáner de red ARP — descubre dispositivos activos en la subred local.
Usa ARP broadcast para obtener IP, MAC y hostname de cada equipo.
Requiere los mismos privilegios que el sniffer (root / Administrador).
"""
import socket
import logging

logger = logging.getLogger("ids.scanner")


def get_local_ip():
    """Retorna la dirección IP de esta máquina abriendo un socket UDP sin enviar datos."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_default_network():
    """Calcula la subred /24 a partir de la IP local. Ej: 192.168.1.100 → 192.168.1.0/24"""
    ip = get_local_ip()
    prefix = ".".join(ip.split(".")[:3])
    return f"{prefix}.0/24"


def detect_interface():
    """Devuelve el nombre de la interfaz de red que Scapy usaría por defecto."""
    try:
        from scapy.all import conf
        return str(conf.iface)
    except Exception:
        return None


def scan_network(network=None):
    """
    Realiza un escaneo ARP en la red indicada (por defecto la subred /24 local).
    Retorna lista de dicts: [{"ip": ..., "mac": ..., "hostname": ...}, ...]

    Lanza PermissionError si no hay privilegios de root/Administrador.
    Lanza RuntimeError si Scapy no está disponible.
    """
    if network is None:
        network = get_default_network()

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        raise RuntimeError("Scapy no está instalado. Ejecute: pip install scapy")

    logger.info("Iniciando escaneo ARP en %s", network)

    try:
        # Paquete ARP broadcast a toda la subred
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(pkt, timeout=3, verbose=0)
    except PermissionError:
        raise PermissionError(
            "Se requieren privilegios de root/Administrador para el escaneo ARP."
        )
    except Exception as e:
        logger.error("Error en escaneo ARP: %s", e)
        return []

    devices = []
    for _, received in answered:
        hostname = _resolve_hostname(received.psrc)
        devices.append({
            "ip":       received.psrc,
            "mac":      received.hwsrc.lower(),
            "hostname": hostname,
        })

    # Ordenar por IP (numéricamente)
    devices.sort(key=lambda d: list(map(int, d["ip"].split("."))))
    logger.info("Escaneo completado: %d dispositivos encontrados", len(devices))
    return devices


def _resolve_hostname(ip):
    """Resolución DNS inversa — si falla, retorna cadena vacía."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
