"""
Motor de captura de paquetes en tiempo real con Scapy.
Requiere privilegios de root (Linux/macOS) o Administrador (Windows).
"""
import re
import logging
import threading
from datetime import datetime

from core.whitelist import WhitelistChecker
from core.monitor import SiteMonitor
from core.threat_intel import ThreatIntelligence

logger = logging.getLogger("ids.sniffer")

# Singleton global — sobrevive reruns de Streamlit sin crear múltiples instancias
_instance = None
_instance_lock = threading.Lock()


def get_sniffer(interface=None):
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = PacketSniffer(interface=interface)
        return _instance


def reset_sniffer():
    global _instance
    with _instance_lock:
        if _instance:
            _instance.stop()
        _instance = None


class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.active    = False
        self._thread   = None
        self.last_error = None

        self.whitelist = WhitelistChecker()
        self.monitor   = SiteMonitor()
        self.threat    = ThreatIntelligence()

    @property
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running:
            return False, "El sniffer ya está en ejecución."
        self.active     = True
        self.last_error = None
        self._thread    = threading.Thread(
            target=self._scapy_loop, daemon=True, name="ids-sniffer"
        )
        self._thread.start()
        logger.info("Sniffer iniciado — interfaz: %s", self.interface or "auto")
        return True, None

    def stop(self):
        self.active = False
        logger.info("Sniffer detenido")

    def _scapy_loop(self):
        try:
            from scapy.all import sniff
            sniff(
                iface=self.interface or None,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.active,
                filter="ip or arp",
            )
        except PermissionError:
            self.last_error = (
                "Privilegios insuficientes. "
                "En Linux/macOS ejecute con 'sudo'. "
                "En Windows abra la terminal como Administrador."
            )
            logger.error(self.last_error)
            self.active = False
        except OSError as e:
            self.last_error = (
                f"Error de red: {e}. "
                "Verifique que la interfaz configurada exista y esté activa."
            )
            logger.error(self.last_error)
            self.active = False
        except Exception as e:
            self.last_error = f"Error inesperado en el sniffer: {e}"
            logger.error(self.last_error)
            self.active = False

    def _process_packet(self, packet):
        try:
            from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw

            ts      = datetime.now()
            src_mac = packet[Ether].src.lower() if Ether in packet else None

            if IP not in packet:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Módulo 1 — Lista Blanca
            self.whitelist.check(src_ip, src_mac, ts)

            # Módulo 3 — Inteligencia de Amenazas
            self.threat.check(src_ip, dst_ip, ts)

            # Módulo 2 — DNS (UDP puerto 53, solo queries, no respuestas)
            if UDP in packet and packet[UDP].dport == 53 and DNS in packet:
                if packet[DNS].qr == 0 and DNSQR in packet:
                    domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    self.monitor.log_domain(src_ip, domain, "DNS", ts)

            # Módulo 2 — HTTP (puerto 80 / 8080)
            if TCP in packet and Raw in packet:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
                if packet[TCP].dport in (80, 8080) or packet[TCP].sport in (80, 8080):
                    host_m = re.search(r"(?i)Host:\s*([^\r\n]+)", payload)
                    if host_m:
                        proto = "GET" if payload.startswith("GET") else "HTTP"
                        self.monitor.log_domain(src_ip, host_m.group(1).strip(), proto, ts)

                # Módulo 2 — HTTPS / TLS SNI (puerto 443)
                if packet[TCP].dport == 443:
                    sni = _extract_sni(packet[Raw].load)
                    if sni:
                        self.monitor.log_domain(src_ip, sni, "HTTPS", ts)

        except Exception as e:
            logger.debug("Error procesando paquete: %s", e)


def _extract_sni(data):
    """Extrae el Server Name Indication del TLS Client Hello."""
    try:
        # Verifica cabecera TLS: content type 0x16 (Handshake), versión 0x03xx
        if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03:
            return None
        # Saltar: TLS record (5) + handshake type+len (4) + client version (2) + random (32)
        pos = 5 + 4 + 2 + 32
        if pos >= len(data):
            return None
        # Session ID
        pos += 1 + data[pos]
        if pos + 2 > len(data):
            return None
        # Cipher suites
        pos += 2 + ((data[pos] << 8) | data[pos + 1])
        # Compression methods
        if pos >= len(data):
            return None
        pos += 1 + data[pos]
        # Extensions
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + ((data[pos] << 8) | data[pos + 1])
        pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = (data[pos] << 8) | data[pos + 1]
            ext_len  = (data[pos + 2] << 8) | data[pos + 3]
            pos += 4
            # Extensión 0 = SNI
            if ext_type == 0 and pos + 5 <= len(data):
                pos += 3  # server name list length + name type
                name_len = (data[pos] << 8) | data[pos + 1]
                pos += 2
                return data[pos:pos + name_len].decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None
