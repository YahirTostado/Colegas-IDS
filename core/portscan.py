"""
Módulo Plus: Detección de Escaneo de Puertos (Port Scan Detection)
Detecta ataques de reconocimiento: cuando un host accede a demasiados
puertos distintos en un corto período se considera un escáner activo.
"""
import threading
import logging
from datetime import datetime, timedelta

from utils import database as db
from utils.emailer import send_threat_alert

logger = logging.getLogger("ids.portscan")

WINDOW_SECONDS   = 60    # ventana deslizante en segundos
THRESHOLD_PORTS  = 15    # puertos únicos para disparar alerta
COOLDOWN_SECONDS = 120   # cooldown por IP origen (evitar spam)


class PortScanDetector:
    """
    Mantiene una ventana deslizante de puertos accedidos por cada IP.
    Cuando una IP toca ≥ THRESHOLD_PORTS puertos únicos en WINDOW_SECONDS
    segundos, se genera una alerta PORT_SCAN en threat_alerts.
    """

    def __init__(self, window=WINDOW_SECONDS, threshold=THRESHOLD_PORTS,
                 cooldown=COOLDOWN_SECONDS):
        self.window    = window
        self.threshold = threshold
        self.cooldown  = cooldown
        self._tracker     = {}   # {src_ip: {dst_port: datetime}}
        self._alert_cache = {}   # {src_ip: datetime ultima alerta}
        self._lock        = threading.Lock()

    def check(self, src_ip: str, dst_port: int, timestamp=None):
        """
        Registra el acceso de src_ip a dst_port.
        Si se supera el umbral dentro de la ventana se inserta una alerta.
        """
        if not src_ip or dst_port is None:
            return

        ts = timestamp or datetime.now()

        with self._lock:
            cutoff = ts - timedelta(seconds=self.window)

            if src_ip not in self._tracker:
                self._tracker[src_ip] = {}

            self._tracker[src_ip][dst_port] = ts

            # Eliminar entradas fuera de la ventana
            self._tracker[src_ip] = {
                p: t for p, t in self._tracker[src_ip].items() if t > cutoff
            }

            unique = len(self._tracker[src_ip])
            if unique < self.threshold:
                return

            # Verificar cooldown para esta IP
            last = self._alert_cache.get(src_ip)
            if last and (ts - last).total_seconds() < self.cooldown:
                return

            self._alert_cache[src_ip] = ts
            ports = sorted(self._tracker[src_ip].keys())

        # Fuera del lock: insertar en BD y enviar correo
        desc = (
            f"Escaneo de puertos detectado: {unique} puertos únicos "
            f"en {self.window}s. Puertos muestreados: {ports[:20]}"
        )
        row_id = db.insert_threat_alert(
            src_ip=src_ip,
            dst_ip="MULTIPLE",
            threat_type="PORT_SCAN",
            risk_level="Alto",
            description=desc,
        )
        try:
            sent = send_threat_alert(
                src_ip, "MULTIPLE (port scan)",
                "PORT_SCAN", "Alto", desc,
            )
            if sent:
                db.mark_threat_email_sent(row_id)
        except Exception as e:
            logger.error("Error enviando alerta de port scan: %s", e)

        logger.warning(
            "[PORT_SCAN] %s tocó %d puertos únicos en %ds — alerta generada",
            src_ip, unique, self.window,
        )
