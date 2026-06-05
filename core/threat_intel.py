"""
Módulo 3: Inteligencia de Amenazas.
Carga una lista negra de IPs maliciosas y alerta al detectar conexiones hacia ellas.
Dispara análisis forense (Módulo 4) en segundo plano al detectar una amenaza.
"""
import json
import os
import logging
import threading
from datetime import datetime, timedelta

from utils import database as db
from utils.emailer import send_threat_alert

logger = logging.getLogger("ids.threat_intel")

BLACKLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "blacklist.json"
)

_alert_cache = {}
_cache_lock = threading.Lock()
COOLDOWN_SECONDS = 120


class ThreatIntelligence:
    def __init__(self, cooldown=COOLDOWN_SECONDS):
        self.cooldown = cooldown
        self._blacklist = {}
        self.reload()

    def reload(self):
        try:
            with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._blacklist = {
                entry["ip"]: entry
                for entry in data.get("dangerous_ips", [])
            }
            logger.info("Lista negra cargada: %d IPs", len(self._blacklist))
        except Exception as e:
            logger.error("Error al cargar lista negra: %s", e)

    def get_blacklist(self):
        return list(self._blacklist.values())

    def check(self, src_ip, dst_ip, timestamp=None):
        for ip_to_check in [dst_ip, src_ip]:
            if not ip_to_check:
                continue
            entry = self._blacklist.get(ip_to_check)
            if entry:
                self._handle_threat(src_ip, dst_ip, entry, timestamp)
                break

    def _handle_threat(self, src_ip, dst_ip, entry, timestamp=None):
        cache_key = "%s|%s" % (src_ip, dst_ip)
        with _cache_lock:
            last = _alert_cache.get(cache_key)
            now = timestamp or datetime.now()
            if last and (now - last) < timedelta(seconds=self.cooldown):
                return
            _alert_cache[cache_key] = now

        threat_ip   = entry["ip"]
        threat_type = entry.get("threat_type", "Desconocido")
        risk_level  = entry.get("risk_level", "Alto")
        description = entry.get("description", "")

        row_id = db.insert_threat_alert(
            src_ip or "", threat_ip, threat_type, risk_level, description
        )
        sent = send_threat_alert(
            src_ip or "externa", threat_ip, threat_type, risk_level, description
        )
        if sent:
            db.mark_threat_email_sent(row_id)

        logger.warning(
            "[THREAT] %s | %s -> %s | Riesgo: %s",
            threat_type, src_ip, threat_ip, risk_level
        )

        threading.Thread(
            target=_run_forensics,
            args=(threat_ip, threat_type, row_id),
            daemon=True,
        ).start()


def _run_forensics(ip, threat_type, threat_row_id):
    try:
        from core.forensics import ForensicsEngine
        engine = ForensicsEngine()
        engine.investigate(ip, threat_type)
        db.mark_threat_whois_done(threat_row_id)
    except Exception as e:
        logger.error("Error en análisis forense para %s: %s", ip, e)
