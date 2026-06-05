"""
Módulo 1: Lista Blanca (Capa 2 y 3).
Valida IPs y MACs contra la lista de dispositivos autorizados.
Envía alerta por correo si detecta un dispositivo no registrado.
"""
import json
import os
import logging
import threading
from datetime import datetime, timedelta

from utils import database as db
from utils.emailer import send_whitelist_alert

logger = logging.getLogger("ids.whitelist")

WHITELIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "whitelist.json"
)

_alert_cache = {}
_cache_lock = threading.Lock()
COOLDOWN_SECONDS = 60


class WhitelistChecker:
    def __init__(self, cooldown=COOLDOWN_SECONDS):
        self.cooldown = cooldown
        self._authorized_ips = set()
        self._authorized_macs = set()
        self.reload()

    def reload(self):
        try:
            with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._authorized_ips  = {ip.strip()  for ip  in data.get("authorized_ips",  [])}
            self._authorized_macs = {mac.lower().strip() for mac in data.get("authorized_macs", [])}
            logger.info(
                "Lista blanca cargada: %d IPs, %d MACs",
                len(self._authorized_ips), len(self._authorized_macs)
            )
        except Exception as e:
            logger.error("Error al cargar lista blanca: %s", e)

    def save(self, ips, macs):
        data = {
            "description": "Equipos autorizados en la red corporativa",
            "authorized_ips":  [ip.strip()  for ip  in ips],
            "authorized_macs": [mac.lower().strip() for mac in macs],
            "last_updated": datetime.now().strftime("%Y-%m-%d"),
            "updated_by": "admin",
        }
        with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.reload()

    def get_authorized_ips(self):
        return sorted(self._authorized_ips)

    def get_authorized_macs(self):
        return sorted(self._authorized_macs)

    def check(self, src_ip, src_mac, timestamp=None):
        violations = []

        if src_ip and _is_local_network(src_ip):
            if src_ip not in self._authorized_ips:
                violations.append(("IP_NO_AUTORIZADA", src_ip, src_mac))

        if src_mac and src_ip and _is_local_network(src_ip):
            if src_mac.lower() not in self._authorized_macs:
                violations.append(("MAC_NO_AUTORIZADA", src_ip, src_mac))

        for alert_type, ip, mac in violations:
            cache_key = "%s:%s:%s" % (alert_type, ip, mac)
            if _should_alert(cache_key, self.cooldown):
                row_id = db.insert_whitelist_alert(ip, mac or "", alert_type)
                sent = send_whitelist_alert(ip, mac or "", alert_type)
                if sent:
                    db.mark_whitelist_email_sent(row_id)
                logger.warning("[WHITELIST] %s — IP: %s  MAC: %s", alert_type, ip, mac)


def _should_alert(key, cooldown):
    with _cache_lock:
        last = _alert_cache.get(key)
        now = datetime.now()
        if last is None or (now - last) > timedelta(seconds=cooldown):
            _alert_cache[key] = now
            return True
        return False


def _is_local_network(ip):
    prefixes = (
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    )
    return any(ip.startswith(p) for p in prefixes)
