"""
Módulo 2: Monitoreo de Sitios.
Registra dominios visitados via DNS y HTTP/HTTPS en tiempo real.
De-duplica entradas: la misma IP+dominio no se registra más de una vez por minuto.
"""
import logging
import threading
from datetime import datetime, timedelta

from utils import database as db

logger = logging.getLogger("ids.monitor")

_visit_cache: dict[str, datetime] = {}
_cache_lock = threading.Lock()
DEDUP_SECONDS = 60


class SiteMonitor:
    def log_domain(self, src_ip: str, domain: str, protocol: str,
                   timestamp: datetime | None = None) -> None:
        domain = domain.lower().rstrip(".")
        if not domain or len(domain) < 4:
            return
        if _is_noise(domain):
            return

        cache_key = f"{src_ip}|{domain}"
        with _cache_lock:
            last = _visit_cache.get(cache_key)
            now = timestamp or datetime.now()
            if last is not None and (now - last) < timedelta(seconds=DEDUP_SECONDS):
                return
            _visit_cache[cache_key] = now

        db.insert_site_visit(src_ip, domain, protocol)
        logger.debug(f"[MONITOR] {protocol} {src_ip} → {domain}")


def _is_noise(domain: str) -> bool:
    """Filtra dominios de infraestructura interna que no son relevantes."""
    noise_patterns = (
        "local", ".arpa", "localhost", "_", "wpad",
        "isatap", "mdns", "multicast",
    )
    return any(domain.endswith(p) or domain == p.lstrip(".") for p in noise_patterns)
