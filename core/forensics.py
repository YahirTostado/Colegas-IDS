"""
Módulo 4: Automatización Forense.
Realiza consultas WHOIS para IPs maliciosas y extrae datos de contacto de abuso.
Envía el reporte forense completo al administrador.
"""
import json
import logging

from utils import database as db
from utils.emailer import send_forensic_report

logger = logging.getLogger("ids.forensics")


class ForensicsEngine:
    def investigate(self, ip: str, threat_type: str = "Desconocido") -> dict | None:
        logger.info(f"[FORENSE] Iniciando consulta WHOIS para {ip}")
        result = self._whois_lookup(ip)
        if not result:
            logger.warning(f"[FORENSE] Sin resultados para {ip}")
            return None

        row_id = db.insert_forensic_report(
            ip=ip,
            asn=result.get("asn", ""),
            org=result.get("org", ""),
            country=result.get("country", ""),
            abuse_email=result.get("abuse_email", ""),
            abuse_phone=result.get("abuse_phone", ""),
            raw_data=result.get("raw", ""),
        )

        sent = send_forensic_report(
            ip=ip,
            asn=result.get("asn", "N/D"),
            org=result.get("org", "N/D"),
            country=result.get("country", "N/D"),
            abuse_email=result.get("abuse_email", ""),
            abuse_phone=result.get("abuse_phone", ""),
            threat_type=threat_type,
            raw_data=result.get("raw", ""),
        )
        if sent:
            db.mark_forensic_email_sent(row_id)

        logger.info(f"[FORENSE] Reporte completado para {ip} — {result.get('org')}")
        return result

    def _whois_lookup(self, ip: str) -> dict | None:
        # Primero intentamos con ipwhois (más completo, extrae abuso)
        result = self._try_ipwhois(ip)
        if result:
            return result
        # Fallback: RDAP via API pública
        return self._try_rdap(ip)

    def _try_ipwhois(self, ip: str) -> dict | None:
        try:
            from ipwhois import IPWhois
            from ipwhois.exceptions import IPDefinedError

            w = IPWhois(ip)
            data = w.lookup_rdap(depth=1)

            org     = data.get("asn_description", "")
            country = data.get("asn_country_code", "")
            asn     = f"AS{data.get('asn', '')}"

            abuse_email = ""
            abuse_phone = ""
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "abuse" in roles:
                    vcard = entity.get("contact", {})
                    emails = vcard.get("email", [])
                    phones = vcard.get("phone", [])
                    if emails:
                        abuse_email = emails[0].get("value", "") if isinstance(emails[0], dict) else str(emails[0])
                    if phones:
                        abuse_phone = phones[0].get("value", "") if isinstance(phones[0], dict) else str(phones[0])
                    break

            # Si no hubo abuse contact en entidades RDAP, buscar en objetos de red
            if not abuse_email:
                for obj_key, obj_val in data.get("objects", {}).items():
                    contact = obj_val.get("contact", {})
                    if contact:
                        for role in obj_val.get("roles", []):
                            if "abuse" in role.lower():
                                emails = contact.get("email", [])
                                if emails:
                                    abuse_email = emails[0].get("value", "") if isinstance(emails[0], dict) else str(emails[0])
                                break

            raw = json.dumps(data, indent=2, default=str)[:3000]
            return {
                "asn": asn, "org": org, "country": country,
                "abuse_email": abuse_email, "abuse_phone": abuse_phone,
                "raw": raw,
            }

        except ImportError:
            logger.warning("ipwhois no instalado — usando fallback RDAP")
            return None
        except Exception as e:
            logger.debug(f"ipwhois error para {ip}: {e}")
            return None

    def _try_rdap(self, ip: str) -> dict | None:
        """Consulta RDAP pública de ARIN como fallback."""
        try:
            import urllib.request
            import urllib.error

            url = f"https://rdap.arin.net/registry/ip/{ip}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            org     = data.get("name", "")
            country = ""
            asn     = ""
            abuse_email = ""

            for entity in data.get("entities", []):
                for role in entity.get("roles", []):
                    if "abuse" in role.lower():
                        for vcard_array in entity.get("vcardArray", [[]])[1:]:
                            for item in vcard_array:
                                if isinstance(item, list) and item[0] == "email":
                                    abuse_email = item[3]

            raw = json.dumps(data, indent=2, default=str)[:3000]
            return {
                "asn": asn, "org": org, "country": country,
                "abuse_email": abuse_email, "abuse_phone": "",
                "raw": raw,
            }
        except Exception as e:
            logger.debug(f"RDAP fallback error para {ip}: {e}")
            return None
