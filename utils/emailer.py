"""
Módulo de envío de correos electrónicos de alerta.
Usa smtplib con STARTTLS. Soporta Gmail App Passwords.

Carga de credenciales (en orden de prioridad):
  1. Variables de entorno IDS_SMTP_USER / IDS_SMTP_PASSWORD (definidas en .env)
  2. settings.json (fallback para servidores/puertos no sensibles)
Las contraseñas NUNCA se almacenan en texto plano en el código fuente.
"""
import smtplib
import json
import os
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

logger = logging.getLogger("ids.emailer")

ROOT          = os.path.dirname(os.path.dirname(__file__))
SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")
ENV_PATH      = os.path.join(ROOT, ".env")


def _load_env_file() -> dict:
    """Lee el archivo .env y retorna un dict {CLAVE: valor}."""
    env = {}
    if not os.path.exists(ENV_PATH):
        return env
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip()
    return env

# ──────────────────────────────────────────────
# Paleta de colores del correo (corporativa)
# ──────────────────────────────────────────────
COLORS = {
    "primary":   "#2563EB",
    "warning":   "#D97706",
    "danger":    "#DC2626",
    "success":   "#16A34A",
    "bg":        "#F8FAFC",
    "border":    "#E2E8F0",
    "text":      "#1E293B",
    "muted":     "#64748B",
}

_EMAIL_BASE = """
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background:{bg}; margin:0; padding:0; color:{text}; }}
  .wrapper {{ max-width:600px; margin:32px auto; background:#fff;
              border:1px solid {border}; border-radius:8px; overflow:hidden; }}
  .header  {{ background:{header_color}; padding:24px 32px; }}
  .header h1 {{ margin:0; color:#fff; font-size:18px; font-weight:600; letter-spacing:.02em; }}
  .header p  {{ margin:4px 0 0; color:rgba(255,255,255,.8); font-size:13px; }}
  .body    {{ padding:24px 32px; }}
  .body p  {{ line-height:1.6; margin:0 0 12px; font-size:14px; }}
  .detail-box {{ background:{bg}; border:1px solid {border}; border-radius:6px;
                 padding:16px; margin:16px 0; }}
  .detail-box table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .detail-box td {{ padding:6px 4px; vertical-align:top; }}
  .detail-box td:first-child {{ color:{muted}; width:140px; font-weight:500; }}
  .badge {{ display:inline-block; padding:3px 10px; border-radius:12px;
             font-size:11px; font-weight:700; letter-spacing:.05em; text-transform:uppercase; }}
  .badge-danger  {{ background:#FEE2E2; color:#991B1B; }}
  .badge-warning {{ background:#FEF3C7; color:#92400E; }}
  .badge-info    {{ background:#DBEAFE; color:#1E40AF; }}
  .footer  {{ background:{bg}; border-top:1px solid {border};
              padding:16px 32px; font-size:11px; color:{muted}; text-align:center; }}
  hr {{ border:none; border-top:1px solid {border}; margin:16px 0; }}
</style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <h1>{title}</h1>
    <p>Sistema de Detección de Intrusos — {timestamp}</p>
  </div>
  <div class="body">
    {content}
  </div>
  <div class="footer">
    Este mensaje fue generado automáticamente por el IDS corporativo.
    No responda a este correo.
  </div>
</div>
</body>
</html>
"""


def _load_settings() -> dict:
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _send(subject: str, html_body: str) -> bool:
    try:
        cfg  = _load_settings()
        env  = _load_env_file()

        smtp_server = cfg.get("smtp_server", "smtp.gmail.com")
        smtp_port   = int(cfg.get("smtp_port", 587))
        admin_email = cfg.get("admin_email", "")

        # Credenciales: .env tiene prioridad sobre settings.json
        smtp_user = (
            os.environ.get("IDS_SMTP_USER") or
            env.get("IDS_SMTP_USER") or
            cfg.get("smtp_user", "")
        )
        smtp_pass = (
            os.environ.get("IDS_SMTP_PASSWORD") or
            env.get("IDS_SMTP_PASSWORD") or
            cfg.get("smtp_password", "")
        )

        if not all([smtp_user, smtp_pass, admin_email]):
            logger.warning("Configuración SMTP incompleta — correo no enviado.")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Colega's IDS <{smtp_user}>"
        msg["To"]      = admin_email
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, admin_email, msg.as_string())

        logger.info(f"Correo enviado a {admin_email}: {subject}")
        return True

    except Exception as e:
        logger.error(f"Error al enviar correo: {e}")
        return False


def send_whitelist_alert(src_ip: str, src_mac: str, alert_type: str) -> bool:
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    badge = "badge-warning" if alert_type == "IP_NO_AUTORIZADA" else "badge-danger"
    label = "IP No Autorizada" if "IP" in alert_type else "MAC No Autorizada"

    content = f"""
    <p>Se ha detectado tráfico de red proveniente de un dispositivo <strong>no registrado</strong>
       en la lista blanca corporativa.</p>
    <div class="detail-box">
      <table>
        <tr><td>Tipo de Alerta</td><td><span class="badge {badge}">{label}</span></td></tr>
        <tr><td>Dirección IP</td><td><code>{src_ip}</code></td></tr>
        <tr><td>Dirección MAC</td><td><code>{src_mac or 'No disponible'}</code></td></tr>
        <tr><td>Detectado el</td><td>{ts}</td></tr>
      </table>
    </div>
    <p>Se recomienda identificar el dispositivo e incorporarlo a la lista blanca si es legítimo,
       o bloquear la conexión si se trata de un intruso.</p>
    """
    html = _EMAIL_BASE.format(
        title="Alerta de Lista Blanca — Dispositivo No Autorizado",
        timestamp=ts, content=content, header_color=COLORS["warning"],
        **COLORS
    )
    return _send(f"[IDS] Alerta: Dispositivo no autorizado — {src_ip}", html)


def send_threat_alert(src_ip: str, dst_ip: str, threat_type: str,
                      risk_level: str, description: str) -> bool:
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    risk_badge = "badge-danger" if risk_level in ("Critico", "Alto") else "badge-warning"

    content = f"""
    <p>Se ha detectado una conexión hacia una <strong>IP catalogada como maliciosa</strong>
       en la base de inteligencia de amenazas.</p>
    <div class="detail-box">
      <table>
        <tr><td>Nivel de Riesgo</td><td><span class="badge {risk_badge}">{risk_level}</span></td></tr>
        <tr><td>Tipo de Amenaza</td><td><strong>{threat_type}</strong></td></tr>
        <tr><td>IP de Origen</td><td><code>{src_ip or 'Externa'}</code></td></tr>
        <tr><td>IP Destino (maliciosa)</td><td><code>{dst_ip}</code></td></tr>
        <tr><td>Descripción</td><td>{description}</td></tr>
        <tr><td>Detectado el</td><td>{ts}</td></tr>
      </table>
    </div>
    <hr>
    <p><strong>Acción recomendada:</strong> Aislar el equipo origen de la red e iniciar
       procedimiento forense. Se adjuntará informe WHOIS en mensaje separado.</p>
    """
    html = _EMAIL_BASE.format(
        title=f"ALERTA DE EMERGENCIA — {threat_type}",
        timestamp=ts, content=content, header_color=COLORS["danger"],
        **COLORS
    )
    return _send(f"[IDS] EMERGENCIA: {threat_type} — IP {dst_ip}", html)


def send_forensic_report(ip: str, asn: str, org: str, country: str,
                         abuse_email: str, abuse_phone: str,
                         threat_type: str, raw_data: str) -> bool:
    ts = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    abuse_section = ""
    if abuse_email:
        abuse_section = f"""
        <p>Puede reportar el abuso directamente al proveedor usando los siguientes datos:</p>
        <div class="detail-box">
          <table>
            <tr><td>Correo de Abuso</td><td><a href="mailto:{abuse_email}">{abuse_email}</a></td></tr>
            <tr><td>Teléfono de Abuso</td><td>{abuse_phone or 'No disponible'}</td></tr>
          </table>
        </div>
        """

    content = f"""
    <p>Se ha completado la consulta forense automatizada para la IP maliciosa
       detectada en el incidente de <strong>{threat_type}</strong>.</p>

    <div class="detail-box">
      <table>
        <tr><td>IP Investigada</td><td><code>{ip}</code></td></tr>
        <tr><td>ASN</td><td>{asn or 'N/D'}</td></tr>
        <tr><td>Organización</td><td>{org or 'N/D'}</td></tr>
        <tr><td>País</td><td>{country or 'N/D'}</td></tr>
        <tr><td>Correo de Abuso</td><td>{abuse_email or 'No encontrado'}</td></tr>
        <tr><td>Teléfono de Abuso</td><td>{abuse_phone or 'No disponible'}</td></tr>
        <tr><td>Fecha Consulta</td><td>{ts}</td></tr>
      </table>
    </div>

    {abuse_section}

    <hr>
    <p><strong>Datos WHOIS completos:</strong></p>
    <div class="detail-box">
      <pre style="font-size:11px;overflow:auto;white-space:pre-wrap;">{raw_data[:2000]}</pre>
    </div>
    """
    html = _EMAIL_BASE.format(
        title=f"Reporte Forense — IP {ip}",
        timestamp=ts, content=content, header_color=COLORS["primary"],
        **COLORS
    )
    return _send(f"[IDS] Informe Forense: {ip} ({org or 'Desconocido'})", html)
