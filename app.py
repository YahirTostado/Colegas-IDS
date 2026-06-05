"""
IDS Corporativo — Interfaz Principal (Streamlit)
Sistema de Detección de Intrusos — Captura real de paquetes de red.
"""
import json
import os
import sys
import socket
import logging

import streamlit as st
import pandas as pd

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from utils import database as db
from utils.auth import verify_password, change_password
from core.sniffer import get_sniffer, reset_sniffer

os.makedirs(os.path.join(ROOT, "data", "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(ROOT, "data", "logs", "ids.log"), encoding="utf-8"
        ),
    ],
)

SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")

# ════════════════════════════════════════════════════════════════════════════
# CSS — Diseño corporativo limpio
# ════════════════════════════════════════════════════════════════════════════
CSS = """
<style>
.main .block-container {
    padding-top: 1.75rem;
    padding-bottom: 2rem;
    max-width: 1100px;
}
[data-testid="stSidebar"] {
    background-color: #F8FAFC;
    border-right: 1px solid #E2E8F0;
}
[data-testid="stSidebar"] .block-container { padding-top: 1.5rem; }
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stDecoration"] { display: none; }

.page-header {
    border-bottom: 2px solid #2563EB;
    padding-bottom: 0.6rem;
    margin-bottom: 1.5rem;
}
.page-header h2 {
    color: #1E293B; font-size: 1.3rem; font-weight: 700;
    margin: 0; letter-spacing: -0.01em;
}
.page-header p { color: #64748B; font-size: 0.82rem; margin: 0.25rem 0 0; }

.metric-card {
    background: #FFFFFF; border: 1px solid #E2E8F0;
    border-radius: 8px; padding: 1.25rem 1.5rem; text-align: center;
}
.metric-card .value {
    font-size: 2rem; font-weight: 700; color: #1E293B; line-height: 1;
}
.metric-card .label {
    font-size: 0.75rem; color: #64748B; text-transform: uppercase;
    letter-spacing: 0.07em; font-weight: 600; margin-top: 0.4rem;
}
.metric-card.danger .value  { color: #DC2626; }
.metric-card.warning .value { color: #D97706; }
.metric-card.primary .value { color: #2563EB; }

.badge {
    display: inline-block; padding: 2px 9px; border-radius: 10px;
    font-size: 0.7rem; font-weight: 700;
    letter-spacing: 0.05em; text-transform: uppercase;
}
.badge-critico { background:#FEE2E2; color:#991B1B; }
.badge-alto    { background:#FEF3C7; color:#92400E; }
.badge-medio   { background:#FEF9C3; color:#713F12; }
.badge-info    { background:#DBEAFE; color:#1E40AF; }
.badge-ok      { background:#DCFCE7; color:#166534; }
.badge-gray    { background:#F1F5F9; color:#475569; }

.alert-row {
    border-left: 3px solid #DC2626; background: #FEF2F2;
    padding: 0.6rem 0.9rem; margin-bottom: 0.5rem;
    border-radius: 0 6px 6px 0; font-size: 0.82rem;
}
.alert-row.warning { border-left-color: #D97706; background: #FFFBEB; }
.alert-row.info    { border-left-color: #2563EB; background: #EFF6FF; }
.alert-row strong  { display: block; margin-bottom: 2px; }

.priv-warning {
    background: #FEF3C7; border: 1px solid #FDE68A;
    border-left: 4px solid #D97706; border-radius: 0 8px 8px 0;
    padding: 0.75rem 1rem; font-size: 0.83rem; margin-bottom: 1rem;
}
.priv-warning strong { display: block; margin-bottom: 4px; color: #92400E; }

.info-box {
    background: #F8FAFC; border: 1px solid #E2E8F0;
    border-radius: 8px; padding: 1rem 1.25rem; font-size: 0.82rem;
}
.info-box table { width: 100%; border-collapse: collapse; }
.info-box td { padding: 4px 0; }
.info-box td:first-child { color: #64748B; width: 140px; font-weight: 500; }

.status-dot {
    display: inline-block; width: 9px; height: 9px;
    border-radius: 50%; margin-right: 6px; vertical-align: middle;
}
.dot-green { background: #22C55E; box-shadow: 0 0 5px #22C55E55; }
.dot-red   { background: #EF4444; }
.dot-gray  { background: #94A3B8; }

.sidebar-section {
    font-size: 0.68rem; font-weight: 700; letter-spacing: 0.1em;
    text-transform: uppercase; color: #94A3B8;
    padding: 0.5rem 0 0.25rem; margin-top: 0.5rem;
}
</style>
"""

# ════════════════════════════════════════════════════════════════════════════
# Utilidades del sistema
# ════════════════════════════════════════════════════════════════════════════

def check_privileges():
    """
    True si el proceso puede capturar paquetes de red.
    macOS : verifica acceso de lectura a /dev/bpf0 (no requiere root si se ejecutó
            'sudo chmod o+r /dev/bpf*')
    Linux : verifica root (uid 0)
    Windows: verifica Administrador
    """
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    if sys.platform == "darwin":
        # En macOS Scapy usa dispositivos BPF — intentar abrirlos es la prueba real
        try:
            with open("/dev/bpf0", "rb"):
                return True
        except (PermissionError, OSError):
            return os.geteuid() == 0

    return os.geteuid() == 0


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip.strip())
        return True
    except socket.error:
        return False


def load_settings():
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_settings(data):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ════════════════════════════════════════════════════════════════════════════
# Helpers de UI
# ════════════════════════════════════════════════════════════════════════════

def badge(text, level="info"):
    lvl_map = {
        "Critico": "critico", "Alto": "alto", "Medio": "medio",
        "info": "info", "ok": "ok", "gray": "gray",
    }
    return f'<span class="badge badge-{lvl_map.get(level, "gray")}">{text}</span>'


def dot(active):
    return f'<span class="status-dot {"dot-green" if active else "dot-gray"}"></span>'


def page_header(title, subtitle=""):
    st.markdown(
        f'<div class="page-header"><h2>{title}</h2>'
        + (f"<p>{subtitle}</p>" if subtitle else "")
        + "</div>",
        unsafe_allow_html=True,
    )


def metric_card(value, label, variant=""):
    return (
        f'<div class="metric-card {variant}">'
        f'<div class="value">{value}</div>'
        f'<div class="label">{label}</div>'
        f"</div>"
    )


def privilege_warning():
    """Muestra aviso si no hay privilegios suficientes."""
    if not check_privileges():
        if sys.platform == "darwin":
            cmd = "sudo chmod o+r /dev/bpf*"
            instruccion = (
                "En macOS, ejecuta <strong>una sola vez</strong> en la terminal y recarga:<br>"
                f"<code>{cmd}</code>"
            )
        elif sys.platform == "win32":
            instruccion = "Abre la terminal como <strong>Administrador</strong> y relanza la app."
        else:
            instruccion = (
                "En Linux: <code>sudo venv/bin/streamlit run app.py</code>"
            )
        st.markdown(
            f'<div class="priv-warning">'
            f"<strong>Sin acceso a la interfaz de red — captura inactiva</strong>"
            f"{instruccion}"
            f"</div>",
            unsafe_allow_html=True,
        )
        return True
    return False


def autorefresh(interval_ms, key):
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=interval_ms, key=key)
    except ImportError:
        pass


# ════════════════════════════════════════════════════════════════════════════
# Inicialización
# ════════════════════════════════════════════════════════════════════════════

def init_app():
    db.init_db()
    if "admin_authenticated" not in st.session_state:
        st.session_state.admin_authenticated = False
    if "scanned_devices" not in st.session_state:
        st.session_state.scanned_devices = []


# ════════════════════════════════════════════════════════════════════════════
# Sidebar
# ════════════════════════════════════════════════════════════════════════════

def render_sidebar():
    with st.sidebar:
        st.markdown(
            "<div style='margin-bottom:1rem'>"
            "<div style='font-size:1rem;font-weight:700;color:#1E293B'>IDS Corporativo</div>"
            "<div style='font-size:0.72rem;color:#94A3B8'>Sistema de Detección de Intrusos</div>"
            "</div>",
            unsafe_allow_html=True,
        )

        # Aviso de privilegios en el sidebar
        if not check_privileges():
            st.markdown(
                "<div style='background:#FEF3C7;border-left:3px solid #D97706;"
                "padding:8px 10px;border-radius:0 6px 6px 0;font-size:0.75rem;"
                "margin-bottom:8px;color:#92400E'>"
                "<strong>Sin acceso a BPF</strong><br>"
                "Ejecuta en la terminal:<br>"
                "<code>sudo chmod o+r /dev/bpf*</code><br>"
                "Luego recarga la página."
                "</div>",
                unsafe_allow_html=True,
            )

        st.divider()
        st.markdown('<div class="sidebar-section">Navegación</div>', unsafe_allow_html=True)

        pages = {
            "Dashboard":              "dashboard",
            "Modulo 1: Lista Blanca": "whitelist",
            "Modulo 2: Sitios":       "monitor",
            "Modulo 3: Amenazas":     "threats",
            "Modulo 4: Forense":      "forensics",
            "Configuracion":          "settings",
        }
        selection = st.radio("Pagina", list(pages.keys()), label_visibility="collapsed")

        st.divider()
        st.markdown('<div class="sidebar-section">Motor IDS</div>', unsafe_allow_html=True)

        cfg      = load_settings()
        iface    = cfg.get("network_interface") or "auto"
        sniffer  = get_sniffer(interface=cfg.get("network_interface") or None)

        # Si el sniffer tuvo un error, mostrarlo
        if sniffer.last_error:
            st.markdown(
                f"<div style='background:#FEF2F2;border-left:3px solid #DC2626;"
                f"padding:6px 8px;border-radius:0 4px 4px 0;font-size:0.72rem;"
                f"color:#991B1B;margin-bottom:6px'>{sniffer.last_error}</div>",
                unsafe_allow_html=True,
            )

        st.markdown(
            f"{dot(sniffer.is_running)}"
            f"<span style='font-size:.82rem;color:#334155'>"
            f"{'Activo' if sniffer.is_running else 'Inactivo'}</span>",
            unsafe_allow_html=True,
        )
        st.caption(f"Interfaz: {iface}")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Iniciar", use_container_width=True, disabled=sniffer.is_running):
                ok, err = sniffer.start()
                if not ok and err:
                    st.error(err)
                st.rerun()
        with col2:
            if st.button("Detener", use_container_width=True, disabled=not sniffer.is_running):
                sniffer.stop()
                st.rerun()

        st.divider()
        # Info de red en tiempo real
        local_ip = get_local_ip()
        st.caption(f"IP local: {local_ip}")
        st.caption("UAA · 8vo Sem · ISC 2026")

    return pages[selection]


# ════════════════════════════════════════════════════════════════════════════
# Dashboard
# ════════════════════════════════════════════════════════════════════════════

def page_dashboard():
    page_header("Dashboard", "Estado de seguridad de la red en tiempo real")
    autorefresh(6000, "dash_refresh")
    privilege_warning()

    stats   = db.get_stats()
    sniffer = get_sniffer()

    # Info del sistema
    local_ip  = get_local_ip()
    cfg       = load_settings()
    iface_cfg = cfg.get("network_interface") or "auto-detect"

    from core.scanner import detect_interface
    iface_real = detect_interface() or iface_cfg

    st.markdown(
        f'<div class="info-box"><table>'
        f"<tr><td>IP local</td><td><code>{local_ip}</code></td></tr>"
        f"<tr><td>Interfaz activa</td><td><code>{iface_real}</code></td></tr>"
        f"<tr><td>Motor IDS</td><td>{'<span style=\"color:#16A34A\">Activo</span>' if sniffer.is_running else '<span style=\"color:#94A3B8\">Inactivo</span>'}</td></tr>"
        f"<tr><td>Email alertas</td><td>{cfg.get('admin_email') or '<em style=\"color:#94A3B8\">No configurado</em>'}</td></tr>"
        f"</table></div>",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card(stats["whitelist_alerts"], "Alertas Lista Blanca", "warning"), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card(stats["site_visits"], "Dominios Registrados", "primary"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card(stats["threat_alerts"], "Alertas de Amenaza", "danger"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card(stats["forensic_reports"], "Informes Forenses", ""), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Ultimas alertas — Lista Blanca**")
        alerts = db.fetch_whitelist_alerts(limit=6)
        if alerts:
            for a in alerts:
                st.markdown(
                    f'<div class="alert-row warning">'
                    f'<strong>{a["alert_type"].replace("_", " ")}</strong>'
                    f'IP: <code>{a["src_ip"]}</code> &nbsp;|&nbsp; MAC: <code>{a["src_mac"] or "—"}</code>'
                    f'<br><small style="color:#92400E">{a["timestamp"]}</small>'
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("Sin alertas de lista blanca.")

    with col_b:
        st.markdown("**Ultimas amenazas detectadas**")
        threats = db.fetch_threat_alerts(limit=6)
        if threats:
            for t in threats:
                risk = t["risk_level"]
                st.markdown(
                    f'<div class="alert-row">'
                    f'<strong>{t["threat_type"]} &nbsp;{badge(risk, risk)}</strong>'
                    f'Destino: <code>{t["dst_ip"]}</code>'
                    f'<br><small style="color:#991B1B">{t["timestamp"]}</small>'
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("Sin amenazas detectadas.")

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("**Top dominios visitados**")
    top = db.fetch_top_domains(limit=10)
    if top:
        df = pd.DataFrame(top)
        df.columns = ["Dominio", "Visitas", "Ultima vez"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("Sin registros de dominios. Active el IDS para comenzar la captura.")


# ════════════════════════════════════════════════════════════════════════════
# Módulo 1 — Lista Blanca
# ════════════════════════════════════════════════════════════════════════════

def page_whitelist():
    page_header(
        "Modulo 1: Lista Blanca",
        "Capa 2 (MAC) y Capa 3 (IP) — dispositivos autorizados en la red",
    )
    autorefresh(8000, "wl_refresh")

    wl_path = os.path.join(ROOT, "config", "whitelist.json")
    with open(wl_path) as f:
        wl_data = json.load(f)

    tab_alerts, tab_manage, tab_scan = st.tabs([
        "Alertas en tiempo real", "Gestionar lista blanca", "Escanear red local"
    ])

    # ── Tab 1: Alertas ───────────────────────────────────────────────────────
    with tab_alerts:
        alerts = db.fetch_whitelist_alerts(limit=100)
        if alerts:
            df = pd.DataFrame(alerts)
            df = df[["timestamp", "src_ip", "src_mac", "alert_type", "email_sent"]]
            df.columns = ["Timestamp", "IP Origen", "MAC Origen", "Tipo", "Email Enviado"]
            df["Email Enviado"] = df["Email Enviado"].map({1: "Si", 0: "No"})
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(alerts)} eventos registrados · actualización cada 8 s")
        else:
            st.info("Sin alertas. El sistema monitorea y alertará al detectar dispositivos no autorizados.")

    # ── Tab 2: Gestionar ─────────────────────────────────────────────────────
    with tab_manage:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**IPs autorizadas**")
            current_ips = "\n".join(wl_data.get("authorized_ips", []))
            new_ips_text = st.text_area(
                "Una IP por linea", value=current_ips, height=220, key="wl_ips"
            )
        with col2:
            st.markdown("**MACs autorizadas**")
            current_macs = "\n".join(wl_data.get("authorized_macs", []))
            new_macs_text = st.text_area(
                "Una MAC por linea (aa:bb:cc:dd:ee:ff)",
                value=current_macs, height=220, key="wl_macs"
            )

        if st.button("Guardar lista blanca", type="primary"):
            new_ips  = [ip.strip()  for ip  in new_ips_text.splitlines()  if ip.strip()]
            new_macs = [mac.strip().lower() for mac in new_macs_text.splitlines() if mac.strip()]
            from core.whitelist import WhitelistChecker
            checker = WhitelistChecker()
            checker.save(new_ips, new_macs)
            sniffer = get_sniffer()
            sniffer.whitelist.reload()
            st.success(f"Lista blanca guardada: {len(new_ips)} IPs, {len(new_macs)} MACs.")

    # ── Tab 3: Escáner ARP ───────────────────────────────────────────────────
    with tab_scan:
        st.markdown("Descubre automáticamente los dispositivos activos en tu red local.")
        st.caption(
            "Usa ARP broadcast (requiere privilegios de root/Administrador). "
            "El resultado muestra IP, dirección MAC y hostname de cada equipo encontrado."
        )

        from core.scanner import get_default_network, scan_network
        default_net = get_default_network()

        col_net, col_btn = st.columns([3, 1])
        with col_net:
            target_net = st.text_input(
                "Red a escanear (CIDR)", value=default_net, key="scan_net"
            )
        with col_btn:
            st.markdown("<br>", unsafe_allow_html=True)
            do_scan = st.button("Escanear", type="primary", use_container_width=True)

        if do_scan:
            if not check_privileges():
                st.error(
                    "Se necesitan privilegios de root/Administrador para el escaneo ARP. "
                    "Reinicie la app con sudo."
                )
            else:
                with st.spinner(f"Escaneando {target_net}... (puede tardar hasta 5 segundos)"):
                    try:
                        devices = scan_network(target_net)
                        st.session_state.scanned_devices = devices
                    except PermissionError as e:
                        st.error(str(e))
                    except Exception as e:
                        st.error(f"Error durante el escaneo: {e}")

        if st.session_state.scanned_devices:
            devices = st.session_state.scanned_devices
            st.success(f"{len(devices)} dispositivos encontrados en la red.")

            df_dev = pd.DataFrame(devices)
            df_dev.columns = ["IP", "MAC", "Hostname"]
            st.dataframe(df_dev, use_container_width=True, hide_index=True)

            existing_ips  = wl_data.get("authorized_ips", [])
            existing_macs = wl_data.get("authorized_macs", [])

            # Marcar cuáles ya están en la lista blanca
            options = []
            for d in devices:
                ya_ip  = d["ip"]  in existing_ips
                ya_mac = d["mac"] in existing_macs
                label = f"{d['ip']}  |  {d['mac']}"
                if d["hostname"]:
                    label += f"  |  {d['hostname']}"
                if ya_ip and ya_mac:
                    label += "  [ya autorizado]"
                options.append(label)

            selected = st.multiselect(
                "Seleccionar dispositivos para agregar a la lista blanca:",
                options=options,
                default=[],
            )

            if st.button("Agregar seleccionados", disabled=not selected):
                new_ips  = existing_ips[:]
                new_macs = existing_macs[:]
                count = 0
                for sel in selected:
                    parts = sel.split("  |  ")
                    ip  = parts[0].strip()
                    mac = parts[1].strip()
                    if ip not in new_ips:
                        new_ips.append(ip)
                        count += 1
                    if mac not in new_macs:
                        new_macs.append(mac)

                from core.whitelist import WhitelistChecker
                checker = WhitelistChecker()
                checker.save(new_ips, new_macs)
                sniffer = get_sniffer()
                sniffer.whitelist.reload()
                st.success(f"{count} dispositivos agregados a la lista blanca.")
                st.session_state.scanned_devices = []
                st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# Módulo 2 — Monitoreo de Sitios
# ════════════════════════════════════════════════════════════════════════════

def page_monitor():
    page_header(
        "Modulo 2: Monitoreo de Sitios",
        "Bitacora en tiempo real de dominios visitados — DNS / HTTP / HTTPS",
    )
    autorefresh(5000, "mon_refresh")

    tab_log, tab_top = st.tabs(["Bitacora en tiempo real", "Top dominios"])

    with tab_log:
        visits = db.fetch_site_visits(limit=150)
        if visits:
            df = pd.DataFrame(visits)
            df = df[["timestamp", "src_ip", "domain", "protocol"]]
            df.columns = ["Timestamp", "IP Origen", "Dominio", "Protocolo"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(visits)} registros · actualización cada 5 s")
        else:
            st.info("Sin visitas registradas. Active el IDS para comenzar la captura.")

    with tab_top:
        top = db.fetch_top_domains(limit=25)
        if top:
            df = pd.DataFrame(top)
            df.columns = ["Dominio", "Visitas", "Ultima vez"]
            try:
                import plotly.express as px
                fig = px.bar(
                    df.head(15), x="Visitas", y="Dominio",
                    orientation="h", color_discrete_sequence=["#2563EB"],
                )
                fig.update_layout(
                    plot_bgcolor="#FFFFFF", paper_bgcolor="#FFFFFF",
                    font_color="#1E293B", margin=dict(l=10, r=10, t=10, b=10),
                    xaxis_title="", yaxis_title="", yaxis_autorange="reversed",
                )
                fig.update_xaxes(showgrid=True, gridcolor="#F1F5F9")
                fig.update_yaxes(showgrid=False)
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                pass
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("Sin datos de dominios aún.")


# ════════════════════════════════════════════════════════════════════════════
# Módulo 3 — Inteligencia de Amenazas
# ════════════════════════════════════════════════════════════════════════════

def page_threats():
    page_header(
        "Modulo 3: Inteligencia de Amenazas",
        "Detección de conexiones hacia IPs maliciosas — lista negra en tiempo real",
    )
    autorefresh(7000, "thr_refresh")

    bl_path = os.path.join(ROOT, "config", "blacklist.json")
    with open(bl_path) as f:
        bl_data = json.load(f)

    tab_alerts, tab_bl, tab_import = st.tabs([
        "Alertas de amenaza", "Lista negra activa", "Importar threat feed"
    ])

    # ── Tab 1: Alertas ───────────────────────────────────────────────────────
    with tab_alerts:
        threats = db.fetch_threat_alerts(limit=100)
        if threats:
            df = pd.DataFrame(threats)
            df = df[["timestamp", "src_ip", "dst_ip", "threat_type",
                     "risk_level", "email_sent", "whois_done"]]
            df.columns = ["Timestamp", "IP Origen", "IP Maliciosa",
                          "Tipo", "Riesgo", "Email", "WHOIS"]
            df["Email"] = df["Email"].map({1: "Si", 0: "No"})
            df["WHOIS"] = df["WHOIS"].map({1: "Completado", 0: "Pendiente"})
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(threats)} alertas · actualización cada 7 s")
        else:
            st.info("Sin amenazas detectadas. El sistema monitorea activamente la red.")

    # ── Tab 2: Lista negra ───────────────────────────────────────────────────
    with tab_bl:
        entries = bl_data.get("dangerous_ips", [])
        if entries:
            df = pd.DataFrame(entries)
            df = df[["ip", "threat_type", "risk_level", "description", "source", "reported"]]
            df.columns = ["IP", "Tipo", "Riesgo", "Descripcion", "Fuente", "Reportada"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(entries)} IPs en la lista negra")
        else:
            st.info("La lista negra está vacía. Importa IPs desde un threat feed o agrégalas manualmente.")

        st.divider()
        st.markdown("**Agregar IP manualmente**")
        c1, c2, c3 = st.columns([2, 2, 2])
        with c1:
            new_ip   = st.text_input("Dirección IP", placeholder="1.2.3.4", key="bl_ip")
            new_src  = st.text_input("Fuente / Referencia", placeholder="AbuseIPDB, Shodan...", key="bl_src")
        with c2:
            new_type = st.selectbox("Tipo de amenaza", [
                "Botnet C2", "Malware Distributor", "Phishing",
                "Cryptominer", "APT Infrastructure", "Spyware C2",
                "Exploit Kit", "Scanner", "Spam", "Otro",
            ])
        with c3:
            new_risk = st.selectbox("Nivel de riesgo", ["Critico", "Alto", "Medio"])
        new_desc = st.text_input("Descripcion", placeholder="Descripcion del comportamiento malicioso")

        if st.button("Agregar a lista negra", type="primary", key="bl_add"):
            if new_ip and is_valid_ip(new_ip):
                from datetime import date
                entries.append({
                    "ip":          new_ip.strip(),
                    "threat_type": new_type,
                    "risk_level":  new_risk,
                    "description": new_desc,
                    "source":      new_src or "Manual",
                    "reported":    str(date.today()),
                })
                bl_data["dangerous_ips"] = entries
                with open(bl_path, "w") as f:
                    json.dump(bl_data, f, indent=2, ensure_ascii=False)
                sniffer = get_sniffer()
                sniffer.threat.reload()
                st.success(f"IP {new_ip} agregada. Lista negra recargada.")
                st.rerun()
            else:
                st.error("Ingrese una dirección IP válida.")

    # ── Tab 3: Importar feed ─────────────────────────────────────────────────
    with tab_import:
        st.markdown("**Importar desde un feed de threat intelligence**")
        st.caption(
            "Los feeds deben tener una IP por línea. "
            "Las líneas que empiezan con # son ignoradas. "
            "IPs duplicadas se omiten automáticamente."
        )

        fuentes = bl_data.get("fuentes_recomendadas", [])
        if fuentes:
            with st.expander("Fuentes recomendadas"):
                for f_src in fuentes:
                    st.markdown(
                        f"**{f_src['nombre']}** — Tipo: {f_src['tipo']}, "
                        f"Riesgo: {f_src['riesgo']}  \n`{f_src['url']}`"
                    )

        feed_url = st.text_input(
            "URL del feed",
            placeholder="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        )
        col_t, col_r = st.columns(2)
        with col_t:
            feed_type = st.selectbox("Tipo de amenaza para este feed", [
                "Botnet C2", "Malware Distributor", "Phishing",
                "Cryptominer", "APT Infrastructure", "Spam", "Multiple / Otro",
            ], key="feed_type")
        with col_r:
            feed_risk = st.selectbox("Riesgo", ["Critico", "Alto", "Medio"], key="feed_risk")

        if st.button("Importar desde URL", type="primary"):
            if not feed_url:
                st.error("Ingrese una URL.")
            else:
                with st.spinner("Descargando y procesando feed..."):
                    try:
                        import requests as req
                        resp = req.get(feed_url, timeout=20)
                        resp.raise_for_status()
                        lines = resp.text.splitlines()

                        existing_ips = {e["ip"] for e in entries}
                        added = 0
                        from datetime import date
                        today = str(date.today())

                        for line in lines:
                            line = line.strip()
                            if not line or line.startswith("#") or line.startswith(";"):
                                continue
                            # Soporte para formatos: "1.2.3.4" o "1.2.3.4 # comentario"
                            ip = line.split()[0].split(",")[0].strip()
                            if is_valid_ip(ip) and ip not in existing_ips:
                                entries.append({
                                    "ip":          ip,
                                    "threat_type": feed_type,
                                    "risk_level":  feed_risk,
                                    "description": f"Importado de: {feed_url}",
                                    "source":      feed_url,
                                    "reported":    today,
                                })
                                existing_ips.add(ip)
                                added += 1

                        bl_data["dangerous_ips"] = entries
                        with open(bl_path, "w") as fw:
                            json.dump(bl_data, fw, indent=2, ensure_ascii=False)
                        sniffer = get_sniffer()
                        sniffer.threat.reload()
                        st.success(
                            f"{added} IPs importadas ({len(lines)} lineas procesadas). "
                            f"Lista negra total: {len(entries)} IPs."
                        )
                    except req.exceptions.RequestException as e:
                        st.error(f"Error al descargar el feed: {e}")
                    except Exception as e:
                        st.error(f"Error al procesar el feed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# Módulo 4 — Informes Forenses
# ════════════════════════════════════════════════════════════════════════════

def page_forensics():
    page_header(
        "Modulo 4: Informes Forenses",
        "WHOIS automatizado — contacto de abuso del proveedor de la IP maliciosa",
    )
    autorefresh(10000, "for_refresh")

    tab_auto, tab_manual = st.tabs(["Informes automaticos", "Consulta manual"])

    with tab_auto:
        reports = db.fetch_forensic_reports(limit=50)
        if reports:
            df = pd.DataFrame(reports)
            df = df[["timestamp", "ip", "org", "country", "asn", "abuse_email", "email_sent"]]
            df.columns = ["Timestamp", "IP", "Organizacion", "Pais", "ASN",
                          "Contacto Abuso", "Email Enviado"]
            df["Email Enviado"] = df["Email Enviado"].map({1: "Si", 0: "No"})
            st.dataframe(df, use_container_width=True, hide_index=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("**Detalle — último informe**")
            latest = reports[0]
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**IP investigada:** `{latest['ip']}`")
                st.markdown(f"**Organizacion:** {latest['org'] or 'N/D'}")
                st.markdown(f"**ASN:** {latest['asn'] or 'N/D'}")
                st.markdown(f"**Pais:** {latest['country'] or 'N/D'}")
            with col2:
                st.markdown(f"**Email de abuso:** {latest['abuse_email'] or 'No encontrado'}")
                st.markdown(f"**Telefono de abuso:** {latest.get('abuse_phone') or 'N/D'}")
                st.markdown(f"**Reporte enviado:** {'Si' if latest['email_sent'] else 'No'}")
            with st.expander("Ver datos WHOIS completos"):
                st.code(latest.get("raw_data", "Sin datos"), language="json")
        else:
            st.info("Sin informes forenses. Se generan automáticamente al detectar amenazas (Módulo 3).")

    with tab_manual:
        st.markdown("Consulta WHOIS para cualquier dirección IP.")
        ip_input = st.text_input("Dirección IP", placeholder="8.8.8.8")
        if st.button("Ejecutar WHOIS", type="primary"):
            if ip_input and is_valid_ip(ip_input):
                with st.spinner(f"Consultando WHOIS para {ip_input}..."):
                    from core.forensics import ForensicsEngine
                    result = ForensicsEngine().investigate(ip_input, "Consulta manual")
                if result:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Organizacion", result.get("org", "N/D"))
                        st.metric("Pais", result.get("country", "N/D"))
                    with col2:
                        st.metric("ASN", result.get("asn", "N/D"))
                        st.metric("Contacto de Abuso", result.get("abuse_email") or "No encontrado")
                    with st.expander("Datos WHOIS completos"):
                        st.code(result.get("raw", ""), language="json")
                else:
                    st.error("No se obtuvieron datos WHOIS. La IP puede ser privada o inaccesible.")
            else:
                st.error("Ingrese una dirección IP válida.")


# ════════════════════════════════════════════════════════════════════════════
# Configuración (protegida por contraseña)
# ════════════════════════════════════════════════════════════════════════════

def page_settings():
    page_header(
        "Configuracion",
        "Ajustes del sistema — acceso restringido al administrador",
    )

    # ── Autenticación ────────────────────────────────────────────────────────
    if not st.session_state.get("admin_authenticated", False):
        st.markdown(
            '<div class="alert-row info" style="margin-bottom:1rem">'
            "<strong>Area restringida</strong>"
            "Esta seccion requiere autenticacion de administrador."
            "</div>",
            unsafe_allow_html=True,
        )
        with st.form("login_form"):
            pwd = st.text_input("Contrasena de administrador", type="password")
            if st.form_submit_button("Iniciar sesion", type="primary"):
                if verify_password(pwd):
                    st.session_state.admin_authenticated = True
                    st.rerun()
                else:
                    st.error("Contrasena incorrecta.")
        st.caption("Contrasena por defecto: admin123 — cambiar en la pestaña Seguridad.")
        return

    st.markdown(
        f'{dot(True)}<span style="font-size:.82rem;color:#166534"> Sesion activa</span>',
        unsafe_allow_html=True,
    )
    if st.button("Cerrar sesion"):
        st.session_state.admin_authenticated = False
        st.rerun()

    st.divider()
    cfg = load_settings()

    tab_notif, tab_motor, tab_sec = st.tabs(["Notificaciones", "Motor IDS", "Seguridad"])

    # ── Notificaciones ───────────────────────────────────────────────────────
    with tab_notif:
        st.markdown("**Correo del administrador**")
        st.caption("Todas las alertas del IDS se enviarán a esta dirección.")
        admin_email = st.text_input("Email del administrador", value=cfg.get("admin_email", ""))

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("**Configuracion SMTP**")
        st.caption(
            "Para Gmail: activa Verificación en 2 pasos → genera una "
            "[App Password](https://myaccount.google.com/apppasswords) y úsala aquí."
        )
        col1, col2 = st.columns(2)
        with col1:
            smtp_server = st.text_input("Servidor SMTP", value=cfg.get("smtp_server", "smtp.gmail.com"))
            smtp_user   = st.text_input("Usuario SMTP (tu email)", value=cfg.get("smtp_user", ""))
        with col2:
            smtp_port = st.number_input("Puerto", value=int(cfg.get("smtp_port", 587)), step=1)
            smtp_pass = st.text_input("App Password / Contrasena SMTP",
                                      value=cfg.get("smtp_password", ""), type="password")

        if st.button("Guardar configuracion de notificaciones", type="primary"):
            cfg.update({
                "admin_email":   admin_email,
                "smtp_server":   smtp_server,
                "smtp_port":     smtp_port,
                "smtp_user":     smtp_user,
                "smtp_password": smtp_pass,
            })
            save_settings(cfg)
            st.success("Configuracion guardada.")

        st.divider()
        if st.button("Enviar correo de prueba"):
            with st.spinner("Enviando..."):
                from utils.emailer import send_whitelist_alert
                ok = send_whitelist_alert(get_local_ip(), "test:mac:ids", "IP_NO_AUTORIZADA")
            if ok:
                st.success(f"Correo de prueba enviado a {cfg.get('admin_email')}.")
            else:
                st.error("Error al enviar. Verifique la configuracion SMTP.")

    # ── Motor IDS ────────────────────────────────────────────────────────────
    with tab_motor:
        from core.scanner import detect_interface, get_local_ip as sc_ip

        local_ip    = sc_ip()
        iface_real  = detect_interface()

        st.markdown(
            f'<div class="info-box"><table>'
            f"<tr><td>IP local detectada</td><td><code>{local_ip}</code></td></tr>"
            f"<tr><td>Interfaz detectada</td><td><code>{iface_real or 'N/D'}</code></td></tr>"
            f"</table></div>",
            unsafe_allow_html=True,
        )
        st.markdown("<br>", unsafe_allow_html=True)

        iface_val = cfg.get("network_interface") or ""
        iface = st.text_input(
            "Interfaz de red (dejar en blanco para auto-detectar)",
            value=iface_val,
            placeholder=iface_real or "eth0 / en0 / wlan0",
        )

        col_auto, _ = st.columns([1, 2])
        with col_auto:
            if st.button("Usar interfaz auto-detectada"):
                iface = iface_real or ""
                st.info(f"Interfaz: {iface or 'auto'}")

        cooldown = st.slider(
            "Cooldown entre alertas duplicadas (segundos)",
            min_value=10, max_value=300,
            value=int(cfg.get("alert_cooldown_seconds", 60)),
        )

        if st.button("Guardar y reiniciar motor", type="primary"):
            cfg["network_interface"]      = iface.strip() or None
            cfg["alert_cooldown_seconds"] = cooldown
            save_settings(cfg)
            reset_sniffer()
            st.success("Motor reconfigurado. Inicie el sniffer desde el panel lateral.")

    # ── Seguridad ─────────────────────────────────────────────────────────────
    with tab_sec:
        st.markdown("**Cambiar contrasena de administrador**")
        with st.form("change_pwd_form"):
            old_pwd  = st.text_input("Contrasena actual",    type="password")
            new_pwd  = st.text_input("Nueva contrasena",     type="password")
            conf_pwd = st.text_input("Confirmar contrasena", type="password")
            if st.form_submit_button("Cambiar contrasena", type="primary"):
                if not verify_password(old_pwd):
                    st.error("La contrasena actual es incorrecta.")
                elif new_pwd != conf_pwd:
                    st.error("Las contrasenas nuevas no coinciden.")
                elif len(new_pwd) < 6:
                    st.error("La contrasena debe tener al menos 6 caracteres.")
                else:
                    change_password(new_pwd)
                    st.success("Contrasena actualizada.")

        st.divider()
        st.markdown("**Limpiar base de datos**")
        st.warning("Esta accion elimina todos los registros del IDS. Es irreversible.")
        if st.button("Eliminar todos los registros", type="secondary"):
            import sqlite3
            conn = sqlite3.connect(os.path.join(ROOT, "data", "ids.db"))
            for table in ["whitelist_alerts", "site_visits", "threat_alerts", "forensic_reports"]:
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
            conn.close()
            st.success("Base de datos vaciada.")
            st.rerun()


# ════════════════════════════════════════════════════════════════════════════
# Punto de entrada
# ════════════════════════════════════════════════════════════════════════════

def main():
    st.set_page_config(
        page_title="IDS Corporativo",
        page_icon=None,
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(CSS, unsafe_allow_html=True)
    init_app()

    page = render_sidebar()
    {
        "dashboard": page_dashboard,
        "whitelist": page_whitelist,
        "monitor":   page_monitor,
        "threats":   page_threats,
        "forensics": page_forensics,
        "settings":  page_settings,
    }[page]()


if __name__ == "__main__":
    main()
