"""
IDS Corporativo — Interfaz Principal (Streamlit)
Sistema de Detección de Intrusos — Diseño moderno corporativo.
"""
import json
import os
import sys
import socket
import logging
from datetime import datetime, timedelta

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
# CSS — Diseño moderno corporativo (estilo dashboard HRM)
# ════════════════════════════════════════════════════════════════════════════
CSS = """
<style>
/* ── Fondo global ─────────────────────────────────────────────────────── */
[data-testid="stAppViewContainer"] > .main {
    background-color: #F0F4F8;
}
.main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 1280px;
    background: transparent;
}

/* ── Sidebar ──────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background-color: #FFFFFF;
    border-right: 1px solid #E2E8F0;
}
[data-testid="stSidebar"] .block-container { padding-top: 1.25rem; }
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stDecoration"] { display: none; }

/* ── Cabecera de página ───────────────────────────────────────────────── */
.page-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1.5rem;
}
.page-header-icon {
    width: 40px; height: 40px;
    background: #EFF6FF;
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.2rem;
}
.page-header h2 {
    color: #0F172A; font-size: 1.25rem; font-weight: 700;
    margin: 0; letter-spacing: -0.02em;
}
.page-header p { color: #64748B; font-size: 0.8rem; margin: 0.15rem 0 0; }

/* ── Tarjetas de métricas ─────────────────────────────────────────────── */
.metric-card {
    background: #FFFFFF;
    border: 1px solid #E9EEF5;
    border-radius: 14px;
    padding: 1.25rem 1.4rem 1rem;
    box-shadow: 0 1px 4px rgba(15,23,42,0.06);
    position: relative;
    overflow: hidden;
}
.metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    border-radius: 14px 14px 0 0;
    background: #E2E8F0;
}
.metric-card.primary::before  { background: #2563EB; }
.metric-card.warning::before  { background: #F59E0B; }
.metric-card.danger::before   { background: #EF4444; }
.metric-card.success::before  { background: #10B981; }

.metric-card .mc-icon {
    font-size: 1.5rem; margin-bottom: 0.5rem; display: block;
}
.metric-card .mc-value {
    font-size: 2.2rem; font-weight: 800;
    color: #0F172A; line-height: 1; letter-spacing: -0.03em;
}
.metric-card.primary .mc-value  { color: #1D4ED8; }
.metric-card.warning .mc-value  { color: #D97706; }
.metric-card.danger  .mc-value  { color: #DC2626; }
.metric-card.success .mc-value  { color: #059669; }

.metric-card .mc-label {
    font-size: 0.72rem; font-weight: 600;
    color: #94A3B8; text-transform: uppercase;
    letter-spacing: 0.07em; margin-top: 0.3rem;
}
.metric-card .mc-sub {
    font-size: 0.75rem; color: #64748B;
    margin-top: 0.5rem; padding-top: 0.5rem;
    border-top: 1px solid #F1F5F9;
}

/* ── Banner de alerta activa ──────────────────────────────────────────── */
.live-alert-banner {
    background: linear-gradient(135deg, #FEF2F2, #FFF5F5);
    border: 1px solid #FECACA;
    border-left: 4px solid #DC2626;
    border-radius: 10px;
    padding: 0.85rem 1.2rem;
    margin-bottom: 1.25rem;
    display: flex;
    align-items: center;
    gap: 0.9rem;
    animation: pulse-border 2s ease-in-out infinite;
}
@keyframes pulse-border {
    0%, 100% { border-left-color: #DC2626; }
    50%       { border-left-color: #F87171; }
}
.live-alert-banner .lab-icon { font-size: 1.4rem; flex-shrink: 0; }
.live-alert-banner .lab-title {
    font-weight: 700; color: #991B1B; font-size: 0.9rem; margin: 0;
}
.live-alert-banner .lab-sub {
    color: #B91C1C; font-size: 0.78rem; margin: 0.1rem 0 0;
}
.live-alert-banner .lab-time {
    font-size: 0.7rem; color: #DC2626; margin-left: auto; white-space: nowrap;
}

/* ── Tarjeta de contenido ─────────────────────────────────────────────── */
.content-card {
    background: #FFFFFF;
    border: 1px solid #E9EEF5;
    border-radius: 14px;
    padding: 1.25rem 1.4rem;
    box-shadow: 0 1px 4px rgba(15,23,42,0.06);
    margin-bottom: 1rem;
}
.content-card .cc-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 1rem; padding-bottom: 0.75rem;
    border-bottom: 1px solid #F1F5F9;
}
.content-card .cc-title {
    font-weight: 700; font-size: 0.9rem; color: #1E293B;
}
.content-card .cc-subtitle {
    font-size: 0.72rem; color: #94A3B8; margin-top: 1px;
}
.content-card .cc-badge {
    background: #EFF6FF; color: #1D4ED8;
    font-size: 0.68rem; font-weight: 700;
    padding: 3px 8px; border-radius: 20px;
    letter-spacing: 0.05em;
}

/* ── Filas de alerta ──────────────────────────────────────────────────── */
.alert-item {
    display: flex; align-items: flex-start; gap: 0.75rem;
    padding: 0.7rem 0; border-bottom: 1px solid #F8FAFC;
}
.alert-item:last-child { border-bottom: none; }
.alert-item .ai-dot {
    width: 8px; height: 8px; border-radius: 50%;
    flex-shrink: 0; margin-top: 5px;
}
.ai-dot.danger  { background: #EF4444; box-shadow: 0 0 4px #EF444466; }
.ai-dot.warning { background: #F59E0B; }
.ai-dot.info    { background: #3B82F6; }
.alert-item .ai-body { flex: 1; min-width: 0; }
.alert-item .ai-title {
    font-size: 0.8rem; font-weight: 600; color: #1E293B;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.alert-item .ai-meta { font-size: 0.72rem; color: #94A3B8; margin-top: 1px; }

/* ── Badges ───────────────────────────────────────────────────────────── */
.badge {
    display: inline-block; padding: 2px 8px; border-radius: 20px;
    font-size: 0.67rem; font-weight: 700; letter-spacing: 0.05em;
    text-transform: uppercase;
}
.badge-critico { background: #FEE2E2; color: #991B1B; }
.badge-alto    { background: #FEF3C7; color: #92400E; }
.badge-medio   { background: #FEF9C3; color: #713F12; }
.badge-info    { background: #DBEAFE; color: #1E40AF; }
.badge-ok      { background: #DCFCE7; color: #166534; }
.badge-gray    { background: #F1F5F9; color: #475569; }

/* ── Info box ─────────────────────────────────────────────────────────── */
.info-box {
    background: #F8FAFC; border: 1px solid #E2E8F0;
    border-radius: 10px; padding: 1rem 1.25rem; font-size: 0.82rem;
}
.info-box table { width: 100%; border-collapse: collapse; }
.info-box td { padding: 5px 0; }
.info-box td:first-child { color: #64748B; width: 140px; font-weight: 600; }

/* ── Status dot ───────────────────────────────────────────────────────── */
.status-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; margin-right: 5px; vertical-align: middle;
}
.dot-green { background: #22C55E; box-shadow: 0 0 5px #22C55E66; }
.dot-red   { background: #EF4444; }
.dot-gray  { background: #CBD5E0; }

/* ── Sidebar nav ──────────────────────────────────────────────────────── */
.sidebar-logo {
    padding: 0.25rem 0 1rem;
    border-bottom: 1px solid #F1F5F9;
    margin-bottom: 0.75rem;
}
.sidebar-logo .sl-title {
    font-size: 1rem; font-weight: 800; color: #0F172A; letter-spacing: -0.02em;
}
.sidebar-logo .sl-sub {
    font-size: 0.68rem; color: #94A3B8; margin-top: 2px;
}
.sidebar-section {
    font-size: 0.62rem; font-weight: 700; letter-spacing: 0.12em;
    text-transform: uppercase; color: #CBD5E0;
    padding: 0.6rem 0 0.3rem;
}

/* ── Warning privilegios ──────────────────────────────────────────────── */
.priv-warning {
    background: #FFFBEB; border: 1px solid #FDE68A;
    border-left: 3px solid #F59E0B; border-radius: 0 8px 8px 0;
    padding: 0.65rem 0.9rem; font-size: 0.75rem; margin-bottom: 0.75rem;
    color: #92400E;
}
.priv-warning strong { display: block; margin-bottom: 2px; }

/* ── Motor status ─────────────────────────────────────────────────────── */
.motor-card {
    background: #F8FAFC; border: 1px solid #E2E8F0;
    border-radius: 10px; padding: 0.75rem;
    margin-top: 0.5rem;
}
.motor-card .mc-status { font-size: 0.8rem; font-weight: 600; color: #1E293B; }
.motor-card .mc-iface  { font-size: 0.7rem; color: #94A3B8; margin-top: 2px; }

/* ── Tabla estilizada ─────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border-radius: 8px;
    overflow: hidden;
}
</style>
"""


# ════════════════════════════════════════════════════════════════════════════
# Utilidades del sistema
# ════════════════════════════════════════════════════════════════════════════

def check_privileges():
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    if sys.platform == "darwin":
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
    cls = "dot-green" if active else "dot-gray"
    return f'<span class="status-dot {cls}"></span>'


def page_header(icon, title, subtitle=""):
    st.markdown(
        f'<div class="page-header">'
        f'<div class="page-header-icon">{icon}</div>'
        f'<div><h2>{title}</h2>'
        + (f'<p>{subtitle}</p>' if subtitle else '')
        + '</div></div>',
        unsafe_allow_html=True,
    )


def metric_card(value, label, variant="", icon="", sub=""):
    return (
        f'<div class="metric-card {variant}">'
        + (f'<span class="mc-icon">{icon}</span>' if icon else '')
        + f'<div class="mc-value">{value}</div>'
        f'<div class="mc-label">{label}</div>'
        + (f'<div class="mc-sub">{sub}</div>' if sub else '')
        + '</div>'
    )


def autorefresh(interval_ms, key):
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=interval_ms, key=key)
    except ImportError:
        pass


def render_live_alert_banner():
    """Banner rojo si hay alertas en los últimos 30 minutos."""
    cutoff = (datetime.now() - timedelta(minutes=30)).isoformat(sep=" ", timespec="seconds")

    wl_alerts = db.fetch_whitelist_alerts(limit=5)
    th_alerts = db.fetch_threat_alerts(limit=5)

    recent_wl = [a for a in wl_alerts if a.get("timestamp", "") >= cutoff]
    recent_th = [a for a in th_alerts if a.get("timestamp", "") >= cutoff]

    total_recent = len(recent_wl) + len(recent_th)
    if total_recent == 0:
        return

    if recent_th:
        last = recent_th[0]
        detail = f"IP maliciosa detectada: {last['dst_ip']} — {last['threat_type']}"
        ts = last["timestamp"]
    else:
        last = recent_wl[0]
        detail = f"Dispositivo no autorizado: {last['src_ip']} ({last['alert_type'].replace('_', ' ')})"
        ts = last["timestamp"]

    st.markdown(
        f'<div class="live-alert-banner">'
        f'<div class="lab-icon">🚨</div>'
        f'<div>'
        f'<p class="lab-title">⚠ {total_recent} alerta{"s" if total_recent != 1 else ""} reciente{"s" if total_recent != 1 else ""} detectada{"s" if total_recent != 1 else ""}</p>'
        f'<p class="lab-sub">{detail}</p>'
        f'</div>'
        f'<span class="lab-time">{ts}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


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
        # Logo
        stats = db.get_stats()
        total_alerts = stats["whitelist_alerts"] + stats["threat_alerts"]

        st.markdown(
            '<div class="sidebar-logo">'
            '<div class="sl-title">🛡 IDS Corporativo</div>'
            '<div class="sl-sub">Sistema de Detección de Intrusos</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        if not check_privileges():
            st.markdown(
                '<div class="priv-warning">'
                '<strong>Sin acceso BPF</strong>'
                'Ejecuta: <code>sudo chmod o+r /dev/bpf*</code>'
                '</div>',
                unsafe_allow_html=True,
            )

        st.markdown('<div class="sidebar-section">Navegación</div>', unsafe_allow_html=True)

        pages = {
            "📊  Dashboard":             "dashboard",
            "✅  Módulo 1: Lista Blanca": "whitelist",
            "🌐  Módulo 2: Sitios":       "monitor",
            "⚠️  Módulo 3: Amenazas":     "threats",
            "🔍  Módulo 4: Forense":      "forensics",
            "⚙️  Configuración":          "settings",
        }
        selection = st.radio("Pagina", list(pages.keys()), label_visibility="collapsed")

        st.markdown('<div class="sidebar-section">Motor IDS</div>', unsafe_allow_html=True)

        cfg     = load_settings()
        iface   = cfg.get("network_interface") or "auto"
        sniffer = get_sniffer(interface=cfg.get("network_interface") or None)

        if sniffer.last_error:
            st.error(sniffer.last_error, icon="🔴")

        running = sniffer.is_running
        st.markdown(
            f'<div class="motor-card">'
            f'{dot(running)}<span class="mc-status">{"Activo" if running else "Inactivo"}</span>'
            f'<div class="mc-iface">Interfaz: {iface}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Iniciar", use_container_width=True, disabled=running):
                ok, err = sniffer.start()
                if not ok and err:
                    st.error(err)
                st.rerun()
        with col2:
            if st.button("Detener", use_container_width=True, disabled=not running):
                sniffer.stop()
                st.rerun()

        st.markdown('<div class="sidebar-section">Red</div>', unsafe_allow_html=True)
        local_ip = get_local_ip()
        st.caption(f"IP local: **{local_ip}**")
        st.caption("UAA · 8vo Sem · ISC 2026")

        if total_alerts > 0:
            st.markdown(
                f'<div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;'
                f'padding:8px 12px;margin-top:8px;text-align:center;font-size:0.75rem;color:#991B1B;font-weight:700">'
                f'🚨 {total_alerts} alertas totales registradas</div>',
                unsafe_allow_html=True,
            )

    return pages[selection]


# ════════════════════════════════════════════════════════════════════════════
# Dashboard
# ════════════════════════════════════════════════════════════════════════════

def page_dashboard():
    page_header("📊", "Dashboard", "Estado de seguridad de la red en tiempo real")
    autorefresh(5000, "dash_refresh")

    if not check_privileges():
        if sys.platform == "darwin":
            st.warning("Sin acceso a interfaz de red. Ejecuta: `sudo chmod o+r /dev/bpf*` y recarga.", icon="⚠️")
        elif sys.platform == "win32":
            st.warning("Abre la terminal como Administrador y relanza la app.", icon="⚠️")
        else:
            st.warning("Ejecuta: `sudo venv/bin/streamlit run app.py`", icon="⚠️")

    # Banner de alertas recientes
    render_live_alert_banner()

    stats   = db.get_stats()
    sniffer = get_sniffer()

    # ── Info del sistema ──────────────────────────────────────────────────
    local_ip  = get_local_ip()
    cfg       = load_settings()

    from core.scanner import detect_interface
    iface_real = detect_interface() or (cfg.get("network_interface") or "auto-detect")

    with st.expander("Información del sistema", expanded=False):
        st.markdown(
            f'<div class="info-box"><table>'
            f"<tr><td>IP local</td><td><code>{local_ip}</code></td></tr>"
            f"<tr><td>Interfaz activa</td><td><code>{iface_real}</code></td></tr>"
            f"<tr><td>Motor IDS</td><td>{'<span style=\"color:#059669;font-weight:600\">Activo</span>' if sniffer.is_running else '<span style=\"color:#94A3B8\">Inactivo</span>'}</td></tr>"
            f"<tr><td>Email alertas</td><td>{cfg.get('admin_email') or '<em style=\"color:#94A3B8\">No configurado</em>'}</td></tr>"
            f"</table></div>",
            unsafe_allow_html=True,
        )

    # ── Métricas principales ──────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            metric_card(stats["whitelist_alerts"], "Alertas Lista Blanca",
                        "warning", "🛡",
                        "Dispositivos no autorizados"),
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            metric_card(stats["site_visits"], "Dominios Registrados",
                        "primary", "🌐",
                        "Visitas DNS / HTTP / HTTPS"),
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            metric_card(stats["threat_alerts"], "Amenazas Detectadas",
                        "danger", "⚠️",
                        "Conexiones a IPs maliciosas"),
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            metric_card(stats["forensic_reports"], "Informes Forenses",
                        "success", "🔍",
                        "WHOIS automatizados"),
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Gráfica + Panel de alertas recientes ─────────────────────────────
    col_chart, col_panel = st.columns([3, 2])

    with col_chart:
        st.markdown(
            '<div class="content-card">'
            '<div class="cc-header">'
            '<div><div class="cc-title">📈 Top Dominios Visitados</div>'
            '<div class="cc-subtitle">Sitios más frecuentes capturados por el IDS</div></div>'
            '<span class="cc-badge">TOP 15</span>'
            '</div>',
            unsafe_allow_html=True,
        )

        top = db.fetch_top_domains(limit=15)
        if top:
            df_top = pd.DataFrame(top)
            df_top.columns = ["Dominio", "Visitas", "Ultima vez"]

            try:
                import plotly.express as px
                import plotly.graph_objects as go

                # Color gradient: more visits = darker blue
                max_v = df_top["Visitas"].max()
                colors = [
                    f"rgba(37, 99, 235, {0.35 + 0.65 * (v / max_v)})"
                    for v in df_top["Visitas"]
                ]

                fig = go.Figure(go.Bar(
                    x=df_top["Visitas"],
                    y=df_top["Dominio"],
                    orientation="h",
                    marker_color=colors,
                    marker_line_width=0,
                    text=df_top["Visitas"],
                    textposition="outside",
                    textfont=dict(size=11, color="#1E293B"),
                ))
                fig.update_layout(
                    plot_bgcolor="#FFFFFF",
                    paper_bgcolor="#FFFFFF",
                    font=dict(color="#1E293B", size=11),
                    margin=dict(l=0, r=40, t=10, b=10),
                    xaxis=dict(showgrid=True, gridcolor="#F1F5F9",
                               showticklabels=False, zeroline=False),
                    yaxis=dict(showgrid=False, autorange="reversed",
                               tickfont=dict(size=11)),
                    height=380,
                    showlegend=False,
                )
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                st.dataframe(df_top, use_container_width=True, hide_index=True)
        else:
            st.info("Sin registros de dominios. Active el IDS para comenzar la captura.", icon="ℹ️")

        st.markdown('</div>', unsafe_allow_html=True)

    with col_panel:
        # Panel de alertas recientes combinadas
        st.markdown(
            '<div class="content-card" style="height:460px;overflow:hidden;">'
            '<div class="cc-header">'
            '<div><div class="cc-title">🚨 Alertas Recientes</div>'
            '<div class="cc-subtitle">Lista blanca + amenazas</div></div>'
            '</div>',
            unsafe_allow_html=True,
        )

        wl_alerts = db.fetch_whitelist_alerts(limit=5)
        th_alerts = db.fetch_threat_alerts(limit=5)

        items_html = ""

        for t in th_alerts[:4]:
            items_html += (
                f'<div class="alert-item">'
                f'<div class="ai-dot danger"></div>'
                f'<div class="ai-body">'
                f'<div class="ai-title">🔴 {t["threat_type"]}</div>'
                f'<div class="ai-meta">IP: {t["dst_ip"]} · {badge(t["risk_level"], t["risk_level"])}</div>'
                f'<div class="ai-meta">{t["timestamp"]}</div>'
                f'</div></div>'
            )

        for a in wl_alerts[:4]:
            items_html += (
                f'<div class="alert-item">'
                f'<div class="ai-dot warning"></div>'
                f'<div class="ai-body">'
                f'<div class="ai-title">🟡 {a["alert_type"].replace("_", " ")}</div>'
                f'<div class="ai-meta">IP: <code>{a["src_ip"]}</code></div>'
                f'<div class="ai-meta">{a["timestamp"]}</div>'
                f'</div></div>'
            )

        if not items_html:
            items_html = '<div style="color:#94A3B8;font-size:0.8rem;padding:1rem 0;text-align:center">Sin alertas registradas</div>'

        st.markdown(items_html + '</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Gráfica de amenazas por tipo ──────────────────────────────────────
    threats_all = db.fetch_threat_alerts(limit=200)
    if threats_all:
        st.markdown(
            '<div class="content-card">'
            '<div class="cc-header">'
            '<div class="cc-title">📊 Distribución de Amenazas</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        df_th = pd.DataFrame(threats_all)
        try:
            import plotly.express as px
            counts = df_th.groupby("threat_type").size().reset_index(name="count")
            fig2 = px.bar(
                counts, x="threat_type", y="count",
                color_discrete_sequence=["#EF4444"],
                labels={"threat_type": "Tipo de Amenaza", "count": "Cantidad"},
            )
            fig2.update_layout(
                plot_bgcolor="#FFFFFF", paper_bgcolor="#FFFFFF",
                font=dict(color="#1E293B", size=11),
                margin=dict(l=10, r=10, t=10, b=10),
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor="#F1F5F9"),
                height=200, showlegend=False,
            )
            fig2.update_traces(marker_line_width=0)
            st.plotly_chart(fig2, use_container_width=True)
        except ImportError:
            st.dataframe(df_th[["timestamp", "threat_type", "risk_level", "dst_ip"]].head(10),
                         use_container_width=True, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# Módulo 1 — Lista Blanca
# ════════════════════════════════════════════════════════════════════════════

def page_whitelist():
    page_header("✅", "Módulo 1: Lista Blanca",
                "Capa 2 (MAC) y Capa 3 (IP) — dispositivos autorizados en la red")
    autorefresh(6000, "wl_refresh")

    render_live_alert_banner()

    wl_path = os.path.join(ROOT, "config", "whitelist.json")
    with open(wl_path) as f:
        wl_data = json.load(f)

    tab_alerts, tab_manage, tab_scan = st.tabs([
        "🚨 Alertas en tiempo real", "⚙️ Gestionar lista blanca", "🔎 Escanear red local"
    ])

    with tab_alerts:
        alerts = db.fetch_whitelist_alerts(limit=100)
        if alerts:
            df = pd.DataFrame(alerts)
            df = df[["timestamp", "src_ip", "src_mac", "alert_type", "email_sent"]]
            df.columns = ["Timestamp", "IP Origen", "MAC Origen", "Tipo", "Email Enviado"]
            df["Email Enviado"] = df["Email Enviado"].map({1: "✅ Sí", 0: "No"})
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(alerts)} eventos registrados · actualización cada 6 s")
        else:
            st.info("Sin alertas. El sistema monitoreará y alertará al detectar dispositivos no autorizados.", icon="ℹ️")

    with tab_manage:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**IPs autorizadas**")
            current_ips = "\n".join(wl_data.get("authorized_ips", []))
            new_ips_text = st.text_area(
                "Una IP por línea", value=current_ips, height=220, key="wl_ips"
            )
        with col2:
            st.markdown("**MACs autorizadas**")
            current_macs = "\n".join(wl_data.get("authorized_macs", []))
            new_macs_text = st.text_area(
                "Una MAC por línea (aa:bb:cc:dd:ee:ff)",
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
                st.error("Se necesitan privilegios de root/Administrador para el escaneo ARP.")
            else:
                with st.spinner(f"Escaneando {target_net}..."):
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
                options=options, default=[],
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
    page_header("🌐", "Módulo 2: Monitoreo de Sitios",
                "Bitácora en tiempo real de dominios visitados — DNS / HTTP / HTTPS")
    autorefresh(5000, "mon_refresh")

    tab_log, tab_top, tab_stats = st.tabs([
        "📋 Bitácora en tiempo real", "🏆 Top dominios", "📊 Estadísticas"
    ])

    with tab_log:
        visits = db.fetch_site_visits(limit=150)
        if visits:
            df = pd.DataFrame(visits)
            df = df[["timestamp", "src_ip", "domain", "protocol"]]
            df.columns = ["Timestamp", "IP Origen", "Dominio", "Protocolo"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(visits)} registros · actualización cada 5 s")
        else:
            st.info("Sin visitas registradas. Active el IDS para comenzar la captura.", icon="ℹ️")

    with tab_top:
        top = db.fetch_top_domains(limit=25)
        if top:
            df = pd.DataFrame(top)
            df.columns = ["Dominio", "Visitas", "Última vez"]

            try:
                import plotly.express as px
                import plotly.graph_objects as go

                max_v = df["Visitas"].max()
                colors = [
                    f"rgba(37, 99, 235, {0.3 + 0.7 * (v / max_v)})"
                    for v in df["Visitas"]
                ]

                fig = go.Figure(go.Bar(
                    x=df["Visitas"],
                    y=df["Dominio"],
                    orientation="h",
                    marker_color=colors,
                    marker_line_width=0,
                    text=df["Visitas"],
                    textposition="outside",
                ))
                fig.update_layout(
                    plot_bgcolor="#FFFFFF", paper_bgcolor="#FFFFFF",
                    font=dict(color="#1E293B", size=12),
                    margin=dict(l=0, r=40, t=20, b=10),
                    xaxis=dict(showgrid=True, gridcolor="#F1F5F9",
                               showticklabels=False, zeroline=False,
                               title="Número de visitas"),
                    yaxis=dict(showgrid=False, autorange="reversed"),
                    height=500, showlegend=False,
                    title=dict(text="Dominios más visitados", font=dict(size=14)),
                )
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                pass
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("Sin datos de dominios aún.")

    with tab_stats:
        visits_all = db.fetch_site_visits(limit=1000)
        if visits_all:
            df_all = pd.DataFrame(visits_all)

            try:
                import plotly.express as px

                col_a, col_b = st.columns(2)

                with col_a:
                    proto_counts = df_all.groupby("protocol").size().reset_index(name="count")
                    fig_pie = px.pie(
                        proto_counts, names="protocol", values="count",
                        title="Distribución por Protocolo",
                        color_discrete_sequence=["#2563EB", "#10B981", "#F59E0B", "#EF4444"],
                    )
                    fig_pie.update_layout(
                        paper_bgcolor="#FFFFFF", font=dict(color="#1E293B", size=11),
                        margin=dict(l=10, r=10, t=40, b=10), height=280,
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)

                with col_b:
                    ip_counts = df_all.groupby("src_ip").size().reset_index(name="count")
                    ip_counts = ip_counts.sort_values("count", ascending=False).head(10)
                    fig_ip = px.bar(
                        ip_counts, x="src_ip", y="count",
                        title="Top IPs más activas",
                        color_discrete_sequence=["#1D4ED8"],
                        labels={"src_ip": "IP Origen", "count": "Visitas"},
                    )
                    fig_ip.update_layout(
                        plot_bgcolor="#FFFFFF", paper_bgcolor="#FFFFFF",
                        font=dict(color="#1E293B", size=11),
                        margin=dict(l=10, r=10, t=40, b=10), height=280, showlegend=False,
                    )
                    fig_ip.update_traces(marker_line_width=0)
                    st.plotly_chart(fig_ip, use_container_width=True)

            except ImportError:
                st.dataframe(df_all, use_container_width=True, hide_index=True)
        else:
            st.info("Sin datos estadísticos aún. Active el IDS para comenzar.", icon="ℹ️")


# ════════════════════════════════════════════════════════════════════════════
# Módulo 3 — Inteligencia de Amenazas
# ════════════════════════════════════════════════════════════════════════════

def page_threats():
    page_header("⚠️", "Módulo 3: Inteligencia de Amenazas",
                "Detección de conexiones hacia IPs maliciosas — lista negra en tiempo real")
    autorefresh(5000, "thr_refresh")

    render_live_alert_banner()

    bl_path = os.path.join(ROOT, "config", "blacklist.json")
    with open(bl_path) as f:
        bl_data = json.load(f)

    tab_alerts, tab_bl, tab_import = st.tabs([
        "🚨 Alertas de amenaza", "🗂 Lista negra activa", "📥 Importar threat feed"
    ])

    with tab_alerts:
        threats = db.fetch_threat_alerts(limit=100)
        if threats:
            df = pd.DataFrame(threats)
            df = df[["timestamp", "src_ip", "dst_ip", "threat_type",
                     "risk_level", "email_sent", "whois_done"]]
            df.columns = ["Timestamp", "IP Origen", "IP Maliciosa",
                          "Tipo", "Riesgo", "Email", "WHOIS"]
            df["Email"] = df["Email"].map({1: "✅ Sí", 0: "No"})
            df["WHOIS"] = df["WHOIS"].map({1: "Completado", 0: "Pendiente"})
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(threats)} alertas · actualización cada 5 s")
        else:
            st.info("Sin amenazas detectadas. El sistema monitorea activamente la red.", icon="ℹ️")

    with tab_bl:
        entries = bl_data.get("dangerous_ips", [])
        if entries:
            df = pd.DataFrame(entries)
            df = df[["ip", "threat_type", "risk_level", "description", "source", "reported"]]
            df.columns = ["IP", "Tipo", "Riesgo", "Descripción", "Fuente", "Reportada"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(entries)} IPs en la lista negra")
        else:
            st.info("La lista negra está vacía. Importa IPs o agrégalas manualmente.")

        st.divider()
        st.markdown("**Agregar IP manualmente**")
        c1, c2, c3 = st.columns([2, 2, 2])
        with c1:
            new_ip  = st.text_input("Dirección IP", placeholder="1.2.3.4", key="bl_ip")
            new_src = st.text_input("Fuente / Referencia", placeholder="AbuseIPDB...", key="bl_src")
        with c2:
            new_type = st.selectbox("Tipo de amenaza", [
                "Botnet C2", "Malware Distributor", "Phishing",
                "Cryptominer", "APT Infrastructure", "Spyware C2",
                "Exploit Kit", "Scanner", "Spam", "Otro",
            ])
        with c3:
            new_risk = st.selectbox("Nivel de riesgo", ["Critico", "Alto", "Medio"])
        new_desc = st.text_input("Descripción", placeholder="Comportamiento malicioso...")

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

    with tab_import:
        st.markdown("**Importar desde un feed de threat intelligence**")
        st.caption(
            "Los feeds deben tener una IP por línea. "
            "Las líneas que empiezan con # son ignoradas."
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
                            f"{added} IPs importadas ({len(lines)} líneas procesadas). "
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
    page_header("🔍", "Módulo 4: Informes Forenses",
                "WHOIS automatizado — contacto de abuso del proveedor de la IP maliciosa")
    autorefresh(10000, "for_refresh")

    tab_auto, tab_manual = st.tabs(["📄 Informes automáticos", "🔎 Consulta manual"])

    with tab_auto:
        reports = db.fetch_forensic_reports(limit=50)
        if reports:
            df = pd.DataFrame(reports)
            df = df[["timestamp", "ip", "org", "country", "asn", "abuse_email", "email_sent"]]
            df.columns = ["Timestamp", "IP", "Organización", "País", "ASN",
                          "Contacto Abuso", "Email Enviado"]
            df["Email Enviado"] = df["Email Enviado"].map({1: "✅ Sí", 0: "No"})
            st.dataframe(df, use_container_width=True, hide_index=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("**Detalle — último informe**")
            latest = reports[0]
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**IP investigada:** `{latest['ip']}`")
                st.markdown(f"**Organización:** {latest['org'] or 'N/D'}")
                st.markdown(f"**ASN:** {latest['asn'] or 'N/D'}")
                st.markdown(f"**País:** {latest['country'] or 'N/D'}")
            with col2:
                st.markdown(f"**Email de abuso:** {latest['abuse_email'] or 'No encontrado'}")
                st.markdown(f"**Teléfono de abuso:** {latest.get('abuse_phone') or 'N/D'}")
                st.markdown(f"**Reporte enviado:** {'✅ Sí' if latest['email_sent'] else 'No'}")
            with st.expander("Ver datos WHOIS completos"):
                st.code(latest.get("raw_data", "Sin datos"), language="json")
        else:
            st.info("Sin informes forenses. Se generan automáticamente al detectar amenazas.", icon="ℹ️")

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
                        st.metric("Organización", result.get("org", "N/D"))
                        st.metric("País", result.get("country", "N/D"))
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
    page_header("⚙️", "Configuración",
                "Ajustes del sistema — acceso restringido al administrador")

    if not st.session_state.get("admin_authenticated", False):
        st.info("Esta sección requiere autenticación de administrador.", icon="🔒")
        with st.form("login_form"):
            pwd = st.text_input("Contraseña de administrador", type="password")
            if st.form_submit_button("Iniciar sesión", type="primary"):
                if verify_password(pwd):
                    st.session_state.admin_authenticated = True
                    st.rerun()
                else:
                    st.error("Contraseña incorrecta.")
        st.caption("Contraseña por defecto: admin123 — cambiar en la pestaña Seguridad.")
        return

    st.markdown(
        f'{dot(True)}<span style="font-size:.82rem;color:#059669;font-weight:600"> Sesión activa</span>',
        unsafe_allow_html=True,
    )
    if st.button("Cerrar sesión"):
        st.session_state.admin_authenticated = False
        st.rerun()

    st.divider()
    cfg = load_settings()

    tab_notif, tab_motor, tab_sec = st.tabs([
        "📧 Notificaciones", "🔧 Motor IDS", "🔐 Seguridad"
    ])

    with tab_notif:
        st.markdown("**Correo del administrador**")
        admin_email = st.text_input("Email del administrador", value=cfg.get("admin_email", ""))

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("**Configuración SMTP**")
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
            smtp_pass = st.text_input("App Password / Contraseña SMTP",
                                      value=cfg.get("smtp_password", ""), type="password")

        if st.button("Guardar configuración de notificaciones", type="primary"):
            cfg.update({
                "admin_email":   admin_email,
                "smtp_server":   smtp_server,
                "smtp_port":     smtp_port,
                "smtp_user":     smtp_user,
                "smtp_password": smtp_pass,
            })
            save_settings(cfg)
            st.success("Configuración guardada.")

        st.divider()
        if st.button("Enviar correo de prueba"):
            with st.spinner("Enviando..."):
                from utils.emailer import send_whitelist_alert
                ok = send_whitelist_alert(get_local_ip(), "test:mac:ids", "IP_NO_AUTORIZADA")
            if ok:
                st.success(f"Correo de prueba enviado a {cfg.get('admin_email')}.")
            else:
                st.error("Error al enviar. Verifique la configuración SMTP.")

    with tab_motor:
        from core.scanner import detect_interface, get_local_ip as sc_ip

        local_ip   = sc_ip()
        iface_real = detect_interface()

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

    with tab_sec:
        st.markdown("**Cambiar contraseña de administrador**")
        with st.form("change_pwd_form"):
            old_pwd  = st.text_input("Contraseña actual",    type="password")
            new_pwd  = st.text_input("Nueva contraseña",     type="password")
            conf_pwd = st.text_input("Confirmar contraseña", type="password")
            if st.form_submit_button("Cambiar contraseña", type="primary"):
                if not verify_password(old_pwd):
                    st.error("La contraseña actual es incorrecta.")
                elif new_pwd != conf_pwd:
                    st.error("Las contraseñas nuevas no coinciden.")
                elif len(new_pwd) < 6:
                    st.error("La contraseña debe tener al menos 6 caracteres.")
                else:
                    change_password(new_pwd)
                    st.success("Contraseña actualizada.")

        st.divider()
        st.markdown("**Limpiar base de datos**")
        st.warning("Esta acción elimina todos los registros del IDS. Es irreversible.", icon="⚠️")
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
        page_icon="🛡",
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
