"""
IDS Corporativo — Aplicación de Escritorio
PyQt6 — ventana nativa, sin navegador, sin terminal.
Doble clic en "Lanzar IDS.command" para iniciar.
"""
import sys
import os
import json
import subprocess
import logging

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QStackedWidget, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QTextEdit, QComboBox, QSplitter, QScrollArea, QMessageBox,
    QDialog, QFormLayout, QAbstractItemView, QSlider, QSizePolicy,
    QSpacerItem, QGridLayout,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon

os.makedirs(os.path.join(ROOT, "data", "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(ROOT, "data", "logs", "ids.log"), encoding="utf-8"),
    ],
)

from utils import database as db
from utils.auth import verify_password, change_password
from core.sniffer import get_sniffer, reset_sniffer
from core.scanner import get_local_ip, detect_interface, get_default_network, scan_network

SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")

# ══════════════════════════════════════════════════════════════════
# PALETA Y ESTILOS
# ══════════════════════════════════════════════════════════════════

BLUE    = "#2563EB"
DANGER  = "#DC2626"
WARNING = "#D97706"
SUCCESS = "#16A34A"
TEXT    = "#1E293B"
MUTED   = "#64748B"
BG      = "#F8FAFC"
WHITE   = "#FFFFFF"
BORDER  = "#E2E8F0"

QSS = f"""
QMainWindow, QWidget#Root {{ background: {BG}; }}

/* ─── Sidebar ─────────────────────────────────────────── */
QWidget#Sidebar {{
    background: {WHITE};
    border-right: 1px solid {BORDER};
}}
QLabel#AppTitle {{
    font-size: 14px; font-weight: bold; color: {TEXT};
    padding: 4px 0px 0px 0px;
}}
QLabel#AppSub {{
    font-size: 11px; color: #94A3B8;
}}
QLabel#NavSection {{
    font-size: 10px; font-weight: bold; color: #94A3B8;
    letter-spacing: 2px; padding: 12px 0px 4px 16px;
}}
QPushButton#NavBtn {{
    background: transparent; border: none;
    text-align: left; padding: 9px 16px;
    font-size: 13px; color: {MUTED};
    border-radius: 6px; margin: 1px 8px;
}}
QPushButton#NavBtn:hover {{ background: #F1F5F9; color: {TEXT}; }}
QPushButton#NavBtn[active=true] {{
    background: #EFF6FF; color: {BLUE}; font-weight: bold;
}}

/* ─── Páginas ──────────────────────────────────────────── */
QLabel#PageTitle {{
    font-size: 20px; font-weight: bold; color: {TEXT};
    border-bottom: 2px solid {BLUE}; padding-bottom: 8px;
}}
QLabel#PageSub {{ font-size: 12px; color: {MUTED}; }}
QLabel#SectionTitle {{
    font-size: 12px; font-weight: bold; color: {TEXT}; padding-top: 6px;
}}
QLabel#InfoLabel {{ font-size: 12px; color: {MUTED}; min-width: 130px; }}
QLabel#InfoValue {{ font-size: 12px; color: {TEXT}; }}

/* ─── Tarjetas de métricas ────────────────────────────── */
QFrame#MetricCard {{
    background: {WHITE}; border: 1px solid {BORDER};
    border-radius: 8px; padding: 8px;
}}
QLabel#MVal  {{ font-size: 30px; font-weight: bold; color: {TEXT}; }}
QLabel#MValB {{ font-size: 30px; font-weight: bold; color: {BLUE}; }}
QLabel#MValW {{ font-size: 30px; font-weight: bold; color: {WARNING}; }}
QLabel#MValR {{ font-size: 30px; font-weight: bold; color: {DANGER}; }}
QLabel#MLbl  {{ font-size: 10px; color: {MUTED}; letter-spacing: 1px; }}

/* ─── Botones ─────────────────────────────────────────── */
QPushButton#Btn {{
    background: {BLUE}; color: white; border: none;
    border-radius: 6px; padding: 8px 16px; font-size: 13px; font-weight: bold;
}}
QPushButton#Btn:hover {{ background: #1D4ED8; }}
QPushButton#Btn:disabled {{ background: #CBD5E1; }}
QPushButton#BtnSec {{
    background: {WHITE}; color: {MUTED};
    border: 1px solid {BORDER}; border-radius: 6px;
    padding: 8px 16px; font-size: 13px;
}}
QPushButton#BtnSec:hover {{ background: {BG}; color: {TEXT}; }}
QPushButton#BtnDanger {{
    background: #FEF2F2; color: {DANGER};
    border: 1px solid #FECACA; border-radius: 6px;
    padding: 8px 16px; font-size: 13px;
}}

/* ─── Sniffer controls ────────────────────────────────── */
QPushButton#StartBtn {{
    background: {BLUE}; color: white; border: none;
    border-radius: 5px; padding: 7px 14px; font-size: 12px; font-weight: bold;
}}
QPushButton#StartBtn:hover {{ background: #1D4ED8; }}
QPushButton#StartBtn:disabled {{ background: #CBD5E1; }}
QPushButton#StopBtn {{
    background: {WHITE}; color: {MUTED};
    border: 1px solid {BORDER}; border-radius: 5px;
    padding: 7px 14px; font-size: 12px;
}}
QPushButton#StopBtn:hover {{ background: #FEF2F2; color: {DANGER}; border-color: #FECACA; }}
QPushButton#StopBtn:disabled {{ color: #CBD5E1; border-color: {BORDER}; }}

/* ─── Inputs ──────────────────────────────────────────── */
QLineEdit, QTextEdit {{
    background: {WHITE}; border: 1px solid {BORDER};
    border-radius: 6px; padding: 8px; font-size: 13px; color: {TEXT};
}}
QLineEdit:focus, QTextEdit:focus {{ border: 1px solid {BLUE}; }}
QComboBox {{
    background: {WHITE}; border: 1px solid {BORDER};
    border-radius: 6px; padding: 7px 10px; font-size: 13px; color: {TEXT};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}

/* ─── Tablas ──────────────────────────────────────────── */
QTableWidget {{
    background: {WHITE}; border: 1px solid {BORDER};
    border-radius: 6px; gridline-color: #F1F5F9;
    selection-background-color: #EFF6FF;
    selection-color: #1E40AF; font-size: 12px; color: #334155;
    outline: none;
}}
QTableWidget::item {{ padding: 6px 8px; border: none; }}
QTableWidget::item:alternate {{ background: {BG}; }}
QHeaderView::section {{
    background: {BG}; color: {MUTED}; font-size: 11px;
    font-weight: bold; padding: 8px; border: none;
    border-bottom: 1px solid {BORDER};
}}

/* ─── Tabs ────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {BORDER}; border-radius: 6px;
    background: {WHITE}; top: -1px;
}}
QTabBar::tab {{
    background: transparent; color: {MUTED};
    padding: 9px 18px; font-size: 13px;
    border: none; border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {BLUE}; border-bottom: 2px solid {BLUE}; font-weight: bold;
}}
QTabBar::tab:hover:!selected {{ color: {TEXT}; }}

/* ─── Scrollbar ───────────────────────────────────────── */
QScrollBar:vertical {{
    width: 7px; background: {BG}; border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: #CBD5E1; border-radius: 3px; min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

/* ─── Mensajes de alerta ──────────────────────────────── */
QFrame#AlertWarning {{
    background: #FFFBEB; border-left: 3px solid {WARNING};
    border-radius: 0px 6px 6px 0px; padding: 2px;
}}
QFrame#AlertDanger {{
    background: #FEF2F2; border-left: 3px solid {DANGER};
    border-radius: 0px 6px 6px 0px; padding: 2px;
}}
QFrame#AlertInfo {{
    background: #EFF6FF; border-left: 3px solid {BLUE};
    border-radius: 0px 6px 6px 0px; padding: 2px;
}}
QFrame#InfoBox {{
    background: {BG}; border: 1px solid {BORDER};
    border-radius: 8px;
}}
"""

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

ENV_PATH = os.path.join(ROOT, ".env")


def load_settings():
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_settings(data):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_env_credentials() -> dict:
    """Lee IDS_SMTP_USER e IDS_SMTP_PASSWORD del archivo .env."""
    creds = {"smtp_user": "", "smtp_password": ""}
    if not os.path.exists(ENV_PATH):
        return creds
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key.strip() == "IDS_SMTP_USER":
                creds["smtp_user"] = val.strip()
            elif key.strip() == "IDS_SMTP_PASSWORD":
                creds["smtp_password"] = val.strip()
    return creds


def save_env_credentials(smtp_user: str, smtp_password: str):
    """Escribe IDS_SMTP_USER e IDS_SMTP_PASSWORD en el archivo .env."""
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

    keys_written = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("IDS_SMTP_USER="):
            new_lines.append(f"IDS_SMTP_USER={smtp_user}\n")
            keys_written.add("IDS_SMTP_USER")
        elif stripped.startswith("IDS_SMTP_PASSWORD="):
            new_lines.append(f"IDS_SMTP_PASSWORD={smtp_password}\n")
            keys_written.add("IDS_SMTP_PASSWORD")
        else:
            new_lines.append(line)

    if "IDS_SMTP_USER" not in keys_written:
        new_lines.append(f"IDS_SMTP_USER={smtp_user}\n")
    if "IDS_SMTP_PASSWORD" not in keys_written:
        new_lines.append(f"IDS_SMTP_PASSWORD={smtp_password}\n")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

def check_bpf():
    """Verifica si el proceso puede leer Y escribir en los dispositivos BPF de macOS."""
    if sys.platform != "darwin":
        return os.geteuid() == 0
    return os.access("/dev/bpf0", os.R_OK | os.W_OK)

def fill_table(table: QTableWidget, rows: list[tuple]):
    table.setRowCount(0)
    for r, row in enumerate(rows):
        table.insertRow(r)
        for c, val in enumerate(row):
            item = QTableWidgetItem(str(val) if val is not None else "—")
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            table.setItem(r, c, item)

def make_table(columns: dict) -> QTableWidget:
    t = QTableWidget()
    t.setColumnCount(len(columns))
    t.setHorizontalHeaderLabels(list(columns.keys()))
    t.horizontalHeader().setStretchLastSection(True)
    for i, w in enumerate(columns.values()):
        if w:
            t.setColumnWidth(i, w)
        else:
            t.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setShowGrid(False)
    t.setSortingEnabled(False)
    return t

def metric_card(label: str, obj_id: str = "MVal") -> tuple:
    """Returns (QFrame, val_label). Call val_label.setText() to update."""
    frame = QFrame()
    frame.setObjectName("MetricCard")
    frame.setMinimumHeight(90)
    lay = QVBoxLayout(frame)
    lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
    val = QLabel("0")
    val.setObjectName(obj_id)
    val.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl = QLabel(label.upper())
    lbl.setObjectName("MLbl")
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lay.addWidget(val)
    lay.addWidget(lbl)
    return frame, val

def hr():
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color: {BORDER};")
    return line

# ══════════════════════════════════════════════════════════════════
# DIÁLOGO BPF (macOS — permisos de red)
# ══════════════════════════════════════════════════════════════════

class BFPDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Permisos de red requeridos")
        self.setFixedSize(400, 200)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 24, 28, 24)
        lay.setSpacing(14)

        title = QLabel("Acceso a la interfaz de red")
        title.setStyleSheet(f"font-size:15px;font-weight:bold;color:{TEXT};")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        msg = QLabel(
            "El IDS necesita permiso para leer paquetes de red.\n"
            "Se mostrará el diálogo de contraseña de macOS."
        )
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg.setStyleSheet(f"font-size:13px;color:{MUTED};")
        msg.setWordWrap(True)

        btn_row = QHBoxLayout()
        skip = QPushButton("Omitir")
        skip.setObjectName("BtnSec")
        skip.clicked.connect(self.reject)
        auth = QPushButton("Autorizar acceso")
        auth.setObjectName("Btn")
        auth.clicked.connect(self._fix)
        btn_row.addWidget(skip)
        btn_row.addWidget(auth)

        lay.addWidget(title)
        lay.addWidget(msg)
        lay.addLayout(btn_row)

    def _fix(self):
        res = subprocess.run(
            ["osascript", "-e",
             'do shell script "chmod o+rw /dev/bpf*" with administrator privileges'],
            capture_output=True,
        )
        if res.returncode == 0:
            QMessageBox.information(self, "Listo", "Permisos configurados correctamente.")
            self.accept()
        else:
            QMessageBox.warning(self, "Cancelado",
                "Sin permisos. La captura de paquetes no estará disponible hasta autorizarlo.")
            self.reject()


# ══════════════════════════════════════════════════════════════════
# HILO DE ESCANEO ARP (no bloquear la UI)
# ══════════════════════════════════════════════════════════════════

class ScanThread(QThread):
    result = pyqtSignal(list)
    error  = pyqtSignal(str)

    def __init__(self, network):
        super().__init__()
        self.network = network

    def run(self):
        try:
            devices = scan_network(self.network)
            self.result.emit(devices)
        except Exception as e:
            self.error.emit(str(e))


# ══════════════════════════════════════════════════════════════════
# PÁGINAS
# ══════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    def __init__(self, sidebar_ref):
        super().__init__()
        self.sidebar = sidebar_ref
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)

        lbl = QLabel("Dashboard")
        lbl.setObjectName("PageTitle")
        sub = QLabel("Estado de seguridad de la red en tiempo real")
        sub.setObjectName("PageSub")
        root.addWidget(lbl)
        root.addWidget(sub)

        # Info box
        self.info_box = QFrame()
        self.info_box.setObjectName("InfoBox")
        ib_lay = QGridLayout(self.info_box)
        ib_lay.setContentsMargins(16, 12, 16, 12)
        ib_lay.setSpacing(6)
        self._ib_labels = {}
        rows = [("IP local", "ip"), ("Interfaz activa", "iface"),
                ("Motor IDS", "motor"), ("Email alertas", "email")]
        for i, (ltext, key) in enumerate(rows):
            l = QLabel(ltext)
            l.setObjectName("InfoLabel")
            v = QLabel("—")
            v.setObjectName("InfoValue")
            ib_lay.addWidget(l, i, 0)
            ib_lay.addWidget(v, i, 1)
            self._ib_labels[key] = v
        root.addWidget(self.info_box)

        # Métricas
        grid = QHBoxLayout()
        grid.setSpacing(12)
        self._mc_wl,   self._wl_v  = metric_card("Alertas Lista Blanca", "MValW")
        self._mc_dom,  self._dom_v = metric_card("Dominios Registrados",  "MValB")
        self._mc_thr,  self._thr_v = metric_card("Alertas de Amenaza",    "MValR")
        self._mc_for,  self._for_v = metric_card("Informes Forenses",     "MVal")
        for card in (self._mc_wl, self._mc_dom, self._mc_thr, self._mc_for):
            grid.addWidget(card)
        root.addLayout(grid)

        # Dos columnas — últimas alertas
        cols = QHBoxLayout()
        cols.setSpacing(16)

        left = QVBoxLayout()
        left.addWidget(QLabel("Últimas alertas — Lista Blanca"))
        self.tbl_wl = make_table({"Timestamp": 140, "IP": 120, "Tipo": 0})
        self.tbl_wl.setMaximumHeight(220)
        left.addWidget(self.tbl_wl)

        right = QVBoxLayout()
        right.addWidget(QLabel("Últimas amenazas detectadas"))
        self.tbl_thr = make_table({"Timestamp": 140, "IP Maliciosa": 130, "Tipo": 0, "Riesgo": 80})
        self.tbl_thr.setMaximumHeight(220)
        right.addWidget(self.tbl_thr)

        cols.addLayout(left)
        cols.addLayout(right)
        root.addLayout(cols)

        root.addWidget(QLabel("Top dominios visitados"))
        self.tbl_top = make_table({"Dominio": 0, "Visitas": 80, "Última vez": 140})
        root.addWidget(self.tbl_top)
        root.addStretch()

    def refresh(self):
        stats = db.get_stats()
        self._wl_v.setText(str(stats["whitelist_alerts"]))
        self._dom_v.setText(str(stats["site_visits"]))
        self._thr_v.setText(str(stats["threat_alerts"]))
        self._for_v.setText(str(stats["forensic_reports"]))

        cfg = load_settings()
        sniffer = get_sniffer()
        self._ib_labels["ip"].setText(get_local_ip())
        self._ib_labels["iface"].setText(detect_interface() or "auto")
        self._ib_labels["motor"].setText("Activo" if sniffer.is_running else "Inactivo")
        self._ib_labels["motor"].setStyleSheet(
            f"color:{SUCCESS};font-weight:bold;" if sniffer.is_running
            else f"color:{MUTED};"
        )
        self._ib_labels["email"].setText(cfg.get("admin_email") or "No configurado")

        fill_table(self.tbl_wl, [
            (a["timestamp"], a["src_ip"], a["alert_type"].replace("_", " "))
            for a in db.fetch_whitelist_alerts(limit=6)
        ])
        fill_table(self.tbl_thr, [
            (t["timestamp"], t["dst_ip"], t["threat_type"], t["risk_level"])
            for t in db.fetch_threat_alerts(limit=6)
        ])
        fill_table(self.tbl_top, [
            (r["domain"], r["visits"], r["last_seen"])
            for r in db.fetch_top_domains(limit=10)
        ])


class WhitelistPage(QWidget):
    def __init__(self):
        super().__init__()
        self._scan_thread = None
        self._scanned = []
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)

        root.addWidget(_page_header("Módulo 1: Lista Blanca",
            "Capa 2 (MAC) y Capa 3 (IP) — dispositivos autorizados en la red"))

        tabs = QTabWidget()

        # Tab 1: Alertas
        t1 = QWidget()
        l1 = QVBoxLayout(t1)
        l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_alerts = make_table({
            "Timestamp": 140, "IP Origen": 120, "MAC Origen": 140,
            "Tipo": 160, "Email": 70,
        })
        l1.addWidget(self.tbl_alerts)
        tabs.addTab(t1, "Alertas en tiempo real")

        # Tab 2: Gestionar
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        l2.setContentsMargins(12, 12, 12, 12)
        l2.setSpacing(10)
        row2 = QHBoxLayout()
        lv2 = QVBoxLayout()
        lv2.addWidget(QLabel("IPs autorizadas (una por línea)"))
        self.txt_ips = QTextEdit()
        lv2.addWidget(self.txt_ips)
        rv2 = QVBoxLayout()
        rv2.addWidget(QLabel("MACs autorizadas (aa:bb:cc:dd:ee:ff)"))
        self.txt_macs = QTextEdit()
        rv2.addWidget(self.txt_macs)
        row2.addLayout(lv2)
        row2.addLayout(rv2)
        l2.addLayout(row2)
        save_btn = QPushButton("Guardar lista blanca")
        save_btn.setObjectName("Btn")
        save_btn.clicked.connect(self._save_whitelist)
        l2.addWidget(save_btn)
        tabs.addTab(t2, "Gestionar lista blanca")

        # Tab 3: Escanear
        t3 = QWidget()
        l3 = QVBoxLayout(t3)
        l3.setContentsMargins(12, 12, 12, 12)
        l3.setSpacing(10)
        row3 = QHBoxLayout()
        self.scan_net = QLineEdit(get_default_network())
        self.scan_btn = QPushButton("Escanear red local")
        self.scan_btn.setObjectName("Btn")
        self.scan_btn.clicked.connect(self._start_scan)
        row3.addWidget(QLabel("Red (CIDR):"))
        row3.addWidget(self.scan_net)
        row3.addWidget(self.scan_btn)
        l3.addLayout(row3)
        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet(f"color:{MUTED};font-size:12px;")
        l3.addWidget(self.scan_status)
        self.tbl_scan = make_table({"IP": 130, "MAC": 150, "Hostname": 0})
        l3.addWidget(self.tbl_scan)
        self.add_sel_btn = QPushButton("Agregar seleccionados a lista blanca")
        self.add_sel_btn.setObjectName("Btn")
        self.add_sel_btn.setEnabled(False)
        self.add_sel_btn.clicked.connect(self._add_selected)
        l3.addWidget(self.add_sel_btn)
        tabs.addTab(t3, "Escanear red local")

        root.addWidget(tabs)
        self._load_whitelist()

    def _load_whitelist(self):
        wl_path = os.path.join(ROOT, "config", "whitelist.json")
        with open(wl_path) as f:
            d = json.load(f)
        self.txt_ips.setPlainText("\n".join(d.get("authorized_ips", [])))
        self.txt_macs.setPlainText("\n".join(d.get("authorized_macs", [])))

    def _save_whitelist(self):
        ips  = [l.strip() for l in self.txt_ips.toPlainText().splitlines() if l.strip()]
        macs = [l.strip().lower() for l in self.txt_macs.toPlainText().splitlines() if l.strip()]
        from core.whitelist import WhitelistChecker
        WhitelistChecker().save(ips, macs)
        get_sniffer().whitelist.reload()
        QMessageBox.information(self, "Guardado", f"{len(ips)} IPs y {len(macs)} MACs guardadas.")

    def _start_scan(self):
        if not check_bpf():
            QMessageBox.warning(self, "Sin permisos",
                "Se necesitan permisos de red para el escaneo ARP.\n"
                "Usa el botón de autorizar al inicio de la app.")
            return
        self.scan_btn.setEnabled(False)
        self.scan_status.setText("Escaneando... (puede tardar hasta 5 segundos)")
        self._scan_thread = ScanThread(self.scan_net.text())
        self._scan_thread.result.connect(self._on_scan_done)
        self._scan_thread.error.connect(self._on_scan_error)
        self._scan_thread.start()

    def _on_scan_done(self, devices):
        self._scanned = devices
        self.scan_btn.setEnabled(True)
        self.scan_status.setText(f"{len(devices)} dispositivos encontrados.")
        fill_table(self.tbl_scan, [(d["ip"], d["mac"], d["hostname"]) for d in devices])
        self.tbl_scan.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.add_sel_btn.setEnabled(bool(devices))

    def _on_scan_error(self, msg):
        self.scan_btn.setEnabled(True)
        self.scan_status.setText(f"Error: {msg}")

    def _add_selected(self):
        rows = {idx.row() for idx in self.tbl_scan.selectedIndexes()}
        if not rows:
            QMessageBox.information(self, "Selección vacía", "Selecciona al menos un dispositivo.")
            return
        wl_path = os.path.join(ROOT, "config", "whitelist.json")
        with open(wl_path) as f:
            d = json.load(f)
        existing_ips  = set(d.get("authorized_ips", []))
        existing_macs = set(d.get("authorized_macs", []))
        added = 0
        for r in rows:
            dev = self._scanned[r]
            if dev["ip"] not in existing_ips:
                existing_ips.add(dev["ip"])
                added += 1
            existing_macs.add(dev["mac"])
        from core.whitelist import WhitelistChecker
        WhitelistChecker().save(list(existing_ips), list(existing_macs))
        get_sniffer().whitelist.reload()
        self._load_whitelist()
        self.tbl_scan.clearSelection()
        QMessageBox.information(self, "Agregados", f"{added} dispositivos nuevos agregados.")

    def refresh(self):
        fill_table(self.tbl_alerts, [
            (a["timestamp"], a["src_ip"], a["src_mac"] or "—",
             a["alert_type"].replace("_", " "), "Sí" if a["email_sent"] else "No")
            for a in db.fetch_whitelist_alerts(limit=80)
        ])


class MonitorPage(QWidget):
    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)
        root.addWidget(_page_header("Módulo 2: Monitoreo de Sitios",
            "Bitácora en tiempo real de dominios visitados — DNS / HTTP / HTTPS"))

        tabs = QTabWidget()
        t1 = QWidget()
        l1 = QVBoxLayout(t1)
        l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_log = make_table({"Timestamp": 140, "IP Origen": 120, "Dominio": 0, "Protocolo": 80})
        l1.addWidget(self.tbl_log)
        tabs.addTab(t1, "Bitácora en tiempo real")

        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        l2.setContentsMargins(12, 12, 12, 12)
        self.tbl_top = make_table({"Dominio": 0, "Visitas": 90, "Última vez": 140})
        l2.addWidget(self.tbl_top)
        tabs.addTab(t2, "Top dominios")

        root.addWidget(tabs)

    def refresh(self):
        fill_table(self.tbl_log, [
            (v["timestamp"], v["src_ip"], v["domain"], v["protocol"])
            for v in db.fetch_site_visits(limit=150)
        ])
        fill_table(self.tbl_top, [
            (r["domain"], r["visits"], r["last_seen"])
            for r in db.fetch_top_domains(limit=25)
        ])


class ThreatPage(QWidget):
    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)
        root.addWidget(_page_header("Módulo 3: Inteligencia de Amenazas",
            "Detección de conexiones hacia IPs maliciosas conocidas"))

        tabs = QTabWidget()

        # Tab 1: Alertas
        t1 = QWidget()
        l1 = QVBoxLayout(t1)
        l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_alerts = make_table({
            "Timestamp": 140, "IP Origen": 110, "IP Maliciosa": 120,
            "Tipo": 130, "Riesgo": 80, "Email": 60, "WHOIS": 90,
        })
        l1.addWidget(self.tbl_alerts)
        tabs.addTab(t1, "Alertas de amenaza")

        # Tab 2: Lista negra
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        l2.setContentsMargins(12, 12, 12, 12)
        l2.setSpacing(10)
        self.tbl_bl = make_table({"IP": 120, "Tipo": 140, "Riesgo": 80, "Descripción": 0, "Fuente": 120})
        l2.addWidget(self.tbl_bl)
        l2.addWidget(hr())
        l2.addWidget(QLabel("Agregar IP manualmente"))
        form = QHBoxLayout()
        self.bl_ip   = QLineEdit(); self.bl_ip.setPlaceholderText("1.2.3.4")
        self.bl_type = QComboBox()
        self.bl_type.addItems(["Botnet C2","Malware Distributor","Phishing",
                                "Cryptominer","APT Infrastructure","Spyware C2","Exploit Kit","Otro"])
        self.bl_risk = QComboBox()
        self.bl_risk.addItems(["Critico","Alto","Medio"])
        self.bl_desc = QLineEdit(); self.bl_desc.setPlaceholderText("Descripción")
        self.bl_src  = QLineEdit(); self.bl_src.setPlaceholderText("Fuente / URL")
        add_btn = QPushButton("Agregar")
        add_btn.setObjectName("Btn")
        add_btn.clicked.connect(self._add_ip)
        for w in (self.bl_ip, self.bl_type, self.bl_risk, self.bl_desc, self.bl_src, add_btn):
            form.addWidget(w)
        l2.addLayout(form)
        tabs.addTab(t2, "Lista negra activa")

        # Tab 3: Importar feed
        t3 = QWidget()
        l3 = QVBoxLayout(t3)
        l3.setContentsMargins(12, 12, 12, 12)
        l3.setSpacing(10)
        l3.addWidget(QLabel("URL del feed (una IP por línea, # para comentarios):"))
        self.feed_url  = QLineEdit(); self.feed_url.setPlaceholderText("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        self.feed_type = QComboBox(); self.feed_type.addItems(["Botnet C2","Malware Distributor","Phishing","Multiple / Otro"])
        self.feed_risk = QComboBox(); self.feed_risk.addItems(["Critico","Alto","Medio"])
        self.feed_status = QLabel("")
        self.feed_status.setStyleSheet(f"color:{MUTED};font-size:12px;")
        import_btn = QPushButton("Importar desde URL")
        import_btn.setObjectName("Btn")
        import_btn.clicked.connect(self._import_feed)
        frow = QHBoxLayout()
        frow.addWidget(QLabel("Tipo:")); frow.addWidget(self.feed_type)
        frow.addWidget(QLabel("Riesgo:")); frow.addWidget(self.feed_risk)
        l3.addWidget(self.feed_url)
        l3.addLayout(frow)
        l3.addWidget(import_btn)
        l3.addWidget(self.feed_status)
        l3.addStretch()
        tabs.addTab(t3, "Importar threat feed")

        root.addWidget(tabs)
        self._load_blacklist()

    def _load_blacklist(self):
        bl_path = os.path.join(ROOT, "config", "blacklist.json")
        with open(bl_path) as f:
            d = json.load(f)
        entries = d.get("dangerous_ips", [])
        fill_table(self.tbl_bl, [
            (e["ip"], e.get("threat_type",""), e.get("risk_level",""),
             e.get("description",""), e.get("source",""))
            for e in entries
        ])

    def _add_ip(self):
        ip = self.bl_ip.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Ingresa una dirección IP."); return
        import socket
        try: socket.inet_aton(ip)
        except socket.error:
            QMessageBox.warning(self, "Error", "La IP no tiene formato válido."); return
        from datetime import date
        bl_path = os.path.join(ROOT, "config", "blacklist.json")
        with open(bl_path) as f: d = json.load(f)
        entries = d.get("dangerous_ips", [])
        entries.append({"ip": ip, "threat_type": self.bl_type.currentText(),
                        "risk_level": self.bl_risk.currentText(),
                        "description": self.bl_desc.text(),
                        "source": self.bl_src.text() or "Manual",
                        "reported": str(date.today())})
        d["dangerous_ips"] = entries
        with open(bl_path, "w") as f: json.dump(d, f, indent=2)
        get_sniffer().threat.reload()
        self._load_blacklist()
        self.bl_ip.clear(); self.bl_desc.clear()
        QMessageBox.information(self, "Agregada", f"IP {ip} añadida a la lista negra.")

    def _import_feed(self):
        url = self.feed_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Ingresa una URL."); return
        self.feed_status.setText("Descargando feed...")
        QApplication.processEvents()
        try:
            import requests, socket
            from datetime import date
            resp = requests.get(url, timeout=20); resp.raise_for_status()
            bl_path = os.path.join(ROOT, "config", "blacklist.json")
            with open(bl_path) as f: d = json.load(f)
            entries = d.get("dangerous_ips", [])
            existing = {e["ip"] for e in entries}
            added = 0
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"): continue
                ip = line.split()[0].split(",")[0].strip()
                try:
                    socket.inet_aton(ip)
                except socket.error:
                    continue
                if ip not in existing:
                    entries.append({"ip": ip,
                        "threat_type": self.feed_type.currentText(),
                        "risk_level":  self.feed_risk.currentText(),
                        "description": f"Importado de: {url}",
                        "source": url, "reported": str(date.today())})
                    existing.add(ip); added += 1
            d["dangerous_ips"] = entries
            with open(bl_path, "w") as f: json.dump(d, f, indent=2)
            get_sniffer().threat.reload()
            self._load_blacklist()
            self.feed_status.setText(f"{added} IPs importadas. Total: {len(entries)}")
        except Exception as e:
            self.feed_status.setText(f"Error: {e}")

    def refresh(self):
        fill_table(self.tbl_alerts, [
            (t["timestamp"], t["src_ip"] or "—", t["dst_ip"],
             t["threat_type"], t["risk_level"],
             "Sí" if t["email_sent"] else "No",
             "Completado" if t["whois_done"] else "Pendiente")
            for t in db.fetch_threat_alerts(limit=80)
        ])


class ForensicsPage(QWidget):
    def __init__(self):
        super().__init__()
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)
        root.addWidget(_page_header("Módulo 4: Informes Forenses",
            "WHOIS automatizado — contacto de abuso del proveedor de la IP maliciosa"))

        tabs = QTabWidget()

        # Tab 1: Automáticos
        t1 = QWidget()
        l1 = QVBoxLayout(t1)
        l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_reports = make_table({
            "Timestamp": 140, "IP": 120, "Organización": 0,
            "País": 60, "ASN": 90, "Contacto Abuso": 180, "Email": 60,
        })
        self.tbl_reports.clicked.connect(self._show_detail)
        l1.addWidget(self.tbl_reports)
        l1.addWidget(QLabel("Datos WHOIS completos (selecciona una fila):"))
        self.whois_detail = QTextEdit()
        self.whois_detail.setReadOnly(True)
        self.whois_detail.setMaximumHeight(160)
        self.whois_detail.setStyleSheet(
            f"font-family:monospace;font-size:11px;background:{BG};border:1px solid {BORDER};")
        l1.addWidget(self.whois_detail)
        tabs.addTab(t1, "Informes automáticos")

        # Tab 2: Consulta manual
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        l2.setContentsMargins(12, 12, 12, 12)
        l2.setSpacing(10)
        l2.addWidget(QLabel("Consulta WHOIS para cualquier dirección IP:"))
        row = QHBoxLayout()
        self.manual_ip = QLineEdit(); self.manual_ip.setPlaceholderText("8.8.8.8")
        q_btn = QPushButton("Ejecutar WHOIS")
        q_btn.setObjectName("Btn")
        q_btn.clicked.connect(self._manual_whois)
        row.addWidget(self.manual_ip); row.addWidget(q_btn)
        l2.addLayout(row)
        self.manual_result = QTextEdit()
        self.manual_result.setReadOnly(True)
        self.manual_result.setStyleSheet(
            f"font-family:monospace;font-size:12px;background:{BG};border:1px solid {BORDER};")
        l2.addWidget(self.manual_result)
        tabs.addTab(t2, "Consulta manual")

        root.addWidget(tabs)
        self._reports_cache = []

    def _show_detail(self, idx):
        row = idx.row()
        if row < len(self._reports_cache):
            raw = self._reports_cache[row].get("raw_data", "")
            self.whois_detail.setPlainText(raw or "Sin datos disponibles.")

    def _manual_whois(self):
        ip = self.manual_ip.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Ingresa una IP."); return
        self.manual_result.setPlainText("Consultando WHOIS...")
        QApplication.processEvents()
        from core.forensics import ForensicsEngine
        result = ForensicsEngine().investigate(ip, "Consulta manual")
        if result:
            self.manual_result.setPlainText(
                f"Organización : {result.get('org','N/D')}\n"
                f"ASN          : {result.get('asn','N/D')}\n"
                f"País         : {result.get('country','N/D')}\n"
                f"Abuso email  : {result.get('abuse_email','No encontrado')}\n"
                f"Abuso tel    : {result.get('abuse_phone','N/D')}\n\n"
                f"--- WHOIS completo ---\n{result.get('raw','')}"
            )
        else:
            self.manual_result.setPlainText("Sin resultados. La IP puede ser privada o inaccesible.")

    def refresh(self):
        self._reports_cache = db.fetch_forensic_reports(limit=50)
        fill_table(self.tbl_reports, [
            (r["timestamp"], r["ip"], r["org"] or "—", r["country"] or "—",
             r["asn"] or "—", r["abuse_email"] or "—",
             "Sí" if r["email_sent"] else "No")
            for r in self._reports_cache
        ])


class SettingsPage(QWidget):
    def __init__(self):
        super().__init__()
        self._authenticated = False
        self._build()

    def _build(self):
        self._stack = QStackedWidget(self)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self._stack)
        self._stack.addWidget(self._login_page())
        self._stack.addWidget(self._settings_content())

    def _login_page(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(12)
        title = QLabel("Área restringida")
        title.setStyleSheet(f"font-size:18px;font-weight:bold;color:{TEXT};")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub = QLabel("Esta sección requiere autenticación de administrador.")
        sub.setStyleSheet(f"font-size:13px;color:{MUTED};")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_input.setPlaceholderText("Contraseña de administrador")
        self.pwd_input.setMaximumWidth(300)
        self.pwd_input.returnPressed.connect(self._login)
        login_btn = QPushButton("Iniciar sesión")
        login_btn.setObjectName("Btn")
        login_btn.setMaximumWidth(300)
        login_btn.clicked.connect(self._login)
        hint = QLabel("Contraseña por defecto: admin123")
        hint.setStyleSheet(f"font-size:11px;color:#94A3B8;")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for w_ in (title, sub, self.pwd_input, login_btn, hint):
            lay.addWidget(w_, alignment=Qt.AlignmentFlag.AlignHCenter)
        return w

    def _settings_content(self):
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)
        root.addWidget(_page_header("Configuración", "Ajustes del sistema — sesión de administrador activa"))

        logout_btn = QPushButton("Cerrar sesión")
        logout_btn.setObjectName("BtnSec")
        logout_btn.setMaximumWidth(130)
        logout_btn.clicked.connect(self._logout)
        root.addWidget(logout_btn)

        tabs = QTabWidget()

        # Tab 1: Notificaciones
        t1 = QWidget()
        f1 = QFormLayout(t1)
        f1.setContentsMargins(16, 16, 16, 16)
        f1.setSpacing(12)
        self.s_admin_email = QLineEdit()
        self.s_smtp_server = QLineEdit()
        self.s_smtp_port   = QLineEdit()
        self.s_smtp_user   = QLineEdit()
        self.s_smtp_pass   = QLineEdit(); self.s_smtp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        f1.addRow("Email del administrador:", self.s_admin_email)
        f1.addRow("Servidor SMTP:", self.s_smtp_server)
        f1.addRow("Puerto SMTP:", self.s_smtp_port)
        f1.addRow("Usuario SMTP:", self.s_smtp_user)
        f1.addRow("App Password / Contraseña:", self.s_smtp_pass)
        save_n = QPushButton("Guardar notificaciones")
        save_n.setObjectName("Btn")
        save_n.clicked.connect(self._save_notif)
        test_btn = QPushButton("Enviar correo de prueba")
        test_btn.setObjectName("BtnSec")
        test_btn.clicked.connect(self._send_test)
        brow = QHBoxLayout()
        brow.addWidget(save_n); brow.addWidget(test_btn)
        f1.addRow(brow)
        tabs.addTab(t1, "Notificaciones")

        # Tab 2: Motor IDS
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        l2.setContentsMargins(16, 16, 16, 16)
        l2.setSpacing(12)
        self.info_ip    = QLabel("—"); self.info_ip.setObjectName("InfoValue")
        self.info_iface = QLabel("—"); self.info_iface.setObjectName("InfoValue")
        ib = QFrame(); ib.setObjectName("InfoBox")
        ib_lay = QGridLayout(ib)
        ib_lay.setContentsMargins(12,10,12,10)
        ib_lay.addWidget(QLabel("IP local detectada:"), 0, 0)
        ib_lay.addWidget(self.info_ip, 0, 1)
        ib_lay.addWidget(QLabel("Interfaz detectada:"), 1, 0)
        ib_lay.addWidget(self.info_iface, 1, 1)
        l2.addWidget(ib)
        irow = QHBoxLayout()
        self.s_iface = QLineEdit(); self.s_iface.setPlaceholderText("dejar vacío para auto-detect")
        auto_btn = QPushButton("Auto-detectar")
        auto_btn.setObjectName("BtnSec")
        auto_btn.clicked.connect(self._auto_iface)
        irow.addWidget(QLabel("Interfaz de red:")); irow.addWidget(self.s_iface); irow.addWidget(auto_btn)
        l2.addLayout(irow)
        save_m = QPushButton("Guardar y reiniciar motor")
        save_m.setObjectName("Btn")
        save_m.clicked.connect(self._save_motor)
        l2.addWidget(save_m)
        l2.addStretch()
        tabs.addTab(t2, "Motor IDS")

        # Tab 3: Seguridad
        t3 = QWidget()
        f3 = QFormLayout(t3)
        f3.setContentsMargins(16, 16, 16, 16)
        f3.setSpacing(12)
        self.s_old_pwd  = QLineEdit(); self.s_old_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.s_new_pwd  = QLineEdit(); self.s_new_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.s_conf_pwd = QLineEdit(); self.s_conf_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        f3.addRow("Contraseña actual:", self.s_old_pwd)
        f3.addRow("Nueva contraseña:", self.s_new_pwd)
        f3.addRow("Confirmar:", self.s_conf_pwd)
        chg_btn = QPushButton("Cambiar contraseña")
        chg_btn.setObjectName("Btn")
        chg_btn.clicked.connect(self._change_pwd)
        f3.addRow(chg_btn)
        f3.addRow(hr())
        clr_btn = QPushButton("Eliminar todos los registros de la base de datos")
        clr_btn.setObjectName("BtnDanger")
        clr_btn.clicked.connect(self._clear_db)
        f3.addRow(clr_btn)
        tabs.addTab(t3, "Seguridad")

        root.addWidget(tabs)
        return w

    def _login(self):
        if verify_password(self.pwd_input.text()):
            self._authenticated = True
            self._load_settings_values()
            self._stack.setCurrentIndex(1)
            self.pwd_input.clear()
        else:
            QMessageBox.warning(self, "Error", "Contraseña incorrecta.")

    def _logout(self):
        self._authenticated = False
        self._stack.setCurrentIndex(0)

    def _load_settings_values(self):
        cfg   = load_settings()
        creds = load_env_credentials()
        self.s_admin_email.setText(cfg.get("admin_email",""))
        self.s_smtp_server.setText(cfg.get("smtp_server","smtp.gmail.com"))
        self.s_smtp_port.setText(str(cfg.get("smtp_port", 587)))
        # Credenciales desde .env (nunca desde settings.json)
        self.s_smtp_user.setText(creds["smtp_user"])
        self.s_smtp_pass.setText(creds["smtp_password"])
        self.s_iface.setText(cfg.get("network_interface") or "")
        self.info_ip.setText(get_local_ip())
        self.info_iface.setText(detect_interface() or "N/D")

    def _save_notif(self):
        cfg = load_settings()
        # Datos no sensibles → settings.json
        cfg.update({"admin_email": self.s_admin_email.text(),
                     "smtp_server": self.s_smtp_server.text(),
                     "smtp_port":   int(self.s_smtp_port.text() or 587)})
        # Limpiar credenciales de settings.json si quedaron de versiones anteriores
        cfg.pop("smtp_user", None)
        cfg.pop("smtp_password", None)
        save_settings(cfg)
        # Credenciales sensibles → .env
        save_env_credentials(self.s_smtp_user.text(), self.s_smtp_pass.text())
        QMessageBox.information(self, "Guardado",
            "Configuración guardada.\nCredenciales almacenadas en .env (protegidas).")

    def _send_test(self):
        from utils.emailer import send_whitelist_alert
        ok = send_whitelist_alert(get_local_ip(), "test:mac:ids", "IP_NO_AUTORIZADA")
        cfg = load_settings()
        if ok:
            QMessageBox.information(self, "Enviado", f"Correo de prueba enviado a {cfg.get('admin_email')}.")
        else:
            QMessageBox.warning(self, "Error", "No se pudo enviar. Verifica la configuración SMTP.")

    def _auto_iface(self):
        iface = detect_interface() or ""
        self.s_iface.setText(iface)

    def _save_motor(self):
        cfg = load_settings()
        cfg["network_interface"] = self.s_iface.text().strip() or None
        save_settings(cfg)
        reset_sniffer()
        QMessageBox.information(self, "Motor reiniciado",
            "Configuración guardada. Inicia el sniffer desde el panel lateral.")

    def _change_pwd(self):
        if not verify_password(self.s_old_pwd.text()):
            QMessageBox.warning(self, "Error", "La contraseña actual es incorrecta."); return
        if self.s_new_pwd.text() != self.s_conf_pwd.text():
            QMessageBox.warning(self, "Error", "Las contraseñas nuevas no coinciden."); return
        if len(self.s_new_pwd.text()) < 6:
            QMessageBox.warning(self, "Error", "Mínimo 6 caracteres."); return
        change_password(self.s_new_pwd.text())
        self.s_old_pwd.clear(); self.s_new_pwd.clear(); self.s_conf_pwd.clear()
        QMessageBox.information(self, "Listo", "Contraseña actualizada.")

    def _clear_db(self):
        reply = QMessageBox.question(self, "Confirmar",
            "¿Eliminar TODOS los registros? Esta acción es irreversible.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            import sqlite3
            conn = sqlite3.connect(os.path.join(ROOT, "data", "ids.db"))
            for t in ["whitelist_alerts","site_visits","threat_alerts","forensic_reports"]:
                conn.execute(f"DELETE FROM {t}")
            conn.commit(); conn.close()
            QMessageBox.information(self, "Listo", "Base de datos vaciada.")

    def refresh(self):
        pass


# ══════════════════════════════════════════════════════════════════
# VENTANA PRINCIPAL
# ══════════════════════════════════════════════════════════════════

def _page_header(title, subtitle=""):
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(2)
    t = QLabel(title); t.setObjectName("PageTitle")
    lay.addWidget(t)
    if subtitle:
        s = QLabel(subtitle); s.setObjectName("PageSub")
        lay.addWidget(s)
    return w


class IDSApp(QMainWindow):
    def __init__(self):
        super().__init__()
        db.init_db()
        self.setWindowTitle("IDS Corporativo")
        self.resize(1100, 720)
        self.setMinimumSize(900, 600)
        self._pages = []
        self._nav_buttons = []
        self._build_ui()
        self._setup_refresh()
        QTimer.singleShot(400, self._startup_check)

    # ── UI ────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget(); central.setObjectName("Root")
        self.setCentralWidget(central)
        main = QHBoxLayout(central)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        main.addWidget(self._build_sidebar())
        main.addWidget(self._build_content(), stretch=1)

    def _build_sidebar(self):
        sidebar = QWidget(); sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(210)
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(0, 20, 0, 20)
        lay.setSpacing(2)

        # Logo
        logo_row = QWidget()
        lr = QVBoxLayout(logo_row)
        lr.setContentsMargins(16, 0, 16, 0)
        t = QLabel("IDS Corporativo"); t.setObjectName("AppTitle")
        s = QLabel("Sistema de Detección de Intrusos"); s.setObjectName("AppSub")
        s.setWordWrap(True)
        lr.addWidget(t); lr.addWidget(s)
        lay.addWidget(logo_row)

        # Aviso de BPF
        self.bpf_warning = QLabel("")
        self.bpf_warning.setWordWrap(True)
        self.bpf_warning.setStyleSheet(
            f"font-size:11px;color:{WARNING};padding:6px 16px;"
            f"background:#FFFBEB;border-left:3px solid {WARNING};margin:6px 0;")
        self.bpf_warning.hide()
        lay.addWidget(self.bpf_warning)

        lay.addWidget(self._separator())

        # Navegación
        n = QLabel("NAVEGACIÓN"); n.setObjectName("NavSection")
        lay.addWidget(n)

        nav_items = [
            ("Dashboard",              DashboardPage),
            ("Módulo 1: Lista Blanca", WhitelistPage),
            ("Módulo 2: Sitios",       MonitorPage),
            ("Módulo 3: Amenazas",     ThreatPage),
            ("Módulo 4: Forense",      ForensicsPage),
            ("Configuración",          SettingsPage),
        ]

        for label, _ in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("NavBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setProperty("active", False)
            btn.clicked.connect(lambda _, i=len(self._nav_buttons): self._navigate(i))
            lay.addWidget(btn)
            self._nav_buttons.append(btn)

        lay.addWidget(self._separator())

        # Motor IDS
        m = QLabel("MOTOR IDS"); m.setObjectName("NavSection")
        lay.addWidget(m)

        self.status_label = QLabel("Inactivo")
        self.status_label.setStyleSheet(f"font-size:12px;color:{MUTED};padding:0 16px;")
        self.iface_label  = QLabel("Interfaz: auto")
        self.iface_label.setStyleSheet(f"font-size:11px;color:#94A3B8;padding:0 16px 4px 16px;")
        self.error_label  = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(
            f"font-size:11px;color:{DANGER};padding:4px 16px;"
            f"background:#FEF2F2;border-left:3px solid {DANGER};")
        self.error_label.hide()
        lay.addWidget(self.status_label)
        lay.addWidget(self.iface_label)
        lay.addWidget(self.error_label)

        btn_row = QWidget()
        br = QHBoxLayout(btn_row); br.setContentsMargins(8, 0, 8, 0); br.setSpacing(8)
        self.start_btn = QPushButton("Iniciar"); self.start_btn.setObjectName("StartBtn")
        self.stop_btn  = QPushButton("Detener"); self.stop_btn.setObjectName("StopBtn")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._start_sniffer)
        self.stop_btn.clicked.connect(self._stop_sniffer)
        br.addWidget(self.start_btn); br.addWidget(self.stop_btn)
        lay.addWidget(btn_row)

        lay.addStretch()
        lay.addWidget(self._separator())
        footer = QLabel("UAA · 8vo Sem · ISC 2026")
        footer.setStyleSheet(f"font-size:10px;color:#94A3B8;padding:4px 16px;")
        lay.addWidget(footer)

        return sidebar

    def _build_content(self):
        self._stack = QStackedWidget()
        self._stack.setObjectName("Root")

        page_classes = [
            lambda: DashboardPage(self),
            WhitelistPage,
            MonitorPage,
            ThreatPage,
            ForensicsPage,
            SettingsPage,
        ]
        for cls in page_classes:
            page = cls()
            scroll = QScrollArea()
            scroll.setWidget(page)
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setStyleSheet(f"background:{BG};")
            self._stack.addWidget(scroll)
            self._pages.append(page)

        self._navigate(0)
        return self._stack

    def _separator(self):
        line = QFrame(); line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color:{BORDER};margin:4px 0;")
        return line

    # ── Navegación ────────────────────────────────────────────────
    def _navigate(self, index):
        for i, btn in enumerate(self._nav_buttons):
            btn.setProperty("active", i == index)
            btn.style().unpolish(btn); btn.style().polish(btn)
        self._stack.setCurrentIndex(index)
        self._pages[index].refresh()

    # ── Sniffer ───────────────────────────────────────────────────
    def _start_sniffer(self):
        # En macOS verificar acceso BPF (lectura + escritura) antes de intentar
        if sys.platform == "darwin" and not check_bpf():
            dlg = BFPDialog(self)
            accepted = dlg.exec() == QDialog.DialogCode.Accepted
            if not accepted or not check_bpf():
                QMessageBox.warning(
                    self, "Sin permisos de red",
                    "La captura requiere acceso a /dev/bpf*.\n\n"
                    "Alternativa rápida — ejecuta en Terminal:\n"
                    "  sudo chmod o+rw /dev/bpf*\n\nDespués presiona Iniciar de nuevo."
                )
                return

        cfg     = load_settings()
        sniffer = get_sniffer(interface=cfg.get("network_interface") or None)
        ok, err = sniffer.start()
        self._update_sniffer_status()

        # Verificar 1.5s después si Scapy falló silenciosamente con error BPF
        if sys.platform == "darwin":
            QTimer.singleShot(1500, self._check_bpf_error)

    def _check_bpf_error(self):
        sniffer = get_sniffer()
        if sniffer.last_error and (
            "bpf" in sniffer.last_error.lower() or
            "permission" in sniffer.last_error.lower()
        ):
            dlg = BFPDialog(self)
            if dlg.exec() == QDialog.DialogCode.Accepted and check_bpf():
                reset_sniffer()
                cfg     = load_settings()
                new_sniffer = get_sniffer(interface=cfg.get("network_interface") or None)
                new_sniffer.start()
                self._update_sniffer_status()
                self.bpf_warning.hide()

    def _stop_sniffer(self):
        get_sniffer().stop()
        self._update_sniffer_status()

    def _update_sniffer_status(self):
        sniffer = get_sniffer()
        running = sniffer.is_running
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.status_label.setText("Activo" if running else "Inactivo")
        self.status_label.setStyleSheet(
            f"font-size:12px;color:{SUCCESS};font-weight:bold;padding:0 16px;"
            if running else
            f"font-size:12px;color:{MUTED};padding:0 16px;"
        )
        cfg = load_settings()
        self.iface_label.setText(f"Interfaz: {cfg.get('network_interface') or 'auto'}")
        if sniffer.last_error:
            self.error_label.setText(sniffer.last_error)
            self.error_label.show()
        else:
            self.error_label.hide()

    # ── Auto-refresh ──────────────────────────────────────────────
    def _setup_refresh(self):
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(5000)

    def _tick(self):
        self._update_sniffer_status()
        idx = self._stack.currentIndex()
        if 0 <= idx < len(self._pages):
            self._pages[idx].refresh()

    # ── Startup: BPF check ────────────────────────────────────────
    def _startup_check(self):
        if sys.platform == "darwin" and not check_bpf():
            self.bpf_warning.setText("Sin acceso BPF — haz clic en 'Iniciar' para autorizar")
            self.bpf_warning.show()
        elif sys.platform != "darwin" and os.geteuid() != 0:
            self.bpf_warning.setText("Ejecuta con sudo para captura real")
            self.bpf_warning.show()


# ══════════════════════════════════════════════════════════════════
# ENTRADA
# ══════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("IDS Corporativo")
    app.setStyleSheet(QSS)

    font = QFont("Helvetica Neue", 13)
    app.setFont(font)

    window = IDSApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
