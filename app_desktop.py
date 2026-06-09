"""
IDS Corporativo — Aplicación de Escritorio
PyQt6 
"""
import sys, os, json, subprocess, logging
from datetime import datetime, timedelta
import calendar

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QStackedWidget, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QTextEdit, QComboBox, QScrollArea, QMessageBox, QDialog,
    QFormLayout, QAbstractItemView, QSizePolicy, QGridLayout,
    QToolTip,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRect, QRectF
from PyQt6.QtGui import (
    QFont, QColor, QPainter, QPainterPath,
    QBrush, QPen, QLinearGradient,
)

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

# ════════════════════════════════════════════════════════════════════════
# PALETA — 
# ════════════════════════════════════════════════════════════════════════
FONT        = "Courier New"
TEXT        = "#111111"      # casi negro — máximo contraste
MUTED       = "#555555"      # gris medio legible
BG          = "#F5F5F5"      # gris muy claro
WHITE       = "#FFFFFF"
BORDER      = "#111111"      # borde negro (estilo sketch)
BORDER_LT   = "#CCCCCC"      # borde suave para separadores internos
GOLD        = "#D97706"      # ámbar oscuro
RED_T       = "#DC2626"      # rojo vívido
BLUE_CHART  = "#3B82F6"      # azul vívido (serie A gráfica)
BEIGE       = "#FEF3C7"      # highlight ámbar suave
GREEN       = "#16A34A"      # verde vívido
TEAL        = "#0D9488"      # teal vívido
ORANGE      = "#EA580C"      # naranja vívido
# Sidebar — claro con iconos oscuros (estilo imagen original)
SIDEBAR_BG      = "#FFFFFF"
SIDEBAR_HOVER   = "#F0F0F0"
SIDEBAR_ACTIVE  = "#EBF5FF"
SIDEBAR_BORDER  = "#111111"
SIDEBAR_TXT     = "#555555"
SIDEBAR_TXT_ACT = "#111111"
# Stripe / acentos de tarjetas
C_BLUE   = "#2563EB"
C_TEAL   = "#0D9488"
C_RED    = "#DC2626"
C_ORANGE = "#EA580C"

# ════════════════════════════════════════════════════════════════════════
# QSS GLOBAL
# ════════════════════════════════════════════════════════════════════════
QSS = f"""
/* ══ REGLA BASE — texto siempre visible ══ */
* {{
    font-family: "{FONT}";
    color: {TEXT};
}}
QLabel, QCheckBox, QRadioButton, QGroupBox, QAbstractItemView {{
    color: {TEXT};
    background: transparent;
}}
QMainWindow, QDialog, QScrollArea > QWidget {{
    background: {BG};
}}

QMainWindow, QWidget#Root {{ background: {BG}; }}
QScrollArea  {{ background: {BG}; border: none; }}
QWidget#Page {{ background: {BG}; }}

/* ─── Sidebar claro (estilo sketch) ────────────────────────── */
QWidget#Sidebar {{
    background: {SIDEBAR_BG};
    border-right: 2px solid {SIDEBAR_BORDER};
}}
QPushButton#NavBtn {{
    background: transparent;
    border: none;
    font-size: 19px;
    color: {SIDEBAR_TXT};
    min-width: 52px; max-width: 52px;
    min-height: 52px; max-height: 52px;
    margin: 1px 4px;
    padding: 0;
}}
QPushButton#NavBtn:hover {{
    background: {SIDEBAR_HOVER};
    color: {SIDEBAR_TXT_ACT};
    border: 1px solid {BORDER_LT};
    border-radius: 4px;
}}
QPushButton#NavBtn[active=true] {{
    background: {SIDEBAR_ACTIVE};
    color: {C_BLUE};
    border: 2px solid {C_BLUE};
    border-radius: 4px;
}}

/* ─── Tarjetas — borde negro sketch ────────────────────────── */
QFrame#Card  {{
    background: {WHITE};
    border: 2px solid {BORDER};
    border-radius: 2px;
}}
QFrame#CardHL {{
    background: {BEIGE};
    border: 2px solid {BORDER};
    border-radius: 2px;
}}

/* ─── Labels de tarjeta ─────────────────────────────────────── */
QLabel#MNum    {{ font-size: 34px; font-weight: bold; color: {TEXT}; letter-spacing: -1px; }}
QLabel#MLbl    {{ font-size: 8px;  color: {MUTED}; letter-spacing: 2px; text-transform: uppercase; }}
QLabel#MTrnd   {{ font-size: 10px; color: {GREEN}; font-weight: bold; }}
QLabel#MTrndDn {{ font-size: 10px; color: {RED_T}; font-weight: bold; }}

/* ─── Títulos de sección / página ───────────────────────────── */
QLabel#SecTitle  {{ font-size: 16px; font-weight: bold; color: {TEXT}; }}
QLabel#SecSub    {{ font-size: 10px; color: {MUTED}; }}
QLabel#PageTitle {{ font-size: 18px; font-weight: bold; color: {TEXT}; }}
QLabel#PageSub   {{ font-size: 10px; color: {MUTED}; }}

/* ─── Tabla ─────────────────────────────────────────────────── */
QTableWidget {{
    background: {WHITE};
    border: 2px solid {BORDER};
    gridline-color: {BORDER_LT};
    selection-background-color: {BEIGE};
    selection-color: {TEXT};
    font-size: 11px;
    color: {TEXT};
    outline: none;
}}
QTableWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {BORDER_LT};
    color: {TEXT};
    background: {WHITE};
}}
QTableWidget::item:selected {{
    background: {BEIGE};
    color: {TEXT};
}}
QHeaderView::section {{
    background: {BG};
    color: {MUTED};
    font-size: 9px;
    font-weight: bold;
    padding: 8px 12px;
    border: none;
    border-bottom: 2px solid {BORDER};
    border-right: 1px solid {BORDER_LT};
    letter-spacing: 1px;
}}
QHeaderView::section:last {{
    border-right: none;
}}

/* ─── Tabs ──────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 2px solid {BORDER};
    background: {WHITE};
    top: -2px;
}}
QTabBar::tab {{
    background: {BG};
    color: {MUTED};
    padding: 8px 16px;
    font-size: 11px;
    border: 2px solid {BORDER};
    border-bottom: none;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {WHITE};
    color: {C_BLUE};
    font-weight: bold;
    border-bottom: 2px solid {WHITE};
}}
QTabBar::tab:hover:!selected {{
    color: {TEXT};
    background: {WHITE};
}}

/* ─── Inputs ────────────────────────────────────────────────── */
QLineEdit, QTextEdit {{
    background: {WHITE};
    border: 2px solid {BORDER};
    border-radius: 2px;
    padding: 7px 10px;
    font-size: 11px;
    color: {TEXT};
}}
QLineEdit:focus, QTextEdit:focus {{
    border: 2px solid {C_BLUE};
}}
QLineEdit:disabled, QTextEdit:disabled {{
    background: {BG};
    color: {MUTED};
}}
QComboBox {{
    background: {WHITE};
    border: 2px solid {BORDER};
    border-radius: 2px;
    padding: 7px 10px;
    font-size: 11px;
    color: {TEXT};
}}
QComboBox:focus {{ border: 2px solid {C_BLUE}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {WHITE};
    color: {TEXT};
    border: 2px solid {BORDER};
    selection-background-color: {BEIGE};
    selection-color: {TEXT};
    outline: none;
}}

/* Botones: estilizados via setStyleSheet directo (ver _restyle en helpers) */

/* ─── Scrollbar ─────────────────────────────────────────────── */
QScrollBar:vertical {{
    width: 6px; background: {BG}; margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER_LT}; border-radius: 3px; min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

/* ─── FormLayout labels ─────────────────────────────────────── */
QFormLayout QLabel {{
    color: {TEXT};
    font-size: 11px;
}}

/* ─── Misceláneos ───────────────────────────────────────────── */
QFrame#HRule {{ background: {BORDER_LT}; max-height: 1px; min-height: 1px; }}
QLabel#InfoKey {{ font-size: 10px; color: {MUTED}; min-width: 130px; }}
QLabel#InfoVal {{ font-size: 10px; color: {TEXT}; font-weight: bold; }}
QMessageBox {{ background: {WHITE}; color: {TEXT}; }}
QMessageBox QLabel {{ color: {TEXT}; background: transparent; }}
QDialog {{ background: {WHITE}; color: {TEXT}; }}
"""

# ════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════
ENV_PATH = os.path.join(ROOT, ".env")


def load_settings():
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_settings(data):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_env_credentials():
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


def save_env_credentials(user, pwd):
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            lines = f.readlines()
    written = set()
    out = []
    for line in lines:
        s = line.strip()
        if s.startswith("IDS_SMTP_USER="):
            out.append(f"IDS_SMTP_USER={user}\n"); written.add("U")
        elif s.startswith("IDS_SMTP_PASSWORD="):
            out.append(f"IDS_SMTP_PASSWORD={pwd}\n"); written.add("P")
        else:
            out.append(line)
    if "U" not in written:
        out.append(f"IDS_SMTP_USER={user}\n")
    if "P" not in written:
        out.append(f"IDS_SMTP_PASSWORD={pwd}\n")
    with open(ENV_PATH, "w") as f:
        f.writelines(out)


def check_bpf():
    if sys.platform != "darwin":
        return os.geteuid() == 0
    return os.access("/dev/bpf0", os.R_OK | os.W_OK)


def fill_table(t: QTableWidget, rows: list):
    t.setRowCount(0)
    for r, row in enumerate(rows):
        t.insertRow(r)
        for c, val in enumerate(row):
            item = QTableWidgetItem(str(val) if val is not None else "—")
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            t.setItem(r, c, item)


def make_table(cols: dict) -> QTableWidget:
    t = QTableWidget()
    t.setColumnCount(len(cols))
    t.setHorizontalHeaderLabels(list(cols.keys()))
    t.horizontalHeader().setStretchLastSection(True)
    for i, w in enumerate(cols.values()):
        if w:
            t.setColumnWidth(i, w)
        else:
            t.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(False)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setShowGrid(False)
    t.setSortingEnabled(False)
    return t


def hline():
    f = QFrame(); f.setObjectName("HRule")
    f.setFrameShape(QFrame.Shape.HLine)
    return f


# Estilos de botón — aplicados directo (bypasa conflictos de QSS en macOS/Qt6)
_BTN_STYLES = {
    "primary": (C_BLUE,  "#FFFFFF", C_BLUE,  "#1D4ED8", "8px 18px"),
    "gold":    (GOLD,    "#FFFFFF", GOLD,    "#B45309",  "8px 18px"),
    "sec":     (WHITE,   TEXT,      BORDER,  BG,         "7px 14px"),
    "danger":  (WHITE,   RED_T,     RED_T,   "#FEF2F2",  "7px 14px"),
    "green":   (GREEN,   "#FFFFFF", GREEN,   "#15803D",  "6px 0px"),
    "stop":    (WHITE,   MUTED,     BORDER_LT, "#FEF2F2","6px 0px"),
}

def _restyle(btn: QPushButton, kind: str = "primary") -> QPushButton:
    bg, fg, border, hover, pad = _BTN_STYLES.get(kind, _BTN_STYLES["primary"])
    hover_fg = "#FFFFFF" if kind in ("primary", "gold", "green") else RED_T if kind == "danger" else TEXT
    btn.setStyleSheet(
        f"QPushButton {{"
        f"  background: {bg}; color: {fg};"
        f"  border: 2px solid {border}; border-radius: 2px;"
        f"  padding: {pad}; font-size: 11px; font-weight: bold;"
        f"  font-family: '{FONT}';"
        f"}}"
        f"QPushButton:hover {{"
        f"  background: {hover}; color: {hover_fg};"
        f"}}"
        f"QPushButton:disabled {{"
        f"  background: {BORDER_LT}; color: {MUTED}; border-color: {BORDER_LT};"
        f"}}"
    )
    return btn


def _page_header(title, sub=""):
    w = QWidget()
    l = QVBoxLayout(w); l.setContentsMargins(0, 0, 0, 8); l.setSpacing(2)
    t = QLabel(title); t.setObjectName("PageTitle")
    l.addWidget(t)
    if sub:
        s = QLabel(sub); s.setObjectName("PageSub"); l.addWidget(s)
    return w


# ════════════════════════════════════════════════════════════════════════
# WIDGET: Tarjeta de métrica
# ════════════════════════════════════════════════════════════════════════

class MetricCard(QFrame):
    STRIPE_H = 5

    def __init__(self, label: str, stripe_color: str = C_BLUE, icon: str = ""):
        super().__init__()
        self.setObjectName("Card")
        self._stripe = QColor(stripe_color)
        self.setMinimumSize(160, 120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, self.STRIPE_H + 14, 16, 14)
        lay.setSpacing(3)

        hdr = QHBoxLayout()
        self._lbl = QLabel(label.upper())
        self._lbl.setObjectName("MLbl")
        hdr.addWidget(self._lbl)
        if icon:
            ic = QLabel(icon)
            ic.setStyleSheet(f"font-size:18px; color:{stripe_color}; background:transparent;")
            hdr.addStretch(); hdr.addWidget(ic)

        self._num = QLabel("—")
        self._num.setObjectName("MNum")
        self._num.setStyleSheet(f"color:{stripe_color}; font-size:34px; font-weight:bold;")

        self._trend = QLabel("")
        self._trend.setObjectName("MTrnd")

        lay.addLayout(hdr)
        lay.addWidget(self._num)
        lay.addWidget(self._trend)
        lay.addStretch()

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(self._stripe))
        p.drawRoundedRect(0, 0, self.width(), self.STRIPE_H, 8, 8)
        p.end()

    def update_data(self, value: int, trend_text="", trend_up=True):
        self._num.setText(f"{value:,}")
        if trend_text:
            self._trend.setObjectName("MTrnd" if trend_up else "MTrndDn")
            arrow = "↑" if trend_up else "↓"
            self._trend.setText(f"{arrow}  {trend_text}")
            self._trend.style().unpolish(self._trend)
            self._trend.style().polish(self._trend)
        else:
            self._trend.setText("")


# ════════════════════════════════════════════════════════════════════════
# WIDGET: Gráfica dual de barras (mensuales)
# ════════════════════════════════════════════════════════════════════════

class BarChartWidget(QWidget):
    """
    Gráfica de barras verticales agrupadas — dos series por mes.
    Serie A (Lista blanca): azul  #60A5FA
    Serie B (Amenazas):     rojo  #EF4444
    """
    _COL_A = QColor(BLUE_CHART)   # azul
    _COL_B = QColor(C_RED)        # rojo
    _GRID  = QColor("#E2E8F0")
    _BG    = QColor(WHITE)
    _MUTED = QColor(MUTED)
    _TEXT  = QColor(TEXT)
    _RADIUS = 4

    def __init__(self):
        super().__init__()
        self._data = []
        self.setMinimumHeight(240)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, data: list):
        self._data = data
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), self._BG)

        if not self._data:
            p.setPen(self._MUTED)
            p.setFont(QFont(FONT, 11))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "Sin datos — activa el IDS para capturar tráfico")
            p.end(); return

        W, H = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 48, 20, 30, 36

        cw = W - pad_l - pad_r
        ch = H - pad_t - pad_b
        n  = len(self._data)

        max_v = max(
            max(d.get("whitelist", 0) for d in self._data),
            max(d.get("threats",   0) for d in self._data),
            1,
        )

        # Cuadrícula y etiquetas eje Y
        grid_steps = 4
        p.setFont(QFont(FONT, 8))
        for i in range(grid_steps + 1):
            frac = i / grid_steps
            y    = int(pad_t + ch * (1 - frac))
            p.setPen(QPen(self._GRID, 1, Qt.PenStyle.SolidLine))
            p.drawLine(pad_l, y, pad_l + cw, y)
            p.setPen(self._MUTED)
            lbl = str(int(max_v * frac))
            p.drawText(0, y - 8, pad_l - 6, 16,
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, lbl)

        # Barras
        slot_w = cw / n
        bar_w  = min(slot_w * 0.30, 22)
        gap    = bar_w * 0.25

        p.setPen(Qt.PenStyle.NoPen)
        for i, d in enumerate(self._data):
            cx  = pad_l + (i + 0.5) * slot_w
            xa  = cx - bar_w - gap / 2
            xb  = cx + gap / 2
            wl  = d.get("whitelist", 0)
            th  = d.get("threats",   0)

            # Serie A — lista blanca (azul)
            if wl > 0:
                h_a = int(ch * wl / max_v)
                y_a = pad_t + ch - h_a
                p.setBrush(QBrush(self._COL_A))
                path = QPainterPath()
                path.addRoundedRect(QRectF(xa, y_a, bar_w, h_a),
                                    self._RADIUS, self._RADIUS)
                # Quitar redondeo de la parte inferior
                path.addRect(QRectF(xa, y_a + self._RADIUS, bar_w, h_a - self._RADIUS))
                p.drawPath(path)
                # Valor encima
                if h_a > 16:
                    p.setPen(self._COL_A)
                    p.setFont(QFont(FONT, 7, QFont.Weight.Bold))
                    p.drawText(int(xa), y_a - 14, int(bar_w), 14,
                               Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                               str(wl))
                    p.setPen(Qt.PenStyle.NoPen)

            # Serie B — amenazas (rojo)
            if th > 0:
                h_b = int(ch * th / max_v)
                y_b = pad_t + ch - h_b
                p.setBrush(QBrush(self._COL_B))
                path2 = QPainterPath()
                path2.addRoundedRect(QRectF(xb, y_b, bar_w, h_b),
                                     self._RADIUS, self._RADIUS)
                path2.addRect(QRectF(xb, y_b + self._RADIUS, bar_w, h_b - self._RADIUS))
                p.drawPath(path2)
                if h_b > 16:
                    p.setPen(self._COL_B)
                    p.setFont(QFont(FONT, 7, QFont.Weight.Bold))
                    p.drawText(int(xb), y_b - 14, int(bar_w), 14,
                               Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                               str(th))
                    p.setPen(Qt.PenStyle.NoPen)

            # Etiqueta mes (eje X)
            p.setPen(self._MUTED)
            p.setFont(QFont(FONT, 8))
            p.drawText(int(cx - slot_w / 2), pad_t + ch + 6,
                       int(slot_w), 24,
                       Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                       d.get("label", ""))

        # Eje X (línea base)
        p.setPen(QPen(QColor(BORDER_LT), 1))
        p.drawLine(pad_l, pad_t + ch, pad_l + cw, pad_t + ch)

        # Leyenda superior derecha
        leg_x = pad_l + cw - 180
        leg_y = 6
        for color, label in [(self._COL_A, "Lista blanca"), (self._COL_B, "Amenazas")]:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(color))
            p.drawRoundedRect(leg_x, leg_y, 12, 12, 3, 3)
            p.setPen(self._MUTED)
            p.setFont(QFont(FONT, 8))
            p.drawText(leg_x + 16, leg_y, 80, 12,
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, label)
            leg_x += 100

        p.end()


# Alias para compatibilidad con código existente
DualBarChart = BarChartWidget


# ════════════════════════════════════════════════════════════════════════
# WIDGET: Gráfica de pastel (pie chart)
# ════════════════════════════════════════════════════════════════════════

class PieChartWidget(QWidget):
    """
    Gráfica de pastel con etiquetas y leyenda.
    Recibe lista de dicts: [{label, value, color?}, ...]
    """
    _PALETTE = [
        "#3B82F6", "#EF4444", "#10B981", "#F59E0B",
        "#8B5CF6", "#14B8A6", "#F97316", "#EC4899",
        "#6366F1", "#84CC16",
    ]
    _BG    = QColor(WHITE)
    _MUTED = QColor(MUTED)
    _TEXT  = QColor(TEXT)

    def __init__(self):
        super().__init__()
        self._data = []
        self.setMinimumHeight(260)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, data: list):
        self._data = [d for d in data if d.get("value", 0) > 0]
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), self._BG)

        if not self._data:
            p.setPen(self._MUTED)
            p.setFont(QFont(FONT, 11))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "Sin datos — navega en la red para registrar dominios")
            p.end(); return

        W, H = self.width(), self.height()
        # Pie a la izquierda, leyenda a la derecha
        pie_size = min(H - 40, (W * 55) // 100)
        pie_size = max(pie_size, 140)
        pie_x = 20
        pie_y = (H - pie_size) // 2
        pie_rect = QRectF(pie_x, pie_y, pie_size, pie_size)

        total = sum(d.get("value", 0) for d in self._data)
        if total == 0: p.end(); return

        angle = 90 * 16   # Empezar desde las 12

        slices = self._data[:10]
        for i, d in enumerate(slices):
            color = QColor(d.get("color") or self._PALETTE[i % len(self._PALETTE)])
            span  = int(round(d["value"] / total * 360 * 16))
            p.setPen(QPen(self._BG, 2))
            p.setBrush(QBrush(color))
            p.drawPie(pie_rect, angle, span)
            angle -= span

        # Donut hole (círculo blanco al centro)
        hole = pie_size * 0.42
        hx   = pie_x + (pie_size - hole) / 2
        hy   = pie_y + (pie_size - hole) / 2
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(self._BG))
        p.drawEllipse(QRectF(hx, hy, hole, hole))
        # Total en el centro
        p.setPen(self._TEXT)
        p.setFont(QFont(FONT, 11, QFont.Weight.Bold))
        p.drawText(QRectF(hx, hy, hole, hole),
                   Qt.AlignmentFlag.AlignCenter, str(total))
        p.setPen(self._MUTED)
        p.setFont(QFont(FONT, 7))
        p.drawText(QRectF(hx, hy + hole * 0.52, hole, hole * 0.3),
                   Qt.AlignmentFlag.AlignCenter, "total")

        # Leyenda derecha
        lx = pie_x + pie_size + 20
        ly = pie_y + 4
        row_h = 22
        angle = 90 * 16
        for i, d in enumerate(slices):
            color = QColor(d.get("color") or self._PALETTE[i % len(self._PALETTE)])
            pct   = d["value"] / total * 100
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(color))
            p.drawRoundedRect(lx, ly + i * row_h + 4, 12, 12, 3, 3)
            p.setPen(self._TEXT)
            p.setFont(QFont(FONT, 9))
            lbl = d.get("label", "")
            if len(lbl) > 22: lbl = lbl[:20] + "…"
            p.drawText(lx + 18, ly + i * row_h, W - lx - 18 - 10, row_h,
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       f"{lbl}  ({pct:.0f}%)")

        p.end()


# ════════════════════════════════════════════════════════════════════════
# WIDGET: Barra de severidad para tabla
# ════════════════════════════════════════════════════════════════════════

class SeverityBar(QWidget):
    _MAP = {
        "Critico":   (C_RED,    100),
        "Alto":      (C_ORANGE,  67),
        "Medio":     (GOLD,      33),
        "PORT_SCAN": (C_RED,     75),
    }

    def __init__(self, level: str):
        super().__init__()
        color, pct = self._MAP.get(level, (MUTED, 33))
        self._color = QColor(color)
        self._pct   = pct
        self._label = level

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bw = max(self.width() - 70, 40)
        bh = 7
        by = (self.height() - bh) // 2

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(BORDER_LT)))
        p.drawRoundedRect(4, by, bw, bh, 3, 3)

        filled = int(bw * self._pct / 100)
        if filled > 0:
            p.setBrush(QBrush(self._color))
            p.drawRoundedRect(4, by, filled, bh, 3, 3)

        p.setPen(QColor(TEXT))
        p.setFont(QFont(FONT, 9))
        p.drawText(bw + 10, 0, 56, self.height(),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   self._label)
        p.end()


# ════════════════════════════════════════════════════════════════════════
# WIDGET: Banner de alerta reciente
# ════════════════════════════════════════════════════════════════════════

class AlertBanner(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(
            f"QFrame {{ background: #FEF3C7; border-left: 4px solid {C_ORANGE}; "
            f"border-top: 1px solid #FCD34D; border-bottom: 1px solid #FCD34D; "
            f"border-right: 1px solid #FCD34D; border-radius: 6px; }}"
        )
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)

        self._icon = QLabel("⚠")
        self._icon.setStyleSheet(
            f"font-size:16px; color:{C_ORANGE}; border:none; background:transparent;"
        )

        self._title  = QLabel()
        self._title.setStyleSheet(
            f"font-size:12px; font-weight:bold; color:#92400E; border:none; background:transparent;"
        )
        self._detail = QLabel()
        self._detail.setStyleSheet(
            f"font-size:10px; color:#B45309; border:none; background:transparent;"
        )

        txt = QVBoxLayout(); txt.setSpacing(1)
        txt.addWidget(self._title)
        txt.addWidget(self._detail)

        self._ts = QLabel()
        self._ts.setStyleSheet(
            f"font-size:9px; color:#B45309; border:none; background:transparent;"
        )
        self._ts.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        lay.addWidget(self._icon)
        lay.addLayout(txt, stretch=1)
        lay.addWidget(self._ts)
        self.hide()

        self._blink = True
        tmr = QTimer(self); tmr.timeout.connect(self._do_blink); tmr.start(800)

    def _do_blink(self):
        self._blink = not self._blink
        border_c = C_ORANGE if self._blink else GOLD
        self.setStyleSheet(
            f"QFrame {{ background: #FEF3C7; border-left: 4px solid {border_c}; "
            f"border-top: 1px solid #FCD34D; border-bottom: 1px solid #FCD34D; "
            f"border-right: 1px solid #FCD34D; border-radius: 6px; }}"
        )

    def refresh(self):
        cutoff = (datetime.now() - timedelta(minutes=30)).isoformat(sep=" ", timespec="seconds")
        wl = db.fetch_whitelist_alerts(limit=3)
        th = db.fetch_threat_alerts(limit=3)
        rw = [a for a in wl if a.get("timestamp", "") >= cutoff]
        rt = [a for a in th if a.get("timestamp", "") >= cutoff]
        total = len(rw) + len(rt)
        if total == 0:
            self.hide(); return

        if rt:
            last = rt[0]
            detail = f"{last['threat_type']}  ·  IP: {last['dst_ip']}"
            ts = last["timestamp"]
        else:
            last = rw[0]
            detail = f"{last['alert_type'].replace('_',' ')}  ·  IP: {last['src_ip']}"
            ts = last["timestamp"]

        pl = "s" if total != 1 else ""
        self._title.setText(f"  {total} alerta{pl} en los últimos 30 min")
        self._detail.setText(f"  {detail}")
        self._ts.setText(ts)
        self.show()


# ════════════════════════════════════════════════════════════════════════
# DIÁLOGO BPF
# ════════════════════════════════════════════════════════════════════════

class BFPDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Permisos de red requeridos")
        self.setFixedSize(400, 190)
        lay = QVBoxLayout(self); lay.setContentsMargins(28, 22, 28, 22); lay.setSpacing(14)
        t = QLabel("Acceso a la interfaz de red")
        t.setStyleSheet(f"font-size:15px; font-weight:bold; color:{TEXT};")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        m = QLabel("El IDS necesita leer paquetes de red.\nSe mostrará la solicitud de contraseña macOS.")
        m.setAlignment(Qt.AlignmentFlag.AlignCenter)
        m.setStyleSheet(f"font-size:12px; color:{MUTED};")
        m.setWordWrap(True)
        br = QHBoxLayout()
        skip = _restyle(QPushButton("Omitir"), "sec"); skip.clicked.connect(self.reject)
        auth = _restyle(QPushButton("Autorizar acceso"), "gold"); auth.clicked.connect(self._fix)
        br.addWidget(skip); br.addWidget(auth)
        lay.addWidget(t); lay.addWidget(m); lay.addLayout(br)

    def _fix(self):
        res = subprocess.run(
            ["osascript", "-e",
             'do shell script "chmod o+rw /dev/bpf*" with administrator privileges'],
            capture_output=True,
        )
        if res.returncode == 0:
            QMessageBox.information(self, "Listo", "Permisos configurados.")
            self.accept()
        else:
            QMessageBox.warning(self, "Cancelado", "Sin permisos — captura no disponible.")
            self.reject()


# ════════════════════════════════════════════════════════════════════════
# HILO DE ESCANEO ARP
# ════════════════════════════════════════════════════════════════════════

class ScanThread(QThread):
    result = pyqtSignal(list)
    error  = pyqtSignal(str)
    def __init__(self, net): super().__init__(); self.net = net
    def run(self):
        try: self.result.emit(scan_network(self.net))
        except Exception as e: self.error.emit(str(e))


# ════════════════════════════════════════════════════════════════════════
# PÁGINA: DASHBOARD
# ════════════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__(); self.setObjectName("Page"); self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(16)

        # Cabecera
        hdr = QHBoxLayout()
        left_hdr = QVBoxLayout(); left_hdr.setSpacing(2)
        t = QLabel("Estadísticas"); t.setObjectName("SecTitle")
        s = QLabel("Actividad de la red en tiempo real")
        s.setObjectName("SecSub")
        left_hdr.addWidget(t); left_hdr.addWidget(s)
        hdr.addLayout(left_hdr, stretch=1)
        root.addLayout(hdr)

        # Banner de alertas
        self.banner = AlertBanner()
        root.addWidget(self.banner)

        # ── Sección principal: métricas + gráfica ──────────────────
        main_row = QHBoxLayout(); main_row.setSpacing(18)

        # Tarjetas 2x2
        cards_col = QVBoxLayout(); cards_col.setSpacing(10)
        top_cards = QHBoxLayout(); top_cards.setSpacing(10)
        bot_cards = QHBoxLayout(); bot_cards.setSpacing(10)

        self.card_wl  = MetricCard("Alertas lista blanca", stripe_color=C_BLUE,   icon="✓")
        self.card_dom = MetricCard("Dominios registrados",  stripe_color=C_TEAL,   icon="◉")
        self.card_thr = MetricCard("Amenazas detectadas",   stripe_color=C_RED,    icon="△")
        self.card_ps  = MetricCard("Escaneos de puertos",   stripe_color=C_ORANGE, icon="⚡")

        top_cards.addWidget(self.card_wl)
        top_cards.addWidget(self.card_dom)
        bot_cards.addWidget(self.card_thr)
        bot_cards.addWidget(self.card_ps)

        cards_col.addLayout(top_cards)
        cards_col.addLayout(bot_cards)

        # Estado del motor debajo de las cards
        self.motor_frame = QFrame(); self.motor_frame.setObjectName("Card")
        mf = QHBoxLayout(self.motor_frame); mf.setContentsMargins(12, 10, 12, 10)
        self.motor_status = QLabel("○  Motor inactivo")
        self.motor_status.setStyleSheet(f"font-size:11px; color:{MUTED}; font-weight:bold;")
        self.motor_iface  = QLabel("—")
        self.motor_iface.setStyleSheet(f"font-size:10px; color:{MUTED};")
        mf.addWidget(self.motor_status); mf.addStretch(); mf.addWidget(self.motor_iface)
        cards_col.addWidget(self.motor_frame)
        cards_col.addStretch()

        main_row.addLayout(cards_col, stretch=2)

        # Gráfica dual
        chart_frame = QFrame(); chart_frame.setObjectName("Card")
        cf = QVBoxLayout(chart_frame); cf.setContentsMargins(16, 14, 16, 14); cf.setSpacing(8)
        ch_title = QLabel("Actividad de Red por Mes")
        ch_title.setObjectName("SecTitle")
        ch_title.setStyleSheet(f"font-size:13px; font-weight:bold; color:{TEXT};")
        cf.addWidget(ch_title)
        self.dual_chart = DualBarChart()
        cf.addWidget(self.dual_chart)

        main_row.addWidget(chart_frame, stretch=3)
        root.addLayout(main_row)

        # ── Tabla de alertas recientes ─────────────────────────────
        tbl_hdr = QHBoxLayout()
        t2 = QLabel("Alertas Recientes"); t2.setObjectName("SecTitle")
        t2.setStyleSheet(f"font-size:14px; font-weight:bold; color:{TEXT};")
        tbl_hdr.addWidget(t2); tbl_hdr.addStretch()
        root.addLayout(tbl_hdr)
        root.addWidget(hline())

        self.tbl = make_table({
            "TIMESTAMP": 140, "IP ORIGEN": 115, "TIPO": 160,
            "DESTINO / MAC": 140, "SEVERIDAD": 0,
        })
        self.tbl.setMinimumHeight(200)
        root.addWidget(self.tbl)
        root.addStretch()

    def refresh(self):
        stats = db.get_stats()

        self.card_wl.update_data(stats["whitelist_alerts"],
                                 "activas" if stats["whitelist_alerts"] > 0 else "sin datos",
                                 stats["whitelist_alerts"] > 0)
        self.card_dom.update_data(stats["site_visits"],
                                  "dominios capturados" if stats["site_visits"] > 0 else "sin datos",
                                  stats["site_visits"] > 0)
        self.card_thr.update_data(stats["threat_alerts"],
                                  "detectadas" if stats["threat_alerts"] > 0 else "sin datos",
                                  stats["threat_alerts"] > 0)
        self.card_ps.update_data(stats["port_scans"],
                                 "escaneos bloqueados" if stats["port_scans"] > 0 else "sin datos",
                                 stats["port_scans"] > 0)

        sniffer = get_sniffer()
        cfg     = load_settings()
        if sniffer.is_running:
            self.motor_status.setText("●  Motor activo")
            self.motor_status.setStyleSheet(f"font-size:11px; color:{GREEN}; font-weight:bold;")
        else:
            self.motor_status.setText("○  Motor inactivo")
            self.motor_status.setStyleSheet(f"font-size:11px; color:{MUTED}; font-weight:bold;")
        self.motor_iface.setText(
            f"IP: {get_local_ip()}   interfaz: {cfg.get('network_interface') or 'auto'}"
        )

        # Gráfica mensual
        monthly = db.fetch_monthly_stats(months=8)
        self.dual_chart.set_data(monthly)

        # Banner
        self.banner.refresh()

        # Tabla combinada de alertas recientes
        wl_rows = db.fetch_whitelist_alerts(limit=6)
        th_rows = db.fetch_threat_alerts(limit=6)

        # Unir y ordenar por timestamp
        combined = []
        for a in wl_rows:
            combined.append({
                "ts":   a["timestamp"],
                "src":  a["src_ip"],
                "tipo": a["alert_type"].replace("_", " "),
                "dest": a["src_mac"] or "—",
                "lvl":  "Medio",
            })
        for t in th_rows:
            combined.append({
                "ts":   t["timestamp"],
                "src":  t["src_ip"] or "—",
                "tipo": t["threat_type"],
                "dest": t["dst_ip"],
                "lvl":  t["risk_level"],
            })
        combined.sort(key=lambda x: x["ts"], reverse=True)

        self.tbl.setRowCount(0)
        for i, row in enumerate(combined[:10]):
            self.tbl.insertRow(i)
            for c, val in enumerate([row["ts"], row["src"], row["tipo"], row["dest"]]):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self.tbl.setItem(i, c, item)
            bar = SeverityBar(row["lvl"])
            self.tbl.setCellWidget(i, 4, bar)


# ════════════════════════════════════════════════════════════════════════
# PÁGINA: LISTA BLANCA
# ════════════════════════════════════════════════════════════════════════

class WhitelistPage(QWidget):
    def __init__(self):
        super().__init__(); self.setObjectName("Page")
        self._scan_thread = None; self._scanned = []; self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22); root.setSpacing(12)
        root.addWidget(_page_header("Módulo 1: Lista Blanca",
            "Capa 2 (MAC) y Capa 3 (IP) — dispositivos autorizados"))
        self.banner = AlertBanner(); root.addWidget(self.banner)
        tabs = QTabWidget()

        t1 = QWidget(); l1 = QVBoxLayout(t1); l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_a = make_table({"TIMESTAMP": 140, "IP": 115, "MAC": 150, "TIPO": 170, "EMAIL": 70})
        l1.addWidget(self.tbl_a); tabs.addTab(t1, "Alertas en tiempo real")

        t2 = QWidget(); l2 = QVBoxLayout(t2); l2.setContentsMargins(12, 12, 12, 12); l2.setSpacing(8)
        row2 = QHBoxLayout()
        lv = QVBoxLayout(); lv.addWidget(QLabel("IPs autorizadas (una por línea)"))
        self.txt_ips = QTextEdit(); lv.addWidget(self.txt_ips)
        rv = QVBoxLayout(); rv.addWidget(QLabel("MACs autorizadas (aa:bb:cc:dd:ee:ff)"))
        self.txt_macs = QTextEdit(); rv.addWidget(self.txt_macs)
        row2.addLayout(lv); row2.addLayout(rv)
        l2.addLayout(row2)
        sb = _restyle(QPushButton("Guardar lista blanca"))
        sb.clicked.connect(self._save); l2.addWidget(sb)
        tabs.addTab(t2, "Gestionar lista blanca")

        t3 = QWidget(); l3 = QVBoxLayout(t3); l3.setContentsMargins(12, 12, 12, 12); l3.setSpacing(8)
        r3 = QHBoxLayout()
        self.scan_net = QLineEdit(get_default_network())
        self.scan_btn = _restyle(QPushButton("Escanear red local"))
        self.scan_btn.clicked.connect(self._scan)
        r3.addWidget(QLabel("Red (CIDR):")); r3.addWidget(self.scan_net); r3.addWidget(self.scan_btn)
        l3.addLayout(r3)
        self.scan_status = QLabel(""); self.scan_status.setStyleSheet(f"color:{MUTED};font-size:10px;")
        l3.addWidget(self.scan_status)
        self.tbl_scan = make_table({"IP": 130, "MAC": 155, "Hostname": 0})
        l3.addWidget(self.tbl_scan)
        self.add_btn = QPushButton("Agregar seleccionados a lista blanca")
        _restyle(self.add_btn); self.add_btn.setEnabled(False)
        self.add_btn.clicked.connect(self._add_sel); l3.addWidget(self.add_btn)
        tabs.addTab(t3, "Escanear red local")

        root.addWidget(tabs); self._load()

    def _load(self):
        with open(os.path.join(ROOT, "config", "whitelist.json")) as f:
            d = json.load(f)
        self.txt_ips.setPlainText("\n".join(d.get("authorized_ips", [])))
        self.txt_macs.setPlainText("\n".join(d.get("authorized_macs", [])))

    def _save(self):
        ips  = [l.strip() for l in self.txt_ips.toPlainText().splitlines() if l.strip()]
        macs = [l.strip().lower() for l in self.txt_macs.toPlainText().splitlines() if l.strip()]
        from core.whitelist import WhitelistChecker
        WhitelistChecker().save(ips, macs); get_sniffer().whitelist.reload()
        QMessageBox.information(self, "Guardado", f"{len(ips)} IPs, {len(macs)} MACs guardadas.")

    def _scan(self):
        if not check_bpf():
            QMessageBox.warning(self, "Sin permisos", "Requiere permisos de red para escaneo ARP.")
            return
        self.scan_btn.setEnabled(False)
        self.scan_status.setText("Escaneando red...")
        self._scan_thread = ScanThread(self.scan_net.text())
        self._scan_thread.result.connect(self._on_scan)
        self._scan_thread.error.connect(lambda e: (self.scan_btn.setEnabled(True),
                                                    self.scan_status.setText(f"Error: {e}")))
        self._scan_thread.start()

    def _on_scan(self, devices):
        self._scanned = devices
        self.scan_btn.setEnabled(True)
        self.scan_status.setText(f"{len(devices)} dispositivos encontrados.")
        fill_table(self.tbl_scan, [(d["ip"], d["mac"], d["hostname"]) for d in devices])
        self.tbl_scan.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.add_btn.setEnabled(bool(devices))

    def _add_sel(self):
        rows = {i.row() for i in self.tbl_scan.selectedIndexes()}
        if not rows:
            QMessageBox.information(self, "Vacío", "Selecciona al menos un dispositivo."); return
        with open(os.path.join(ROOT, "config", "whitelist.json")) as f:
            d = json.load(f)
        ei = set(d.get("authorized_ips", [])); em = set(d.get("authorized_macs", []))
        added = 0
        for r in rows:
            dev = self._scanned[r]
            if dev["ip"] not in ei: ei.add(dev["ip"]); added += 1
            em.add(dev["mac"])
        from core.whitelist import WhitelistChecker
        WhitelistChecker().save(list(ei), list(em)); get_sniffer().whitelist.reload()
        self._load(); self.tbl_scan.clearSelection()
        QMessageBox.information(self, "Agregados", f"{added} dispositivos nuevos agregados.")

    def refresh(self):
        self.banner.refresh()
        fill_table(self.tbl_a, [
            (a["timestamp"], a["src_ip"], a["src_mac"] or "—",
             a["alert_type"].replace("_", " "), "Sí" if a["email_sent"] else "No")
            for a in db.fetch_whitelist_alerts(limit=80)
        ])


# ════════════════════════════════════════════════════════════════════════
# PÁGINA: MONITOR DE SITIOS
# ════════════════════════════════════════════════════════════════════════

class MonitorPage(QWidget):
    def __init__(self):
        super().__init__(); self.setObjectName("Page"); self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22); root.setSpacing(12)
        root.addWidget(_page_header("Módulo 2: Monitoreo de Sitios",
            "Bitácora en tiempo real — DNS / HTTP / HTTPS"))
        tabs = QTabWidget()

        t1 = QWidget(); l1 = QVBoxLayout(t1); l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_log = make_table({"TIMESTAMP": 140, "IP": 115, "DOMINIO": 0, "PROTOCOLO": 80})
        l1.addWidget(self.tbl_log); tabs.addTab(t1, "Bitácora en tiempo real")

        t2 = QWidget(); l2 = QVBoxLayout(t2); l2.setContentsMargins(12, 12, 12, 12); l2.setSpacing(10)

        # Layout: pastel (izq) + tabla dominios (der)
        charts_row = QHBoxLayout(); charts_row.setSpacing(16)

        # Pastel — distribución de dominios
        pie_frame = QFrame(); pie_frame.setObjectName("Card")
        pf = QVBoxLayout(pie_frame); pf.setContentsMargins(12, 12, 12, 12); pf.setSpacing(6)
        pie_lbl = QLabel("Distribución de dominios")
        pie_lbl.setStyleSheet(f"font-size:12px; font-weight:bold; color:{TEXT}; background:transparent;")
        self.pie_chart = PieChartWidget()
        self.pie_chart.setMinimumHeight(260)
        pf.addWidget(pie_lbl)
        pf.addWidget(self.pie_chart)
        charts_row.addWidget(pie_frame, stretch=2)

        # Barras — actividad mensual
        bar_frame = QFrame(); bar_frame.setObjectName("Card")
        bf = QVBoxLayout(bar_frame); bf.setContentsMargins(12, 12, 12, 12); bf.setSpacing(6)
        bar_lbl = QLabel("Actividad mensual (barras)")
        bar_lbl.setStyleSheet(f"font-size:12px; font-weight:bold; color:{TEXT}; background:transparent;")
        self.top_chart = BarChartWidget()
        self.top_chart.setMinimumHeight(260)
        bf.addWidget(bar_lbl)
        bf.addWidget(self.top_chart)
        charts_row.addWidget(bar_frame, stretch=3)

        l2.addLayout(charts_row)
        l2.addWidget(hline())
        self.tbl_top = make_table({"DOMINIO": 0, "VISITAS": 90, "ÚLTIMA VEZ": 140})
        self.tbl_top.setMaximumHeight(180)
        l2.addWidget(self.tbl_top)
        tabs.addTab(t2, "Top dominios")

        root.addWidget(tabs)

    def refresh(self):
        fill_table(self.tbl_log, [
            (v["timestamp"], v["src_ip"], v["domain"], v["protocol"])
            for v in db.fetch_site_visits(limit=150)
        ])
        top = db.fetch_top_domains(limit=10)
        fill_table(self.tbl_top, [(r["domain"], r["visits"], r["last_seen"]) for r in top])
        # Pastel con top dominios
        self.pie_chart.set_data([
            {"label": r["domain"], "value": r["visits"]} for r in top
        ])
        # Barras mensuales
        monthly = db.fetch_monthly_stats(months=8)
        self.top_chart.set_data(monthly)


# ════════════════════════════════════════════════════════════════════════
# PÁGINA: AMENAZAS
# ════════════════════════════════════════════════════════════════════════

class ThreatPage(QWidget):
    def __init__(self):
        super().__init__(); self.setObjectName("Page"); self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22); root.setSpacing(12)
        root.addWidget(_page_header("Módulo 3: Amenazas + Escaneo de Puertos",
            "Lista negra activa · detección en tiempo real · port scan detection"))
        self.banner = AlertBanner(); root.addWidget(self.banner)
        tabs = QTabWidget()

        t1 = QWidget(); l1 = QVBoxLayout(t1); l1.setContentsMargins(12, 12, 12, 12)
        self.tbl_th = make_table({
            "TIMESTAMP": 140, "IP ORIGEN": 110, "IP MALICIOSA": 120,
            "TIPO": 130, "RIESGO": 0, "EMAIL": 60,
        })
        l1.addWidget(self.tbl_th); tabs.addTab(t1, "Alertas de amenaza")

        # Pestaña port scan
        t1b = QWidget(); l1b = QVBoxLayout(t1b); l1b.setContentsMargins(12, 12, 12, 12)
        info = QLabel(
            "Detección de escaneo de puertos (PORT_SCAN):\n"
            "Se alerta cuando una IP accede a ≥ 15 puertos únicos en 60 segundos.\n"
            "Umbral configurable en core/portscan.py (THRESHOLD_PORTS / WINDOW_SECONDS)."
        )
        info.setStyleSheet(
            f"font-size:10px; color:{MUTED}; border:1px solid {BORDER_LT}; "
            f"border-radius:2px; padding:10px; background:{BG};"
        )
        info.setWordWrap(True)
        l1b.addWidget(info)
        self.tbl_ps = make_table({
            "TIMESTAMP": 140, "IP ESCÁNER": 140, "TIPO": 110,
            "DESCRIPCIÓN": 0, "EMAIL": 60,
        })
        l1b.addWidget(self.tbl_ps)
        tabs.addTab(t1b, "Escaneos de puertos")

        t2 = QWidget(); l2 = QVBoxLayout(t2); l2.setContentsMargins(12, 12, 12, 12); l2.setSpacing(8)
        self.tbl_bl = make_table({"IP": 120, "TIPO": 140, "RIESGO": 80, "DESCRIPCIÓN": 0, "FUENTE": 120})
        l2.addWidget(self.tbl_bl); l2.addWidget(hline())
        l2.addWidget(QLabel("Agregar IP manualmente"))
        form = QHBoxLayout()
        self.bl_ip   = QLineEdit(); self.bl_ip.setPlaceholderText("1.2.3.4")
        self.bl_type = QComboBox()
        self.bl_type.addItems(["Botnet C2","Malware Distributor","Phishing","Cryptominer","Exploit Kit","Otro"])
        self.bl_risk = QComboBox(); self.bl_risk.addItems(["Critico","Alto","Medio"])
        self.bl_desc = QLineEdit(); self.bl_desc.setPlaceholderText("Descripción")
        self.bl_src  = QLineEdit(); self.bl_src.setPlaceholderText("Fuente")
        add_b = _restyle(QPushButton("Agregar")); add_b.clicked.connect(self._add_ip)
        for w in (self.bl_ip, self.bl_type, self.bl_risk, self.bl_desc, self.bl_src, add_b):
            form.addWidget(w)
        l2.addLayout(form); tabs.addTab(t2, "Lista negra activa")

        t3 = QWidget(); l3 = QVBoxLayout(t3); l3.setContentsMargins(12, 12, 12, 12); l3.setSpacing(8)
        l3.addWidget(QLabel("URL del feed (una IP por línea):"))
        self.feed_url  = QLineEdit(); self.feed_url.setPlaceholderText("https://feodotracker.abuse.ch/...")
        self.feed_type = QComboBox(); self.feed_type.addItems(["Botnet C2","Malware Distributor","Phishing","Otro"])
        self.feed_risk = QComboBox(); self.feed_risk.addItems(["Critico","Alto","Medio"])
        self.feed_st   = QLabel(""); self.feed_st.setStyleSheet(f"color:{MUTED};font-size:10px;")
        ib_btn = _restyle(QPushButton("Importar desde URL"))
        ib_btn.clicked.connect(self._import_feed)
        fr = QHBoxLayout()
        fr.addWidget(QLabel("Tipo:")); fr.addWidget(self.feed_type)
        fr.addWidget(QLabel("Riesgo:")); fr.addWidget(self.feed_risk)
        l3.addWidget(self.feed_url); l3.addLayout(fr)
        l3.addWidget(ib_btn); l3.addWidget(self.feed_st); l3.addStretch()
        tabs.addTab(t3, "Importar threat feed")

        root.addWidget(tabs); self._load_bl()

    def _load_bl(self):
        with open(os.path.join(ROOT, "config", "blacklist.json")) as f:
            d = json.load(f)
        fill_table(self.tbl_bl, [
            (e["ip"], e.get("threat_type",""), e.get("risk_level",""),
             e.get("description",""), e.get("source",""))
            for e in d.get("dangerous_ips", [])
        ])

    def _add_ip(self):
        ip = self.bl_ip.text().strip()
        if not ip: QMessageBox.warning(self, "Error", "Ingresa una IP."); return
        import socket
        try: socket.inet_aton(ip)
        except socket.error: QMessageBox.warning(self, "Error", "IP inválida."); return
        from datetime import date
        bl_path = os.path.join(ROOT, "config", "blacklist.json")
        with open(bl_path) as f: d = json.load(f)
        d.setdefault("dangerous_ips", []).append({
            "ip": ip, "threat_type": self.bl_type.currentText(),
            "risk_level": self.bl_risk.currentText(),
            "description": self.bl_desc.text(),
            "source": self.bl_src.text() or "Manual",
            "reported": str(date.today()),
        })
        with open(bl_path, "w") as f: json.dump(d, f, indent=2)
        get_sniffer().threat.reload(); self._load_bl()
        self.bl_ip.clear(); self.bl_desc.clear()
        QMessageBox.information(self, "Agregada", f"IP {ip} añadida.")

    def _import_feed(self):
        url = self.feed_url.text().strip()
        if not url: QMessageBox.warning(self, "Error", "Ingresa una URL."); return
        self.feed_st.setText("Descargando..."); QApplication.processEvents()
        try:
            import requests, socket
            from datetime import date
            resp = requests.get(url, timeout=20); resp.raise_for_status()
            bl_path = os.path.join(ROOT, "config", "blacklist.json")
            with open(bl_path) as f: d = json.load(f)
            entries = d.get("dangerous_ips", [])
            existing = {e["ip"] for e in entries}; added = 0
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"): continue
                ip = line.split()[0].split(",")[0].strip()
                try: socket.inet_aton(ip)
                except: continue
                if ip not in existing:
                    entries.append({"ip": ip,
                        "threat_type": self.feed_type.currentText(),
                        "risk_level":  self.feed_risk.currentText(),
                        "description": f"Importado de: {url}",
                        "source": url, "reported": str(date.today())})
                    existing.add(ip); added += 1
            d["dangerous_ips"] = entries
            with open(bl_path, "w") as f: json.dump(d, f, indent=2)
            get_sniffer().threat.reload(); self._load_bl()
            self.feed_st.setText(f"{added} IPs importadas. Total: {len(entries)}")
        except Exception as e:
            self.feed_st.setText(f"Error: {e}")

    def refresh(self):
        self.banner.refresh()
        fill_table(self.tbl_th, [
            (t["timestamp"], t["src_ip"] or "—", t["dst_ip"],
             t["threat_type"], t["risk_level"], "Sí" if t["email_sent"] else "No")
            for t in db.fetch_threat_alerts(limit=80)
        ])
        # Tabla port scan
        ps_rows = [t for t in db.fetch_threat_alerts(limit=200) if t["threat_type"] == "PORT_SCAN"]
        fill_table(self.tbl_ps, [
            (t["timestamp"], t["src_ip"] or "—", t["threat_type"],
             (t.get("description") or "")[:80], "Sí" if t["email_sent"] else "No")
            for t in ps_rows
        ])


# ════════════════════════════════════════════════════════════════════════
# PÁGINA: FORENSE
# ════════════════════════════════════════════════════════════════════════

class ForensicsPage(QWidget):
    def __init__(self):
        super().__init__(); self.setObjectName("Page"); self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22); root.setSpacing(12)
        root.addWidget(_page_header("Módulo 4: Informes Forenses",
            "WHOIS automatizado — contacto de abuso del proveedor"))
        tabs = QTabWidget()

        t1 = QWidget(); l1 = QVBoxLayout(t1); l1.setContentsMargins(12, 12, 12, 12); l1.setSpacing(8)
        self.tbl_r = make_table({
            "TIMESTAMP": 140, "IP": 120, "ORGANIZACIÓN": 0,
            "PAÍS": 55, "ASN": 80, "CONTACTO": 160, "EMAIL": 55,
        })
        self.tbl_r.clicked.connect(self._detail)
        l1.addWidget(self.tbl_r)
        l1.addWidget(QLabel("WHOIS completo (selecciona una fila):"))
        self.raw = QTextEdit(); self.raw.setReadOnly(True); self.raw.setMaximumHeight(150)
        self.raw.setStyleSheet(f"font-family:{FONT}; font-size:10px; background:{BG}; border:1.5px solid {BORDER};")
        l1.addWidget(self.raw); tabs.addTab(t1, "Informes automáticos")

        t2 = QWidget(); l2 = QVBoxLayout(t2); l2.setContentsMargins(12, 12, 12, 12); l2.setSpacing(8)
        l2.addWidget(QLabel("Consulta WHOIS manual:"))
        r = QHBoxLayout()
        self.manual_ip = QLineEdit(); self.manual_ip.setPlaceholderText("8.8.8.8")
        qb = _restyle(QPushButton("Ejecutar WHOIS")); qb.clicked.connect(self._manual)
        r.addWidget(self.manual_ip); r.addWidget(qb)
        l2.addLayout(r)
        self.manual_out = QTextEdit(); self.manual_out.setReadOnly(True)
        self.manual_out.setStyleSheet(f"font-family:{FONT}; font-size:11px; background:{BG}; border:1.5px solid {BORDER};")
        l2.addWidget(self.manual_out)
        tabs.addTab(t2, "Consulta manual")

        root.addWidget(tabs); self._cache = []

    def _detail(self, idx):
        r = idx.row()
        if r < len(self._cache):
            self.raw.setPlainText(self._cache[r].get("raw_data", "Sin datos."))

    def _manual(self):
        ip = self.manual_ip.text().strip()
        if not ip: QMessageBox.warning(self, "Error", "Ingresa una IP."); return
        self.manual_out.setPlainText("Consultando WHOIS..."); QApplication.processEvents()
        from core.forensics import ForensicsEngine
        r = ForensicsEngine().investigate(ip, "Consulta manual")
        if r:
            self.manual_out.setPlainText(
                f"Organización : {r.get('org','N/D')}\n"
                f"ASN          : {r.get('asn','N/D')}\n"
                f"País         : {r.get('country','N/D')}\n"
                f"Abuso email  : {r.get('abuse_email','No encontrado')}\n\n"
                f"--- WHOIS completo ---\n{r.get('raw','')}"
            )
        else:
            self.manual_out.setPlainText("Sin resultados. IP privada o inaccesible.")

    def refresh(self):
        self._cache = db.fetch_forensic_reports(limit=50)
        fill_table(self.tbl_r, [
            (r["timestamp"], r["ip"], r["org"] or "—", r["country"] or "—",
             r["asn"] or "—", r["abuse_email"] or "—",
             "Sí" if r["email_sent"] else "No")
            for r in self._cache
        ])


# ════════════════════════════════════════════════════════════════════════
# PÁGINA: CONFIGURACIÓN
# ════════════════════════════════════════════════════════════════════════

class SettingsPage(QWidget):
    def __init__(self):
        super().__init__(); self.setObjectName("Page"); self._auth = False; self._build()

    def _build(self):
        self._stack = QStackedWidget(self)
        lay = QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.addWidget(self._stack)
        self._stack.addWidget(self._login_widget())
        self._stack.addWidget(self._content_widget())

    def _login_widget(self):
        w = QWidget()
        w.setStyleSheet(f"background: {BG};")
        l = QVBoxLayout(w)
        l.setAlignment(Qt.AlignmentFlag.AlignCenter); l.setSpacing(14)

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background: {WHITE}; border-radius: 12px; }}"
        )
        card.setFixedWidth(340)
        card.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)
        cl = QVBoxLayout(card); cl.setContentsMargins(32, 32, 32, 32); cl.setSpacing(14)

        icon = QLabel("🔐")
        icon.setStyleSheet("font-size:36px; background:transparent; border:none;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        t = QLabel("Área Restringida")
        t.setStyleSheet(f"font-size:20px; font-weight:bold; color:{TEXT}; background:transparent; border:none;")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)

        s = QLabel("Autenticación de administrador requerida")
        s.setStyleSheet(f"font-size:11px; color:{MUTED}; background:transparent; border:none;")
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd.setPlaceholderText("Contraseña de administrador")
        self.pwd.setStyleSheet(
            f"background:{WHITE}; color:{TEXT}; border:2px solid {BORDER_LT}; "
            f"border-radius:8px; padding:10px 14px; font-size:12px;"
        )
        self.pwd.returnPressed.connect(self._login)

        lb = QPushButton("  Iniciar sesión")
        lb.setStyleSheet(
            f"QPushButton {{ background:{C_BLUE}; color:#FFFFFF; border:none; "
            f"border-radius:8px; padding:11px 20px; font-size:13px; font-weight:bold; }}"
            f"QPushButton:hover {{ background:#2563EB; }}"
            f"QPushButton:pressed {{ background:#1D4ED8; }}"
        )
        lb.setCursor(Qt.CursorShape.PointingHandCursor)
        lb.clicked.connect(self._login)

        hint = QLabel("Contraseña por defecto: admin123")
        hint.setStyleSheet(
            f"font-size:10px; color:{MUTED}; background:transparent; border:none;"
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        for x in (icon, t, s, self.pwd, lb, hint):
            cl.addWidget(x)

        l.addWidget(card, alignment=Qt.AlignmentFlag.AlignHCenter)
        return w

    def _content_widget(self):
        w = QWidget(); root = QVBoxLayout(w)
        root.setContentsMargins(28, 22, 28, 22); root.setSpacing(12)
        root.addWidget(_page_header("Configuración", "Sesión de administrador activa"))
        lo = _restyle(QPushButton("Cerrar sesión"), "sec")
        lo.setMaximumWidth(130); lo.clicked.connect(self._logout); root.addWidget(lo)
        tabs = QTabWidget()

        # Notificaciones
        tn = QWidget(); fn = QFormLayout(tn); fn.setContentsMargins(16,16,16,16); fn.setSpacing(10)
        self.s_email  = QLineEdit(); self.s_server = QLineEdit()
        self.s_port   = QLineEdit(); self.s_user   = QLineEdit()
        self.s_pass   = QLineEdit(); self.s_pass.setEchoMode(QLineEdit.EchoMode.Password)
        fn.addRow("Email admin:", self.s_email); fn.addRow("Servidor SMTP:", self.s_server)
        fn.addRow("Puerto:", self.s_port);       fn.addRow("Usuario SMTP:", self.s_user)
        fn.addRow("App Password:", self.s_pass)
        brow = QHBoxLayout()
        sn = _restyle(QPushButton("Guardar")); sn.clicked.connect(self._save_notif)
        te = _restyle(QPushButton("Correo de prueba"), "sec"); te.clicked.connect(self._test_email)
        brow.addWidget(sn); brow.addWidget(te); fn.addRow(brow)
        tabs.addTab(tn, "Notificaciones")

        # Motor
        tm = QWidget(); lm = QVBoxLayout(tm); lm.setContentsMargins(16,16,16,16); lm.setSpacing(10)
        self.m_ip = QLabel("—"); self.m_ip.setObjectName("InfoVal")
        self.m_if = QLabel("—"); self.m_if.setObjectName("InfoVal")
        ib = QFrame(); ib.setObjectName("Card")
        ig = QGridLayout(ib); ig.setContentsMargins(12,8,12,8)
        for i,(k,v) in enumerate([("IP local:", self.m_ip),("Interfaz:", self.m_if)]):
            lk = QLabel(k); lk.setObjectName("InfoKey")
            ig.addWidget(lk, i//2, (i%2)*2); ig.addWidget(v, i//2, (i%2)*2+1)
        lm.addWidget(ib)
        ir = QHBoxLayout()
        self.s_iface = QLineEdit(); self.s_iface.setPlaceholderText("dejar vacío para auto-detect")
        ab = _restyle(QPushButton("Auto-detectar"), "sec"); ab.clicked.connect(self._auto_if)
        ir.addWidget(QLabel("Interfaz:")); ir.addWidget(self.s_iface); ir.addWidget(ab)
        lm.addLayout(ir)
        sm = _restyle(QPushButton("Guardar y reiniciar motor")); sm.clicked.connect(self._save_motor)
        lm.addWidget(sm); lm.addStretch()
        tabs.addTab(tm, "Motor IDS")

        # Seguridad
        ts = QWidget(); fs = QFormLayout(ts); fs.setContentsMargins(16,16,16,16); fs.setSpacing(10)
        self.s_op = QLineEdit(); self.s_op.setEchoMode(QLineEdit.EchoMode.Password)
        self.s_np = QLineEdit(); self.s_np.setEchoMode(QLineEdit.EchoMode.Password)
        self.s_cp = QLineEdit(); self.s_cp.setEchoMode(QLineEdit.EchoMode.Password)
        fs.addRow("Contraseña actual:", self.s_op)
        fs.addRow("Nueva contraseña:", self.s_np)
        fs.addRow("Confirmar:", self.s_cp)
        cb = _restyle(QPushButton("Cambiar contraseña")); cb.clicked.connect(self._change_pwd)
        fs.addRow(cb); fs.addRow(hline())
        clr = QPushButton("Eliminar todos los registros de la base de datos")
        _restyle(clr, "danger"); clr.clicked.connect(self._clear_db); fs.addRow(clr)
        tabs.addTab(ts, "Seguridad")

        root.addWidget(tabs); return w

    def _login(self):
        if verify_password(self.pwd.text()):
            self._auth = True; self._load_values(); self._stack.setCurrentIndex(1); self.pwd.clear()
        else:
            QMessageBox.warning(self, "Error", "Contraseña incorrecta.")

    def _logout(self): self._auth = False; self._stack.setCurrentIndex(0)

    def _load_values(self):
        cfg = load_settings(); creds = load_env_credentials()
        self.s_email.setText(cfg.get("admin_email",""))
        self.s_server.setText(cfg.get("smtp_server","smtp.gmail.com"))
        self.s_port.setText(str(cfg.get("smtp_port",587)))
        self.s_user.setText(creds["smtp_user"]); self.s_pass.setText(creds["smtp_password"])
        self.s_iface.setText(cfg.get("network_interface") or "")
        self.m_ip.setText(get_local_ip()); self.m_if.setText(detect_interface() or "N/D")

    def _save_notif(self):
        cfg = load_settings()
        cfg.update({"admin_email": self.s_email.text(), "smtp_server": self.s_server.text(),
                     "smtp_port": int(self.s_port.text() or 587)})
        cfg.pop("smtp_user", None); cfg.pop("smtp_password", None)
        save_settings(cfg); save_env_credentials(self.s_user.text(), self.s_pass.text())
        QMessageBox.information(self, "Guardado", "Configuración guardada.")

    def _test_email(self):
        from utils.emailer import send_whitelist_alert
        cfg = load_settings()
        ok = send_whitelist_alert(get_local_ip(), "test:mac:ids", "IP_NO_AUTORIZADA")
        if ok: QMessageBox.information(self, "Enviado", f"Correo enviado a {cfg.get('admin_email')}.")
        else:  QMessageBox.warning(self, "Error", "No se pudo enviar. Verifica SMTP.")

    def _auto_if(self): self.s_iface.setText(detect_interface() or "")

    def _save_motor(self):
        cfg = load_settings(); cfg["network_interface"] = self.s_iface.text().strip() or None
        save_settings(cfg); reset_sniffer()
        QMessageBox.information(self, "Motor reiniciado", "Inicia el sniffer desde el panel lateral.")

    def _change_pwd(self):
        if not verify_password(self.s_op.text()):
            QMessageBox.warning(self, "Error", "Contraseña actual incorrecta."); return
        if self.s_np.text() != self.s_cp.text():
            QMessageBox.warning(self, "Error", "Las contraseñas no coinciden."); return
        if len(self.s_np.text()) < 6:
            QMessageBox.warning(self, "Error", "Mínimo 6 caracteres."); return
        change_password(self.s_np.text())
        self.s_op.clear(); self.s_np.clear(); self.s_cp.clear()
        QMessageBox.information(self, "Listo", "Contraseña actualizada.")

    def _clear_db(self):
        r = QMessageBox.question(self, "Confirmar",
            "¿Eliminar TODOS los registros? Irreversible.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.Yes:
            import sqlite3
            conn = sqlite3.connect(os.path.join(ROOT, "data", "ids.db"))
            for t in ["whitelist_alerts","site_visits","threat_alerts","forensic_reports"]:
                conn.execute(f"DELETE FROM {t}")
            conn.commit(); conn.close()
            QMessageBox.information(self, "Listo", "Base de datos vaciada.")

    def refresh(self): pass


# ════════════════════════════════════════════════════════════════════════
# VENTANA PRINCIPAL
# ════════════════════════════════════════════════════════════════════════

class IDSApp(QMainWindow):
    # Mapa: (símbolo Unicode, tooltip)
    _NAV = [
        ("⊞", "Dashboard"),
        ("✓", "Módulo 1: Lista Blanca"),
        ("◉", "Módulo 2: Sitios"),
        ("△", "Módulo 3: Amenazas"),
        ("◈", "Módulo 4: Forense"),
        ("⚙", "Configuración"),
    ]

    def __init__(self):
        super().__init__()
        db.init_db()
        self.setWindowTitle("IDS Corporativo")
        self.resize(1200, 760); self.setMinimumSize(980, 640)
        self._pages: list = []
        self._nav_btns: list = []
        self._build_ui()
        self._setup_timer()
        QTimer.singleShot(500, self._startup_check)

    # ── Construcción de UI ────────────────────────────────────────
    def _build_ui(self):
        c = QWidget(); c.setObjectName("Root"); self.setCentralWidget(c)
        m = QHBoxLayout(c); m.setContentsMargins(0,0,0,0); m.setSpacing(0)
        m.addWidget(self._build_sidebar())
        m.addWidget(self._build_content(), stretch=1)

    def _build_sidebar(self):
        sb = QWidget(); sb.setObjectName("Sidebar"); sb.setFixedWidth(62)
        l = QVBoxLayout(sb); l.setContentsMargins(0, 16, 0, 16); l.setSpacing(2)
        l.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Logo
        logo = QLabel("◈")
        logo.setStyleSheet(f"font-size:22px; color:{C_BLUE}; background:transparent; padding: 8px 0 14px 0;")
        logo.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        l.addWidget(logo)
        l.addWidget(self._sep())

        # Botones de navegación
        for sym, tip in self._NAV:
            btn = QPushButton(sym)
            btn.setObjectName("NavBtn")
            btn.setToolTip(tip)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setProperty("active", False)
            btn.clicked.connect(lambda _, i=len(self._nav_btns): self._navigate(i))
            l.addWidget(btn, alignment=Qt.AlignmentFlag.AlignHCenter)
            self._nav_btns.append(btn)

        l.addWidget(self._sep())
        l.addStretch()

        # Motor IDS (mini-controles)
        self.start_btn = _restyle(QPushButton("▶"), "green")
        self.start_btn.setToolTip("Iniciar captura")
        self.start_btn.setFixedSize(50, 34); self.start_btn.clicked.connect(self._start)
        self.stop_btn = _restyle(QPushButton("■"), "stop")
        self.stop_btn.setToolTip("Detener captura")
        self.stop_btn.setFixedSize(50, 34); self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        l.addWidget(self.start_btn, alignment=Qt.AlignmentFlag.AlignHCenter)
        l.addWidget(self.stop_btn,  alignment=Qt.AlignmentFlag.AlignHCenter)

        # Aviso BPF
        self.bpf_lbl = QLabel("")
        self.bpf_lbl.setWordWrap(True)
        self.bpf_lbl.setStyleSheet(
            f"font-size:8px; color:{RED_T}; padding:3px 5px; "
            f"background:#FEE2E2; border:1px solid {RED_T}; margin:2px 4px;"
        )
        self.bpf_lbl.hide(); l.addWidget(self.bpf_lbl)

        self.err_lbl = QLabel("")
        self.err_lbl.setWordWrap(True)
        self.err_lbl.setStyleSheet(
            f"font-size:8px; color:{RED_T}; padding:3px 5px; "
            f"background:#FEE2E2; border:1px solid {RED_T}; margin:2px 4px;"
        )
        self.err_lbl.hide(); l.addWidget(self.err_lbl)

        return sb

    def _build_content(self):
        self._stack = QStackedWidget(); self._stack.setObjectName("Root")
        page_cls = [DashboardPage, WhitelistPage, MonitorPage,
                    ThreatPage, ForensicsPage, SettingsPage]
        for cls in page_cls:
            page = cls()
            scroll = QScrollArea()
            scroll.setWidget(page); scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setStyleSheet(f"background:{BG};")
            self._stack.addWidget(scroll)
            self._pages.append(page)
        self._navigate(0)
        return self._stack

    def _sep(self):
        f = QFrame(); f.setFrameShape(QFrame.Shape.HLine)
        f.setStyleSheet(f"background:{BORDER_LT}; max-height:1px; min-height:1px; margin: 2px 6px;")
        return f

    # ── Navegación ────────────────────────────────────────────────
    def _navigate(self, idx):
        for i, btn in enumerate(self._nav_btns):
            btn.setProperty("active", i == idx)
            btn.style().unpolish(btn); btn.style().polish(btn)
        self._stack.setCurrentIndex(idx)
        self._pages[idx].refresh()

    # ── Sniffer ───────────────────────────────────────────────────
    def _start(self):
        if sys.platform == "darwin" and not check_bpf():
            dlg = BFPDialog(self)
            if dlg.exec() != QDialog.DialogCode.Accepted or not check_bpf():
                QMessageBox.warning(self, "Sin permisos",
                    "Ejecuta en Terminal:\n  sudo chmod o+rw /dev/bpf*\nLuego presiona ▶")
                return
        cfg = load_settings()
        get_sniffer(interface=cfg.get("network_interface") or None).start()
        self._update_motor()
        if sys.platform == "darwin":
            QTimer.singleShot(1500, self._check_bpf_err)

    def _check_bpf_err(self):
        s = get_sniffer()
        if s.last_error and ("bpf" in s.last_error.lower() or "permission" in s.last_error.lower()):
            dlg = BFPDialog(self)
            if dlg.exec() == QDialog.DialogCode.Accepted and check_bpf():
                reset_sniffer()
                get_sniffer(interface=load_settings().get("network_interface") or None).start()
                self._update_motor(); self.bpf_lbl.hide()

    def _stop(self):
        get_sniffer().stop(); self._update_motor()

    def _update_motor(self):
        s = get_sniffer(); running = s.is_running
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        if s.last_error:
            self.err_lbl.setText(s.last_error[:60]); self.err_lbl.show()
        else:
            self.err_lbl.hide()

    # ── Auto-refresh ──────────────────────────────────────────────
    def _setup_timer(self):
        self._tmr = QTimer(self); self._tmr.timeout.connect(self._tick); self._tmr.start(5000)

    def _tick(self):
        self._update_motor()
        idx = self._stack.currentIndex()
        if 0 <= idx < len(self._pages):
            self._pages[idx].refresh()

    def _startup_check(self):
        if sys.platform == "darwin" and not check_bpf():
            self.bpf_lbl.setText("Sin BPF — pulsa ▶"); self.bpf_lbl.show()
        elif sys.platform != "darwin" and os.geteuid() != 0:
            self.bpf_lbl.setText("Usar sudo para captura real"); self.bpf_lbl.show()


# ════════════════════════════════════════════════════════════════════════
# ENTRADA
# ════════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("IDS Corporativo")
    app.setStyleSheet(QSS)
    app.setFont(QFont(FONT, 12))
    window = IDSApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
