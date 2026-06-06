"""
SQLite database manager — thread-safe, singleton por ruta.
"""
import sqlite3
import threading
import os
from datetime import datetime

_local = threading.local()

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ids.db")


def _get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS whitelist_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT,
            src_mac     TEXT,
            alert_type  TEXT    NOT NULL,
            detail      TEXT,
            email_sent  INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS site_visits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            domain      TEXT    NOT NULL,
            protocol    TEXT    DEFAULT 'DNS'
        );

        CREATE TABLE IF NOT EXISTS threat_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT    NOT NULL,
            threat_type TEXT    NOT NULL,
            risk_level  TEXT    NOT NULL,
            description TEXT,
            email_sent  INTEGER DEFAULT 0,
            whois_done  INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS forensic_reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            asn         TEXT,
            org         TEXT,
            country     TEXT,
            abuse_email TEXT,
            abuse_phone TEXT,
            raw_data    TEXT,
            email_sent  INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_site_visits_domain    ON site_visits(domain);
        CREATE INDEX IF NOT EXISTS idx_threat_alerts_dst_ip  ON threat_alerts(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_forensic_ip           ON forensic_reports(ip);
    """)
    conn.commit()


def insert_whitelist_alert(src_ip, src_mac, alert_type, detail=""):
    conn = _get_conn()
    ts = datetime.now().isoformat(sep=" ", timespec="seconds")
    cur = conn.execute(
        "INSERT INTO whitelist_alerts (timestamp, src_ip, src_mac, alert_type, detail) VALUES (?,?,?,?,?)",
        (ts, src_ip, src_mac, alert_type, detail)
    )
    conn.commit()
    return cur.lastrowid


def mark_whitelist_email_sent(row_id):
    conn = _get_conn()
    conn.execute("UPDATE whitelist_alerts SET email_sent=1 WHERE id=?", (row_id,))
    conn.commit()


def insert_site_visit(src_ip, domain, protocol):
    conn = _get_conn()
    ts = datetime.now().isoformat(sep=" ", timespec="seconds")
    conn.execute(
        "INSERT INTO site_visits (timestamp, src_ip, domain, protocol) VALUES (?,?,?,?)",
        (ts, src_ip, domain, protocol)
    )
    conn.commit()


def insert_threat_alert(src_ip, dst_ip, threat_type, risk_level, description=""):
    conn = _get_conn()
    ts = datetime.now().isoformat(sep=" ", timespec="seconds")
    cur = conn.execute(
        """INSERT INTO threat_alerts
           (timestamp, src_ip, dst_ip, threat_type, risk_level, description)
           VALUES (?,?,?,?,?,?)""",
        (ts, src_ip, dst_ip, threat_type, risk_level, description)
    )
    conn.commit()
    return cur.lastrowid


def mark_threat_email_sent(row_id):
    conn = _get_conn()
    conn.execute("UPDATE threat_alerts SET email_sent=1 WHERE id=?", (row_id,))
    conn.commit()


def mark_threat_whois_done(row_id):
    conn = _get_conn()
    conn.execute("UPDATE threat_alerts SET whois_done=1 WHERE id=?", (row_id,))
    conn.commit()


def insert_forensic_report(ip, asn, org, country, abuse_email, abuse_phone, raw_data):
    conn = _get_conn()
    ts = datetime.now().isoformat(sep=" ", timespec="seconds")
    cur = conn.execute(
        """INSERT INTO forensic_reports
           (timestamp, ip, asn, org, country, abuse_email, abuse_phone, raw_data)
           VALUES (?,?,?,?,?,?,?,?)""",
        (ts, ip, asn, org, country, abuse_email, abuse_phone, raw_data)
    )
    conn.commit()
    return cur.lastrowid


def mark_forensic_email_sent(row_id):
    conn = _get_conn()
    conn.execute("UPDATE forensic_reports SET email_sent=1 WHERE id=?", (row_id,))
    conn.commit()


def fetch_whitelist_alerts(limit=100):
    conn = _get_conn()
    cur = conn.execute(
        "SELECT * FROM whitelist_alerts ORDER BY id DESC LIMIT ?", (limit,)
    )
    return [dict(r) for r in cur.fetchall()]


def fetch_site_visits(limit=200):
    conn = _get_conn()
    cur = conn.execute(
        "SELECT * FROM site_visits ORDER BY id DESC LIMIT ?", (limit,)
    )
    return [dict(r) for r in cur.fetchall()]


def fetch_top_domains(limit=20):
    conn = _get_conn()
    cur = conn.execute(
        """SELECT domain, COUNT(*) as visits, MAX(timestamp) as last_seen
           FROM site_visits GROUP BY domain ORDER BY visits DESC LIMIT ?""",
        (limit,)
    )
    return [dict(r) for r in cur.fetchall()]


def fetch_threat_alerts(limit=100):
    conn = _get_conn()
    cur = conn.execute(
        "SELECT * FROM threat_alerts ORDER BY id DESC LIMIT ?", (limit,)
    )
    return [dict(r) for r in cur.fetchall()]


def fetch_forensic_reports(limit=50):
    conn = _get_conn()
    cur = conn.execute(
        "SELECT * FROM forensic_reports ORDER BY id DESC LIMIT ?", (limit,)
    )
    return [dict(r) for r in cur.fetchall()]


def get_stats():
    conn = _get_conn()
    stats = {}
    for key in ["whitelist_alerts", "site_visits", "threat_alerts", "forensic_reports"]:
        row = conn.execute(f"SELECT COUNT(*) as n FROM {key}").fetchone()
        stats[key] = row["n"]
    # Escaneos de puertos (subconjunto de threat_alerts)
    row = conn.execute(
        "SELECT COUNT(*) as n FROM threat_alerts WHERE threat_type='PORT_SCAN'"
    ).fetchone()
    stats["port_scans"] = row["n"]
    return stats


def fetch_monthly_stats(months=8):
    """
    Retorna estadísticas mensuales de alertas para la gráfica dual.
    Resultado: lista de dicts con keys: label, whitelist, threats.
    """
    conn = _get_conn()
    cur = conn.execute("""
        SELECT month,
               SUM(wl) AS whitelist,
               SUM(th) AS threats
        FROM (
            SELECT strftime('%Y-%m', timestamp) AS month, 1 AS wl, 0 AS th
            FROM whitelist_alerts
            UNION ALL
            SELECT strftime('%Y-%m', timestamp) AS month, 0 AS wl, 1 AS th
            FROM threat_alerts
        )
        GROUP BY month
        ORDER BY month ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    # Tomar los últimos N meses
    rows = rows[-months:] if len(rows) > months else rows
    # Formatear etiqueta del mes: "2025-06" → "Jun"
    import calendar
    result = []
    for r in rows:
        try:
            y, m = r["month"].split("-")
            label = calendar.month_abbr[int(m)]
        except Exception:
            label = r["month"]
        result.append({
            "label":     label,
            "whitelist": r["whitelist"],
            "threats":   r["threats"],
        })
    return result
