# Colega's IDS — Documentación del Sistema

**Sistema de Detección de Intrusos en Python**  
UAA · Ingeniería en Sistemas Computacionales · 8vo Semestre · Seguridad e Integridad de Datos

---

## Índice

1. [Descripción general](#1-descripción-general)
2. [Arquitectura del sistema](#2-arquitectura-del-sistema)
3. [Flujo principal de datos](#3-flujo-principal-de-datos)
4. [Módulos del IDS](#4-módulos-del-ids)
   - [Módulo 1 — Lista Blanca](#módulo-1--lista-blanca-capa-2-y-3)
   - [Módulo 2 — Monitoreo de Sitios](#módulo-2--monitoreo-de-sitios)
   - [Módulo 3 — Inteligencia de Amenazas](#módulo-3--inteligencia-de-amenazas)
   - [Módulo 4 — Automatización Forense](#módulo-4--automatización-forense)
5. [Estructura de archivos](#5-estructura-de-archivos)
6. [Base de datos](#6-base-de-datos)
7. [Sistema de correos electrónicos](#7-sistema-de-correos-electrónicos)
8. [Autenticación del administrador](#8-autenticación-del-administrador)
9. [Instalación y ejecución](#9-instalación-y-ejecución)
10. [Guía de uso paso a paso](#10-guía-de-uso-paso-a-paso)
11. [Resolución de problemas](#11-resolución-de-problemas)

---

## 1. Descripción general

El Colega's IDS es una aplicación de seguridad de red que captura y analiza el tráfico en tiempo real para detectar:

- Dispositivos **no autorizados** que se conectan a la red (intrusión por IP o MAC desconocida)
- Los **sitios web** que visitan los usuarios (HTTP, HTTPS y DNS)
- Conexiones hacia **IPs maliciosas** conocidas (botnet, malware, phishing, etc.)
- Información de **contacto de abuso** del proveedor que hospeda una IP maliciosa (WHOIS forense)

La interfaz gráfica corre en el navegador web mediante **Streamlit** y se actualiza automáticamente cada pocos segundos. El motor de captura usa **Scapy** para interceptar paquetes de red a nivel de sistema operativo.

---

## 2. Arquitectura del sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERFAZ WEB                             │
│                    app.py  (Streamlit)                          │
│   Dashboard │ Lista Blanca │ Sitios │ Amenazas │ Forense │ Config│
└────────────────────────────┬────────────────────────────────────┘
                             │ lee / escribe
              ┌──────────────┼──────────────────┐
              │              │                  │
   ┌──────────▼──────┐  ┌────▼─────┐  ┌────────▼────────┐
   │  core/sniffer   │  │  utils/  │  │  utils/auth.py  │
   │  (hilo daemon)  │  │database  │  │  (contraseñas)  │
   └──┬──────┬───┬───┘  └──────────┘  └─────────────────┘
      │      │   │              ▲
      │      │   │              │ INSERT / SELECT
      ▼      ▼   ▼              │
  whitelist monitor threat  SQLite (data/ids.db)
  .py       .py  _intel.py
      │              │
      │              ▼
      │         forensics.py
      │         (WHOIS / RDAP)
      │
      ▼
  emailer.py  ──► SMTP ──► Correo del administrador
```

### Componentes clave

| Archivo | Rol |
|---|---|
| `app.py` | Interfaz web Streamlit — 6 páginas, auto-refresh, CSS corporativo |
| `core/sniffer.py` | Motor principal — captura paquetes con Scapy en hilo de fondo |
| `core/scanner.py` | Escáner ARP — descubre dispositivos en la red local |
| `core/whitelist.py` | Módulo 1 — valida IPs y MACs contra la lista autorizada |
| `core/monitor.py` | Módulo 2 — registra dominios visitados |
| `core/threat_intel.py` | Módulo 3 — compara IPs contra lista negra de amenazas |
| `core/forensics.py` | Módulo 4 — consulta WHOIS y extrae contacto de abuso |
| `utils/database.py` | SQLite thread-safe — 4 tablas de eventos |
| `utils/emailer.py` | Plantillas HTML y envío de correos via SMTP |
| `utils/auth.py` | Hash de contraseña con PBKDF2-SHA256 |

---

## 3. Flujo principal de datos

```
RED LOCAL
    │
    │  (todos los paquetes IP/ARP de la interfaz de red)
    ▼
┌─────────────────────────────────────────────────────┐
│  Scapy  sniff()  — hilo daemon "ids-sniffer"        │
│                                                     │
│  Por cada paquete recibido:                         │
│                                                     │
│  1. Extrae:  src_ip, dst_ip, src_mac                │
│                                                     │
│  2. ┌─────────────────────────────────┐             │
│     │ ¿src_ip está en whitelist?      │             │
│     │  NO → alerta + correo Módulo 1  │             │
│     └─────────────────────────────────┘             │
│                                                     │
│  3. ┌─────────────────────────────────┐             │
│     │ ¿dst_ip está en blacklist?      │             │
│     │  SÍ → alerta + correo Módulo 3  │             │
│     │       + lanza WHOIS (Módulo 4)  │             │
│     └─────────────────────────────────┘             │
│                                                     │
│  4. ┌─────────────────────────────────┐             │
│     │ ¿UDP puerto 53?   → DNS query   │             │
│     │ ¿TCP puerto 80?   → HTTP Host   │ Módulo 2    │
│     │ ¿TCP puerto 443?  → TLS SNI     │             │
│     │  → registra dominio en BD       │             │
│     └─────────────────────────────────┘             │
└─────────────────────────────────────────────────────┘
    │
    ▼
SQLite (data/ids.db)
    │
    ▼
Streamlit auto-refresh cada 5-10 s
    │
    ▼
Visualización en el navegador
```

### Patrón Singleton del sniffer

Streamlit recarga el script Python en cada interacción del usuario. Para evitar crear múltiples instancias del sniffer, se usa un **Singleton global**:

```python
_instance = None                     # Variable de módulo (persiste entre reruns)

def get_sniffer(interface=None):
    global _instance
    with _instance_lock:             # Thread-safe
        if _instance is None:
            _instance = PacketSniffer(interface)
        return _instance             # Siempre la misma instancia
```

---

## 4. Módulos del IDS

### Módulo 1 — Lista Blanca (Capa 2 y 3)

**Archivo:** `core/whitelist.py`  
**Puntos:** 15

**Funcionamiento:**

```
Paquete recibido
      │
      ▼
¿src_ip es de red local (192.168.x, 10.x, 172.16-31.x)?
      │
      ├─ NO → ignorar (IPs externas no se validan contra whitelist)
      │
      └─ SÍ →
            ┌─────────────────────────────────┐
            │ ¿src_ip está en authorized_ips? │
            │  NO → registrar en BD           │
            │       → enviar correo de alerta │
            └─────────────────────────────────┘
            ┌─────────────────────────────────┐
            │ ¿src_mac está en authorized_macs│
            │  NO → registrar en BD           │
            │       → enviar correo de alerta │
            └─────────────────────────────────┘
```

**Anti-spam (cooldown):** Un diccionario en memoria registra la última vez que se envió alerta para cada IP/MAC. Si han pasado menos de 60 segundos, no se envía otro correo.

**Cómo agregar dispositivos:**
- **Manual:** Módulo 1 → Gestionar lista blanca → editar texto → Guardar
- **Automático:** Módulo 1 → Escanear red local → seleccionar dispositivos → Agregar

**Archivo de configuración:** `config/whitelist.json`

---

### Módulo 2 — Monitoreo de Sitios

**Archivo:** `core/monitor.py`  
**Puntos:** 10

**Protocolos monitoreados:**

| Protocolo | Puerto | Técnica |
|---|---|---|
| DNS | UDP 53 | Decodifica el campo `DNSQR.qname` de la query DNS |
| HTTP | TCP 80, 8080 | Extrae el encabezado `Host:` del payload raw |
| HTTPS | TCP 443 | Parsea el `Server Name Indication` del TLS Client Hello |

**Extracción de SNI en TLS:**  
El campo SNI está en el primer mensaje del handshake TLS (`ClientHello`). El código navega los bytes del paquete: cabecera TLS (5 bytes) → tipo de handshake → versión → random → session ID → cipher suites → extensiones → busca la extensión tipo `0x0000` (server_name) y extrae el hostname.

**De-duplicación:** Para no llenar la base de datos, la misma combinación IP+dominio no se registra más de una vez por minuto.

**Visualización:** Bitácora ordenada por tiempo + gráfica de barras horizontales de dominios más visitados.

---

### Módulo 3 — Inteligencia de Amenazas

**Archivo:** `core/threat_intel.py`  
**Puntos:** 15

**Funcionamiento:**

```
Por cada paquete:
      │
      ├─ ¿dst_ip está en blacklist? → amenaza saliente
      └─ ¿src_ip está en blacklist? → amenaza entrante
                │
                ▼
         ¿Alerta enviada en los últimos 120 s? (cooldown)
                │
                ├─ SÍ → ignorar (anti-spam)
                │
                └─ NO →
                      ├─ INSERT en threat_alerts
                      ├─ send_threat_alert() via SMTP
                      └─ Thread separado → Módulo 4 (WHOIS)
```

**Lista negra:** `config/blacklist.json` — formato JSON con campos:
- `ip`: dirección IPv4
- `threat_type`: tipo (Botnet C2, Phishing, Malware, etc.)
- `risk_level`: Critico / Alto / Medio
- `description`: descripción del comportamiento
- `source`: referencia o URL de origen
- `reported`: fecha de adición

**Cómo poblar la lista negra:**
1. **Manual:** Módulo 3 → Lista negra activa → formulario de agregar IP
2. **Desde feed URL:** Módulo 3 → Importar threat feed → ingresar URL

**Fuentes recomendadas:**
- `feodotracker.abuse.ch/downloads/ipblocklist.txt` — Botnet C2
- `rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt` — Múltiple
- `bazaar.abuse.ch/export/txt/ipblocklist/recent/` — Malware reciente

---

### Módulo 4 — Automatización Forense

**Archivo:** `core/forensics.py`  
**Puntos:** 15

**Flujo:**

```
Módulo 3 detecta amenaza
      │
      └─ threading.Thread(target=_run_forensics) ← hilo separado (no bloquea el sniffer)
                │
                ▼
         ForensicsEngine.investigate(ip)
                │
                ├─ 1er intento: ipwhois (RDAP)
                │       ├─ IPWhois(ip).lookup_rdap(depth=1)
                │       ├─ Extrae: asn, org, country
                │       └─ Busca entidad con role="abuse" → abuse_email, abuse_phone
                │
                └─ Fallback: RDAP público ARIN (urllib, sin dependencias extra)
                        └─ https://rdap.arin.net/registry/ip/{ip}

                │
                ▼
         INSERT en forensic_reports
                │
                ▼
         send_forensic_report() → correo HTML con datos WHOIS completos
```

**¿Por qué un hilo separado?**  
Las consultas WHOIS/RDAP tardan entre 2 y 10 segundos. Si se ejecutaran en el hilo del sniffer, se perderían paquetes durante ese tiempo. El hilo secundario permite que la captura continúe sin interrupción.

---

## 5. Estructura de archivos

```
proyectoIDS/
│
├── app.py                    ← Interfaz web Streamlit (punto de entrada)
├── requirements.txt          ← Dependencias Python
│
├── .streamlit/
│   └── config.toml           ← Tema visual: fondo blanco, azul #2563EB
│
├── config/
│   ├── whitelist.json        ← IPs y MACs autorizadas
│   ├── blacklist.json        ← IPs maliciosas + fuentes recomendadas
│   └── settings.json         ← SMTP, interfaz de red, hash de contraseña
│
├── core/
│   ├── __init__.py
│   ├── sniffer.py            ← Motor: captura Scapy + Singleton
│   ├── scanner.py            ← Escáner ARP de la red local
│   ├── whitelist.py          ← Módulo 1: validación IP/MAC
│   ├── monitor.py            ← Módulo 2: registro de dominios
│   ├── threat_intel.py       ← Módulo 3: lista negra + alertas
│   └── forensics.py          ← Módulo 4: WHOIS + contacto de abuso
│
├── utils/
│   ├── __init__.py
│   ├── database.py           ← SQLite thread-safe (4 tablas)
│   ├── emailer.py            ← Plantillas HTML + smtplib STARTTLS
│   └── auth.py               ← PBKDF2-SHA256 para contraseña admin
│
└── data/
    ├── ids.db                ← Base de datos SQLite (se crea automáticamente)
    └── logs/
        └── ids.log           ← Log del sistema (se crea automáticamente)
```

---

## 6. Base de datos

**Motor:** SQLite con modo WAL (Write-Ahead Logging) para acceso concurrente seguro.  
**Ubicación:** `data/ids.db` — se crea automáticamente al iniciar la app.

### Tablas

#### `whitelist_alerts`
| Campo | Tipo | Descripción |
|---|---|---|
| id | INTEGER | Clave primaria autoincremental |
| timestamp | TEXT | Fecha y hora del evento |
| src_ip | TEXT | IP de origen detectada |
| src_mac | TEXT | MAC de origen detectada |
| alert_type | TEXT | `IP_NO_AUTORIZADA` o `MAC_NO_AUTORIZADA` |
| detail | TEXT | Información adicional |
| email_sent | INTEGER | 0 = no enviado, 1 = enviado |

#### `site_visits`
| Campo | Tipo | Descripción |
|---|---|---|
| id | INTEGER | Clave primaria |
| timestamp | TEXT | Fecha y hora |
| src_ip | TEXT | IP del equipo que visitó el sitio |
| domain | TEXT | Dominio visitado (ej: `google.com`) |
| protocol | TEXT | `DNS`, `HTTP`, `GET`, `HTTPS` |

#### `threat_alerts`
| Campo | Tipo | Descripción |
|---|---|---|
| id | INTEGER | Clave primaria |
| timestamp | TEXT | Fecha y hora |
| src_ip | TEXT | IP de la máquina en la red interna |
| dst_ip | TEXT | IP maliciosa detectada |
| threat_type | TEXT | Tipo de amenaza |
| risk_level | TEXT | Critico / Alto / Medio |
| description | TEXT | Descripción de la amenaza |
| email_sent | INTEGER | 1 si se envió correo |
| whois_done | INTEGER | 1 si se completó el análisis forense |

#### `forensic_reports`
| Campo | Tipo | Descripción |
|---|---|---|
| id | INTEGER | Clave primaria |
| timestamp | TEXT | Fecha del informe |
| ip | TEXT | IP investigada |
| asn | TEXT | Sistema autónomo (ej: `AS15169`) |
| org | TEXT | Organización propietaria |
| country | TEXT | País de origen |
| abuse_email | TEXT | Correo de contacto para reporte de abuso |
| abuse_phone | TEXT | Teléfono de abuso (si existe) |
| raw_data | TEXT | JSON completo del WHOIS/RDAP |
| email_sent | INTEGER | 1 si se envió el reporte |

### Thread-safety

Cada hilo del sistema (sniffer, forense, UI de Streamlit) crea su propia conexión SQLite usando `threading.local()`. Esto evita conflictos entre hilos sin necesidad de un lock explícito en cada operación.

---

## 7. Sistema de correos electrónicos

**Protocolo:** SMTP con STARTTLS (encriptación en tránsito)  
**Librería:** `smtplib` (estándar de Python, sin dependencias adicionales)

### Tipos de correo

#### Alerta de Lista Blanca (Módulo 1)
- **Asunto:** `[IDS] Alerta: Dispositivo no autorizado — {IP}`
- **Color del encabezado:** Naranja (#D97706)
- **Contenido:** IP, MAC, timestamp, tipo de alerta
- **Cuándo:** Primera vez que se detecta la IP/MAC (luego cooldown de 60 s)

#### Alerta de Emergencia (Módulo 3)
- **Asunto:** `[IDS] EMERGENCIA: {tipo} — IP {IP maliciosa}`
- **Color del encabezado:** Rojo (#DC2626)
- **Contenido:** IP origen, IP maliciosa, tipo de amenaza, nivel de riesgo, descripción
- **Cuándo:** Al detectar conexión hacia IP en lista negra (cooldown de 120 s)

#### Informe Forense (Módulo 4)
- **Asunto:** `[IDS] Informe Forense: {IP} ({Organización})`
- **Color del encabezado:** Azul corporativo (#2563EB)
- **Contenido:** ASN, organización, país, contacto de abuso, datos WHOIS completos
- **Cuándo:** Automáticamente después de cada alerta del Módulo 3

### Configuración para Gmail

1. Activar **Verificación en 2 pasos** en tu cuenta Google
2. Ir a `myaccount.google.com/apppasswords`
3. Crear una App Password para "Correo" + "Otro dispositivo"
4. En la app: **Configuración → Notificaciones** → ingresar:
   - Servidor: `smtp.gmail.com`
   - Puerto: `587`
   - Usuario: `tu_correo@gmail.com`
   - Contraseña: la App Password generada (16 caracteres)

---

## 8. Autenticación del administrador

**Algoritmo:** PBKDF2-SHA256 con 100,000 iteraciones  
**Sal:** Cadena fija configurada en `settings.json`

```
Contraseña ingresada
       │
       ▼
hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000)
       │
       ▼
Comparar hex resultante con admin_password_hash en settings.json
       │
       ├─ Igual → acceso concedido
       └─ Diferente → acceso denegado
```

**Contraseña por defecto:** `admin123`  
**Cambio obligatorio:** Configuración → Seguridad → Cambiar contraseña

La contraseña nunca se almacena en texto plano. Solo el hash se guarda en `config/settings.json`.

---

## 9. Instalación y ejecución

### Requisitos del sistema

- Python 3.10 o superior
- Linux, macOS o Windows
- Permisos de administrador/root para captura de paquetes
- Conexión a internet (para consultas WHOIS y descarga de feeds)

### Instalación

```bash
# 1. Navegar al directorio del proyecto
cd proyectoIDS

# 2. Crear entorno virtual (aísla las dependencias del sistema)
python3 -m venv venv

# 3. Activar el entorno virtual
#    Linux / macOS:
source venv/bin/activate
#    Windows (PowerShell):
venv\Scripts\Activate.ps1

# 4. Instalar todas las dependencias
pip install -r requirements.txt
```

### Ejecución

#### Linux / macOS (requiere sudo para captura de paquetes)

```bash
sudo venv/bin/streamlit run app.py
```

#### Windows (abrir terminal como Administrador)

```powershell
venv\Scripts\streamlit.exe run app.py
```

La aplicación abre automáticamente en `http://localhost:8501`

#### Detener la aplicación

```
Ctrl + C  en la terminal
```

### Dependencias (`requirements.txt`)

| Paquete | Versión mínima | Uso |
|---|---|---|
| streamlit | 1.28.0 | Interfaz web |
| streamlit-autorefresh | 1.0.1 | Auto-actualización de la UI |
| scapy | 2.5.0 | Captura y análisis de paquetes |
| ipwhois | 1.2.0 | Consultas WHOIS / RDAP |
| pandas | 2.0.0 | Manejo de tablas de datos |
| plotly | 5.17.0 | Gráfica de dominios visitados |
| requests | 2.31.0 | Descarga de feeds de threat intel |

---

## 10. Guía de uso paso a paso

### Primera vez

1. **Abrir la app** en `http://localhost:8501`
2. **Configurar correo** (opcional pero recomendado):
   - Ir a `Configuración` → contraseña `admin123`
   - Tab `Notificaciones` → ingresar email y configuración SMTP
3. **Poblar la lista blanca**:
   - `Módulo 1: Lista Blanca` → `Escanear red local`
   - Seleccionar todos los dispositivos conocidos → `Agregar seleccionados`
4. **Poblar la lista negra**:
   - `Módulo 3: Amenazas` → `Importar threat feed`
   - Ingresar URL de Feodo Tracker → `Importar desde URL`
5. **Iniciar el motor IDS**:
   - En el panel lateral → botón `Iniciar`
6. **Monitorear** en el Dashboard — se actualiza cada 6 segundos

### Uso diario

- **Dashboard:** Vista general de alertas y dominios
- **Módulo 1:** Ver dispositivos no autorizados detectados
- **Módulo 2:** Revisar qué sitios visitan los usuarios
- **Módulo 3:** Ver si algún equipo contactó IPs maliciosas
- **Módulo 4:** Revisar informes WHOIS para reportar al proveedor

### Actualizar la lista negra

```
Módulo 3 → Importar threat feed → pegar nueva URL → Importar desde URL
```

Las IPs duplicadas se detectan automáticamente y no se agregan dos veces.

---

## 11. Resolución de problemas

### Error: "Privilegios insuficientes"

La captura de paquetes a nivel de red requiere permisos especiales.

```bash
# Solución en Linux/macOS:
sudo venv/bin/streamlit run app.py

# Solución en Windows:
# Clic derecho en la terminal → "Ejecutar como administrador"
```

### El sniffer inicia pero no captura nada

Puede ser que la interfaz configurada no sea la correcta.

```
Configuración → Motor IDS → "Usar interfaz auto-detectada" → Guardar y reiniciar motor
```

Luego reiniciar el sniffer desde el panel lateral.

### Error de correo: "Authentication failed"

Para Gmail, no se puede usar la contraseña normal. Se necesita una **App Password**:
1. Activar verificación en 2 pasos en Google
2. Generar App Password en `myaccount.google.com/apppasswords`
3. Usar esa contraseña de 16 caracteres en la configuración SMTP

### La lista negra está vacía

La lista negra comienza vacía intencionalmente. Debe poblarse con datos reales:

```
Módulo 3 → Importar threat feed → https://feodotracker.abuse.ch/downloads/ipblocklist.txt
```

### Error: "No module named 'scapy'"

El entorno virtual no está activo o las dependencias no se instalaron:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Los dominios HTTPS no aparecen en el monitoreo

El sistema extrae el SNI del `TLS ClientHello` solo cuando el tráfico HTTPS pasa por la misma interfaz que está siendo capturada. Si el tráfico está encriptado de extremo a extremo y no pasa por el gateway capturado, no será visible. El DNS sí captura el dominio en la mayoría de los casos.

---

*Documentación generada para el proyecto Colega's IDS — UAA ISC 2026*
