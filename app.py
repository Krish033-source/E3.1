import os, re, json, time, secrets, threading, html
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
import requests
from flask import Flask, request, g, jsonify, Response, send_from_directory, abort
from werkzeug.middleware.proxy_fix import ProxyFix

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.getenv("TRUST_PROXY", 1)), x_proto=1)

DATA = os.path.join(BASE, "data"); os.makedirs(DATA, exist_ok=True)
FILE = os.path.join(DATA, "visits.jsonl")
LOCK = threading.Lock()
V = OrderedDict(); HITS = {}; FP = {}; GEO = {}
# IPs that hit a trap endpoint before any /d.js-backed visit record existed
# (e.g. a scraper that goes straight for /trap/ai with no prior page load).
TRAP_IPS = {}

def save(v):
    with LOCK, open(FILE, "a") as f: f.write(json.dumps(v) + "\n")
try:
    for l in open(FILE):
        try: o = json.loads(l); V[o["id"]] = o
        except Exception: pass
except FileNotFoundError: pass

AI_UA = re.compile(r"GPTBot|ChatGPT|OAI-SearchBot|OpenAI|ClaudeBot|Claude-User|Claude-SearchBot|Claude-Web|anthropic|PerplexityBot|Perplexity|Google-Extended|Google-CloudVertexBot|Gemini|Bytespider|CCBot|Amazonbot|Applebot-Extended|cohere|Meta-ExternalAgent|meta-externalfetcher|MistralAI|DuckAssistBot|YouBot|Diffbot|ImagesiftBot|Timpibot|AI2Bot|Manus|browser-use|Operator", re.I)
SCRAPER_UA = re.compile(r"curl|wget|python|requests|aiohttp|httpx|urllib|scrapy|axios|node-fetch|undici|got/|go-http|java/|okhttp|libwww|php|ruby|perl|httpclient|colly|jsdom|cheerio|phantom|crawler|spider|scraper|\bbot\b", re.I)
PLAT = {"Windows": "Windows", "macOS": "Macintosh", "Android": "Android", "iOS": "iPhone|iPad", "Linux": "Linux|X11", "Chrome OS": "CrOS"}
KEEP = ["accept","accept-language","accept-encoding","referer","sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-user","sec-ch-ua","sec-ch-ua-platform","sec-ch-ua-mobile","upgrade-insecure-requests","signature-agent","signature-input","cf-ipcountry","cf-bot-score","cf-ja3-hash","x-forwarded-for"]

def ip_of():
    if os.getenv("CF") and request.headers.get("cf-connecting-ip"): return request.headers["cf-connecting-ip"]
    return (request.remote_addr or "").replace("::ffff:", "")

def lookup(ip):
    if ip in GEO: return GEO[ip]
    if not ip or re.match(r"^(::1|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", ip): return {"local": True}
    try:
        j = requests.get(f"http://ip-api.com/json/{ip}", timeout=2.5,
            params={"fields": "status,country,city,timezone,isp,org,as,mobile,proxy,hosting"}).json()
        GEO[ip] = j; return j
    except Exception: return {}

def bg_geo(v):
    def run(): v["geo"] = lookup(v["ip"]); save(v)
    threading.Thread(target=run, daemon=True).start()

def mk():
    ip, t = ip_of(), int(time.time() * 1000)
    a = [x for x in HITS.get(ip, []) if t - x < 60000] + [t]; HITS[ip] = a
    h = {k: request.headers[k][:200] for k in KEEP if request.headers.get(k)}
    v = {"id": secrets.token_hex(6), "t": t, "ip": ip, "path": request.full_path.rstrip("?")[:200],
         "ua": request.headers.get("User-Agent", ""), "h": h, "https": request.is_secure,
         "rate": len(a), "traps": [], "js": False}
    if ip in TRAP_IPS:
        v["traps"].extend(TRAP_IPS[ip])
    V[v["id"]] = v
    if len(V) > 5000: V.popitem(last=False)
    bg_geo(v); return v

@app.after_request
def cookie(r):
    v = getattr(g, "visit", None)
    if v: r.set_cookie("vid", v["id"], max_age=3600, samesite="Lax")
    return r

@app.get("/d.js")
def djs(): return send_from_directory(os.path.join(BASE, "public"), "d.js")

@app.post("/api/collect")
def collect():
    b = request.get_json(force=True, silent=True) or {}
    v = V.get(b.get("vid"))
    if not v or v["ip"] != ip_of(): return "", 204      # same-IP check vs forged beacons
    v["js"] = True; v["env"] = v.get("env") or b.get("env"); v["beh"] = b.get("beh"); v["beat"] = int(time.time() * 1000)
    fp = (b.get("env") or {}).get("fp")
    if fp: FP.setdefault(fp, set()).add(v["ip"]); v["fpIps"] = len(FP[fp])
    if b.get("final") or not v.get("saved"): v["saved"] = True; save(v)
    return "", 204

def classify(v):
    R = []; s = {"sc": 0, "au": 0, "ai": 0}
    def add(k, p, w): s[k] += p; R.append(w)
    h = v.get("h") or {}; ua = v.get("ua") or ""; e = v.get("env") or {}; b = v.get("beh"); age = time.time() * 1000 - v["t"]
    geo = v.get("geo") or {}; traps = v.get("traps", [])
    def out(label, conf, why=None):
        return {"label": label, "conf": max(1, min(99, round(conf))), "reasons": why if why is not None else R,
                "score": {"scraper": s["sc"], "automation": s["au"], "behavior": s["ai"]}}
    m = AI_UA.search(ua)
    if m: return out("AI Agent", 99, ["Declared AI crawler/agent UA: " + m.group(0)])
    if h.get("signature-agent") or h.get("signature-input"): return out("AI Agent", 97, ["Signed bot request (Web Bot Auth)"])
    if "ai" in traps: return out("AI Agent", 96, ["Followed hidden AI-only instruction trap"])
    # ---- HTTP layer
    if not ua: add("sc", 60, "No User-Agent")
    if SCRAPER_UA.search(ua): add("sc", 70, "HTTP-library/crawler UA")
    if "Mozilla/5.0" in ua:
        if not h.get("accept-language"): add("sc", 25, "Missing Accept-Language")
        if not h.get("sec-fetch-mode"): add("sc", 25, "Missing Sec-Fetch-* (not a real browser navigation)")
        if "Chrome/" in ua and v.get("https") and not h.get("sec-ch-ua"): add("sc", 15, "Chrome UA without client hints")
        pl = h.get("sec-ch-ua-platform", "").replace('"', "")
        if pl in PLAT and not re.search(PLAT[pl], ua): add("sc", 30, "UA OS ≠ Sec-CH-UA-Platform")
    if v.get("rate", 0) > 30: add("sc", 30, f"High request rate ({v['rate']}/min)")
    if "link" in traps: add("sc", 60, "Followed hidden crawler-trap link")
    if geo.get("hosting"): add("au", 15, f"Datacenter/hosting IP ({geo.get('isp','')})")
    if geo.get("proxy"): add("au", 8, "Proxy/VPN/Tor IP")
    if not v.get("js"):
        if s["sc"] >= 50 or age > 8000: return out("Web Scraper", 60 + min(s["sc"], 39), R + ["No JavaScript executed"])
        return out("Pending", 0, ["Waiting for JS beacon"])
    # ---- Browser environment
    chromium = "Chrome/" in ua; desktop = not re.search(r"Mobile|Android|iPhone|iPad", ua)
    plat = e.get("plat") or ""; win = e.get("win") or []; scr = e.get("scr") or []
    if e.get("ua") and e["ua"] != ua: add("au", 40, "JS UA ≠ HTTP UA (spoofed header)")
    if e.get("wd"): add("au", 60, "navigator.webdriver = true")
    if re.search("Headless", (e.get("ua") or "") + (e.get("brands") or ""), re.I): add("au", 60, "HeadlessChrome")
    if e.get("auto"): add("au", 60, "Automation globals: " + ",".join(e["auto"]))
    if e.get("cdp"): add("au", 25, "CDP/DevTools protocol attached")
    if re.search(r"swiftshader|llvmpipe|software|offscreen", e.get("gl") or "", re.I): add("au", 30, "Software WebGL: " + str(e.get("gl")))
    if e.get("gl") is None: add("au", 10, "WebGL unavailable")
    if e.get("tamper"): add("au", 40, "Navigator props overridden: " + ",".join(e["tamper"]))
    if e.get("nonNative"): add("au", 35, "Patched native functions (stealth plugin)")
    if chromium and not e.get("chrome"): add("au", 20, "Chrome UA but no window.chrome")
    if chromium and desktop and e.get("plugins") == 0: add("au", 15, "No plugins on desktop Chrome")
    if not e.get("langs"): add("au", 25, "Empty navigator.languages")
    bw = (b or {}).get("win") or win
    if len(bw) >= 4 and (bw[2] == 0 or bw[3] == 0) and (b or {}).get("vis", "visible") == "visible": add("au", 10, "outerWidth/Height = 0")
    n = e.get("notif")
    if n and n[0] == "denied" and n[1] == "prompt": add("au", 25, "Notification permission inconsistency (headless)")
    if e.get("rtt") == 0: add("au", 10, "connection.rtt = 0")
    if not desktop and e.get("tp") == 0: add("au", 20, "Mobile UA but no touch support")
    if ("Windows" in ua and plat and "win" not in plat.lower()) or ("Macintosh" in ua and plat and "mac" not in plat.lower()):
        add("au", 30, "UA OS ≠ navigator.platform")
    if len(scr) >= 2 and scr[0] == 800 and scr[1] == 600: add("au", 10, "Default 800x600 screen")
    if v.get("fpIps", 0) >= 5: add("au", 30, f"Same fingerprint from {v['fpIps']} IPs")
    if geo.get("timezone") and e.get("tz") and geo["timezone"].split("/")[0] != e["tz"].split("/")[0]: add("au", 5, "Browser timezone ≠ IP region")
    # ---- Behaviour
    if b:
        g_ = lambda k: b.get(k) or 0
        c = g_("clicks"); kc = b.get("keyCV"); gc = b.get("gapCV")
        if g_("untrusted"): add("ai", 60, "Synthetic (untrusted) events")
        if g_("noMove"): add("ai", 25, f"{b['noMove']} click(s) with no preceding mouse movement (teleport)")
        if c and g_("center") >= max(1, c * .6): add("ai", 20, "Clicks land on exact element center")
        if g_("mv") > 5 and g_("screenEq") / g_("mv") > .8: add("ai", 25, "screenX==clientX (CDP-dispatched mouse)")
        if g_("jumps") > 1: add("ai", 15, f"Mouse teleports ({b['jumps']})")
        if g_("inputNoKey"): add("ai", 30, "Text inserted without keystrokes")
        if kc is not None and kc < .15: add("ai", 25, "Machine-regular typing rhythm")
        if g_("progScroll"): add("ai", 15, "Programmatic scrolling")
        if c and not g_("mv") and not g_("touch"): add("ai", 40, "Clicks with zero mouse activity")
        if g_("gapN") >= 3 and gc is not None and gc < .3 and g_("gapMean") > 1200: add("ai", 15, "LLM-paced regular action intervals")
    total = s["au"] + s["ai"]; interact = bool(b) and ((b.get("clicks") or 0) + (b.get("keys") or 0) > 0)
    if s["ai"] >= 40 or (total >= 40 and interact): return out("AI Agent", 60 + total / 2)
    if total >= 40: return out("Web Scraper", 55 + total / 2, R + ["Automated browser, no interaction"])
    if s["sc"] >= 50: return out("Web Scraper", 60 + s["sc"] / 2)
    proof = bool(b) and ((((b.get("mv") or 0) >= 20 and (b.get("spdCV") or 0) > .3 and (b.get("straight") or 0) < .97 and (b.get("jumps") or 0) <= 1)) or (b.get("touch") or 0) >= 5)
    if proof and total < 40 and s["ai"] < 20 and s["sc"] < 25: return out("Human", 95 - total * 2 - s["sc"], R + ["Natural mouse/touch dynamics"])
    return out("Unverified", 30, R + ["JS ran, but no human-interaction proof yet"])

IST = timezone(timedelta(hours=5, minutes=30))
esc = lambda x: html.escape(str(x if x is not None else ""))
COL = {"Human": "#16a34a", "AI Agent": "#dc2626", "Web Scraper": "#ea580c", "Unverified": "#ca8a04", "Pending": "#64748b"}

@app.get("/result")
@app.get("/result.json")
def result():
    key = os.getenv("RESULT_KEY")
    if key and request.args.get("key") != key: abort(401)
    n = int(request.args.get("n", 200))
    rows = [(v, classify(v)) for v in sorted(V.values(), key=lambda x: -x["t"])[:n]]
    if request.path.endswith(".json"):
        return jsonify([{"time": datetime.fromtimestamp(v["t"] / 1000, timezone.utc).isoformat(), "ip": v["ip"],
            "verdict": c["label"], "confidence": c["conf"], "reasons": c["reasons"], "scores": c["score"], "path": v["path"],
            "ua": v["ua"], "geo": v.get("geo"), "headers": v["h"], "env": v.get("env"), "behavior": v.get("beh"), "traps": v["traps"]} for v, c in rows])
    cnt = {}
    for _, c in rows: cnt[c["label"]] = cnt.get(c["label"], 0) + 1
    tr = "".join(f"""<tr><td>{datetime.fromtimestamp(v['t']/1000, IST).strftime('%d %b %Y, %I:%M:%S %p')}</td><td>{esc(v['ip'])}</td>
<td><span class=b style="background:{COL[c['label']]}">{c['label']}</span> {c['conf']}%</td>
<td>{esc(', '.join(x for x in [(v.get('geo') or {}).get('city'), (v.get('geo') or {}).get('country')] if x))}<br><small>{esc((v.get('geo') or {}).get('isp',''))}{' · DATACENTER' if (v.get('geo') or {}).get('hosting') else ''}</small></td>
<td>{esc(v['path'])}</td><td><small>{esc(v['ua'])}</small></td><td><small>{'<br>'.join(esc(r) for r in c['reasons'])}</small></td></tr>""" for v, c in rows)
    gtr = "".join(grow(x) for x in list(GWLOG)[::-1][:150])
    k = f"?key={esc(request.args['key'])}" if request.args.get("key") else ""
    return Response(f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5><title>Detection results</title>
<style>body{{font:13px system-ui;margin:20px;background:#0f172a;color:#e2e8f0}}table{{border-collapse:collapse;width:100%}}td,th{{padding:6px 8px;border-bottom:1px solid #334155;text-align:left;vertical-align:top}}
.b{{padding:2px 8px;border-radius:99px;color:#fff;font-weight:600}}small{{color:#94a3b8}}</style>
<h2>Detection results <small>{' · '.join(f'{a}: {b}' for a, b in cnt.items())} · <a style="color:#7dd3fc" href="/result.json{k}">JSON</a></small></h2>
<table><tr><th>Time (IST)</th><th>IP</th><th>Verdict</th><th>Location / ISP</th><th>Path</th><th>User-Agent</th><th>Why</th></tr>{tr}</table><h2>Gateway decisions <small>(mode: {MODE})</small></h2><table><tr><th>Time (IST)</th><th>IP</th><th>Action</th><th>Risk</th><th>Request</th><th>Why</th></tr>{gtr}</table>""", mimetype="text/html")

# ======================= GATEWAY (runs BEFORE the site/backend) =======================
import hmac, hashlib, demo_site
from collections import deque
from urllib.parse import unquote

UPSTREAM = (os.getenv("UPSTREAM_URL") or "").rstrip("/")          # empty -> built-in demo site
MODE = os.getenv("MODE", "enforce")                               # enforce | monitor (log only)
SECRET = (os.getenv("GW_SECRET") or secrets.token_hex(16)).encode()
BLOCK_AT = int(os.getenv("BLOCK_AT", 70))
BAN_MS = int(os.getenv("BAN_SECS", 900)) * 1000
PASS_S = int(os.getenv("PASS_SECS", 3600))
ALLOW = re.compile(os.getenv("ALLOW_RE")) if os.getenv("ALLOW_RE") else None   # e.g. ^/(webhook|health)
REQ = {}; BAN = {}; WARM = set(); GWLOG = deque(maxlen=1500)

PROBE = re.compile(r"\.(env|git|svn|bak|sql|old|swp|ini|pem|key)\b|/\.(git|aws|ssh|docker)|wp-(admin|login|content|includes)|phpmyadmin|/actuator|/server-status|/cgi-bin|/etc/passwd|/console\b", re.I)
PAYLOAD = re.compile(r"union(\s|\+|/\*.*?\*/)+select|<script|javascript:|\bor\b\s+\d+=\d+|\.\./|\$\{jndi|;\s*(cat|ls|wget|curl|nc|bash|sh)\s|base64_decode|information_schema|sleep\(\d+\)", re.I)
STATIC = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|webp|map)$", re.I)
ID_RE = re.compile(r"(?<=/)(\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,})(?=/|$)", re.I)

def _sig(ip, ua, exp):
    return hmac.new(SECRET, f"{ip}|{hashlib.sha256(ua.encode()).hexdigest()[:12]}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
def mint(ip, ua):
    exp = int(time.time()) + PASS_S; return f"{exp}.{_sig(ip, ua, exp)}"
def valid_pass(ip, ua):
    try:
        exp, sig = request.cookies.get("gwp", "").split(".")
        return int(exp) > time.time() and hmac.compare_digest(sig, _sig(ip, ua, exp))
    except Exception: return False

def gw_score(ip, t, rec):
    R = []; s = 0
    def add(p, w):
        nonlocal s; s += p; R.append(w)
    H = request.headers; ua = H.get("User-Agent", "")
    m = AI_UA.search(ua)
    if m: add(100, "Declared AI UA: " + m.group(0))
    if H.get("Signature-Agent") or H.get("Signature-Input"): add(100, "Signed bot request")
    if not ua: add(60, "No User-Agent")
    if SCRAPER_UA.search(ua): add(70, "HTTP-library/crawler UA")
    if "Mozilla/5.0" in ua:
        if not H.get("Accept-Language"): add(25, "Missing Accept-Language")
        if not H.get("Sec-Fetch-Mode"): add(25, "Missing Sec-Fetch-*")
    body = request.get_data(cache=True)[:8000].decode("utf8", "ignore")
    if PROBE.search(request.path): add(70, "Sensitive-path probe")
    if PAYLOAD.search(unquote(request.full_path) + " " + unquote(body)): add(70, "Attack payload pattern")
    recent = [x for x in REQ.get(ip, ()) if t - x["t"] < 120000]
    n10 = sum(1 for x in recent if t - x["t"] < 10000); n60 = sum(1 for x in recent if t - x["t"] < 60000)
    if n60 > 300: add(100, f"Flood: {n60} req/min")
    elif n60 > 100: add(40, f"High rate: {n60} req/min")
    if n10 > 20: add(30, f"Burst: {n10} req/10s")
    if sum(1 for x in recent if x["m"] == "POST" and re.search(r"login|signin|auth|token", x["p"], re.I) and t - x["t"] < 60000) >= 6: add(70, "Login brute force / credential stuffing")
    if len({x["p"] for x in recent} | {rec["p"]}) >= 25: add(30, "25+ distinct paths in 2 min (enumeration)")
    done = [x for x in recent if x.get("st")]
    if len(done) >= 8 and sum(1 for x in done if x["st"] in (401, 403, 404)) / len(done) >= .4: add(40, "High 401/403/404 ratio (probing)")
    tpl = {}; qs = {}
    for x in recent + [rec]:
        if x["tpl"] != x["p"]: tpl.setdefault(x["tpl"], set()).add(x["p"])
        if x["q"]: qs.setdefault(x["p"], set()).add(x["q"])
    mx = max((len(v) for v in tpl.values()), default=0)
    if mx >= 12: add(70, f"ID enumeration ({mx} distinct IDs)")
    elif mx >= 8: add(40, f"Possible ID enumeration ({mx} IDs)")
    if any(len(v) >= 10 for v in qs.values()): add(30, "Parameter fuzzing")
    ts = [x["t"] for x in recent][-11:] + [t]
    if len(ts) >= 10:
        iv = [b - a for a, b in zip(ts, ts[1:])]; mu = sum(iv) / len(iv)
        if 0 < mu < 3000 and (sum((x - mu) ** 2 for x in iv) / len(iv)) ** .5 / mu < .25: add(30, "Machine-regular request timing")
    if sum(1 for x in recent if not STATIC.search(x["p"])) >= 10 and not any(STATIC.search(x["p"]) for x in recent): add(15, "No static assets loaded")
    geo = GEO.get(ip)
    if geo is None and ip not in WARM:
        WARM.add(ip); threading.Thread(target=lookup, args=(ip,), daemon=True).start()
    if geo and geo.get("hosting"): add(25, "Datacenter IP (" + str(geo.get("isp", "")) + ")")
    if geo and geo.get("proxy"): add(10, "Proxy/VPN IP")
    try:
        if H.get("CF-Bot-Score") and int(H["CF-Bot-Score"]) < 30: add(40, "Cloudflare bot score " + H["CF-Bot-Score"])
    except ValueError: pass
    return s, R

CHALLENGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Checking your browser</title>
<style>body{font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0;background:#f8fafc;color:#0f172a;text-align:center}p{color:#64748b}</style>
<div><h2>Checking your browser…</h2><p>This only takes a moment. Please move your mouse or swipe slightly.</p></div>
<script src="/d.js" data-vid="__VID__"></script>
<script>setInterval(()=>fetch('/__gw/status',{credentials:'same-origin'}).then(r=>r.json()).then(j=>{if(j.pass)location.reload()}).catch(()=>{}),1000)</script>"""

def forbidden(): return Response("Forbidden", 403, mimetype="text/plain")

@app.before_request
def gateway():
    p = request.path
    if p in ("/api/collect", "/__gw/status", "/d.js") or p.startswith("/result") or (ALLOW and ALLOW.search(p)): return
    ip, t = ip_of(), int(time.time() * 1000); ua = request.headers.get("User-Agent", "")
    rec = {"t": t, "ip": ip, "p": p, "tpl": ID_RE.sub("{id}", p), "q": request.query_string.decode("utf8", "ignore")[:200],
           "m": request.method, "ua": ua[:200], "st": None}
    g.gw = rec
    if BAN.get(ip, 0) > t: act, risk, why = "block", 100, ["IP temporarily banned"]
    else:
        risk, why = gw_score(ip, t, rec)
        act = "block" if risk >= BLOCK_AT else "allow" if valid_pass(ip, ua) else "challenge"
        if risk >= 100: BAN[ip] = t + BAN_MS
    REQ.setdefault(ip, deque(maxlen=400)).append(rec)
    if len(REQ) > 20000: REQ.pop(next(iter(REQ)))
    rec.update(action=("monitor:" if MODE == "monitor" else "") + act, risk=risk, why=why); GWLOG.append(rec)
    if MODE == "monitor" or act == "allow": return
    if act == "block": return forbidden()
    if request.method == "GET" and "text/html" in request.headers.get("Accept", ""):
        v = mk(); g.visit = v
        return Response(CHALLENGE.replace("__VID__", v["id"]), mimetype="text/html", headers={"Cache-Control": "no-store"})
    return forbidden()

@app.after_request
def gw_after(r):
    rec = g.get("gw")
    if rec: rec["st"] = r.status_code
    return r

# ------------------------- Trap endpoints -------------------------
# These paths are only reachable via the hidden, off-screen links that
# demo_site.py places on the home page. A real human visiting normally
# will never click them (they're not rendered visibly); anything that
# requests one of these paths is, by construction, parsing/following
# raw HTML links rather than looking at the rendered page.
@app.after_request
def trap_after(r):
    p = request.path.lstrip("/")
    if p in ("trap/link", "trap/ai"):
        kind = "ai" if p == "trap/ai" else "link"
        ip = ip_of()
        vid = request.cookies.get("vid")
        v = V.get(vid)
        if v and v["ip"] == ip:
            # Normal path: we already have a visit record (from the JS
            # challenge flow) for this cookie — attach the trap hit to it
            # so classify() picks it up next time /result is viewed.
            if kind not in v["traps"]:
                v["traps"].append(kind)
                save(v)
        else:
            # No visit record yet — e.g. a scraper that went straight for
            # the trap URL with no cookie at all. Remember it by IP so
            # that if/when a visit record for this IP does get created
            # (via mk()), it inherits the trap flag immediately. Also
            # record a synthetic lightweight entry directly so it shows
            # up in /result even if no JS-challenge visit ever happens.
            TRAP_IPS.setdefault(ip, [])
            if kind not in TRAP_IPS[ip]:
                TRAP_IPS[ip].append(kind)
            synthetic = {
                "id": secrets.token_hex(6), "t": int(time.time() * 1000), "ip": ip,
                "path": request.full_path.rstrip("?")[:200],
                "ua": request.headers.get("User-Agent", ""), "h": {}, "https": request.is_secure,
                "rate": 0, "traps": [kind], "js": False,
            }
            V[synthetic["id"]] = synthetic
            if len(V) > 5000: V.popitem(last=False)
            save(synthetic)
    return r

@app.get("/trap/link")
@app.get("/trap/ai")
def trap_hit():
    # Serve something innocuous-looking so the requester doesn't learn
    # anything from the response itself; the real signal is recorded in
    # trap_after() above, keyed off this same request.
    return Response("Not found", 404, mimetype="text/plain")

@app.get("/__gw/status")
def gw_status():
    ip, ua = ip_of(), request.headers.get("User-Agent", ""); v = V.get(request.cookies.get("vid", ""))
    if v and v["ip"] == ip and classify(v)["label"] == "Human":
        r = jsonify({"pass": True})
        r.set_cookie("gwp", mint(ip, ua), max_age=PASS_S, httponly=True, samesite="Lax", secure=request.is_secure)
        return r
    return jsonify({"pass": False})

COLA = {"allow": "#16a34a", "block": "#dc2626", "challenge": "#ca8a04"}
def grow(x):
    c = COLA.get(x["action"].split(":")[-1], "#64748b"); q = "?" + x["q"] if x["q"] else ""
    why = "<br>".join(esc(r) for r in x["why"]); ts = datetime.fromtimestamp(x["t"] / 1000, IST).strftime("%I:%M:%S %p")
    return (f"<tr><td>{ts}</td><td>{esc(x['ip'])}</td><td><span class=b style='background:{c}'>{esc(x['action'])}</span></td>"
            f"<td>{x['risk']}</td><td>{esc(x['m'])} {esc(x['p'] + q)} <small>{x['st'] or ''}</small></td><td><small>{why}</small></td></tr>")

@app.get("/result/gateway.json")
def gw_json():
    if os.getenv("RESULT_KEY") and request.args.get("key") != os.getenv("RESULT_KEY"): abort(401)
    return jsonify(list(GWLOG)[::-1])

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization", "trailer", "content-length", "content-encoding", "host", "cookie"}

@app.route("/", defaults={"p": ""}, methods=METHODS)
@app.route("/<path:p>", methods=METHODS)
def upstream(p):
    if UPSTREAM:   # real backend behind the gateway
        h = {k: v for k, v in request.headers if k.lower() not in HOP}; h["X-Forwarded-For"] = ip_of()
        ck = {k: v for k, v in request.cookies.items() if k not in ("gwp", "vid")}
        r = requests.request(request.method, f"{UPSTREAM}/{p}", params=request.args, headers=h, cookies=ck,
                             data=request.get_data(), allow_redirects=False, stream=True, timeout=30)
        hs = [(k, v) for k, v in getattr(r.raw.headers, "iteritems", r.raw.headers.items)() if k.lower() not in HOP]
        return Response(r.iter_content(8192), r.status_code, hs)
    return demo_site.handle(p, request, SECRET)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 3000)))
