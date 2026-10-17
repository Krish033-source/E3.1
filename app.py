import os, re, json, time, secrets, threading, html
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
import requests
from flask import Flask, request, g, jsonify, Response, send_from_directory, abort
from werkzeug.middleware.proxy_fix import ProxyFix

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.getenv("TRUST_PROXY", 1)), x_proto=1)

DATA = os.path.join(BASE, "data"); os.makedirs(DATA, exist_ok=True)
FILE = os.path.join(DATA, "visits.jsonl")
LOCK = threading.Lock()
V = OrderedDict(); HITS = {}; FP = {}; GEO = {}

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
    V[v["id"]] = v
    if len(V) > 5000: V.popitem(last=False)
    bg_geo(v); return v

@app.before_request
def track():
    if request.method != "GET" or re.match(r"^/(result|api|d\.js|trap|favicon)", request.path): return
    g.visit = mk()

@app.after_request
def cookie(r):
    v = getattr(g, "visit", None)
    if v: r.set_cookie("vid", v["id"], max_age=3600, samesite="Lax")
    return r

@app.get("/")
def index():
    page = open(os.path.join(BASE, "public/index.html"), encoding="utf8").read().replace("__VID__", g.visit["id"])
    return Response(page, mimetype="text/html")

@app.get("/d.js")
def djs(): return send_from_directory(os.path.join(BASE, "public"), "d.js")

@app.get("/trap/<k>")
def trap(k):
    ip = ip_of(); v = V.get(request.cookies.get("vid", ""))
    if not v:
        now = time.time() * 1000
        v = next((x for x in reversed(V.values()) if x["ip"] == ip and now - x["t"] < 600000), None) or mk()
    v["traps"].append("ai" if k == "ai" else "link"); save(v)
    return "ok"

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
    if len(win) >= 4 and (win[2] == 0 or win[3] == 0): add("au", 25, "outerWidth/Height = 0")
    n = e.get("notif")
    if n and n[0] == "denied" and n[1] == "prompt": add("au", 25, "Notification permission inconsistency (headless)")
    if e.get("rtt") == 0: add("au", 10, "connection.rtt = 0")
    if not desktop and e.get("tp") == 0: add("au", 20, "Mobile UA but no touch support")
    if ("Windows" in ua and plat and "win" not in plat.lower()) or ("Macintosh" in ua and plat and "mac" not in plat.lower()):
        add("au", 30, "UA OS ≠ navigator.platform")
    if len(scr) >= 2 and scr[0] == 800 and scr[1] == 600: add("au", 10, "Default 800x600 screen")
    if e.get("voices") == 0 and chromium and desktop: add("au", 5, "No speech-synthesis voices")
    if v.get("fpIps", 0) >= 5: add("au", 30, f"Same fingerprint from {v['fpIps']} IPs")
    if geo.get("timezone") and e.get("tz") and geo["timezone"].split("/")[0] != e["tz"].split("/")[0]: add("au", 5, "Browser timezone ≠ IP region")
    # ---- Behaviour
    if b:
        g_ = lambda k: b.get(k) or 0
        c = g_("clicks"); kc = b.get("keyCV"); gc = b.get("gapCV")
        if g_("untrusted"): add("ai", 60, "Synthetic (untrusted) events")
        if g_("noMove"): add("ai", 30, f"{b['noMove']} click(s) with no preceding mouse movement (teleport)")
        if c and g_("center") >= max(1, c * .6): add("ai", 25, "Clicks land on exact element center")
        if g_("mv") > 5 and g_("screenEq") / g_("mv") > .8: add("ai", 25, "screenX==clientX (CDP-dispatched mouse)")
        if g_("jumps") > 1: add("ai", 20, f"Mouse teleports ({b['jumps']})")
        if g_("inputNoKey"): add("ai", 30, "Text inserted without keystrokes")
        if kc is not None and kc < .15: add("ai", 30, "Machine-regular typing rhythm")
        if g_("progScroll"): add("ai", 20, "Programmatic scrolling")
        if c and not g_("mv") and not g_("touch"): add("ai", 40, "Clicks with zero mouse activity")
        if g_("gapN") >= 3 and gc is not None and gc < .3 and g_("gapMean") > 1200: add("ai", 15, "LLM-paced regular action intervals")
    total = s["au"] + s["ai"]; interact = bool(b) and ((b.get("clicks") or 0) + (b.get("keys") or 0) > 0)
    if s["ai"] >= 20 or (total >= 40 and interact): return out("AI Agent", 60 + total / 2)
    if total >= 40: return out("Web Scraper", 55 + total / 2, R + ["Automated browser, no interaction"])
    if s["sc"] >= 50: return out("Web Scraper", 60 + s["sc"] / 2)
    proof = bool(b) and ((((b.get("mv") or 0) >= 20 and (b.get("spdCV") or 0) > .3 and (b.get("straight") or 0) < .97 and (b.get("jumps") or 0) <= 1)) or (b.get("touch") or 0) >= 5)
    if proof and total < 20 and s["sc"] < 25: return out("Human", 95 - total * 2 - s["sc"], R + ["Natural mouse/touch dynamics"])
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
    k = f"?key={esc(request.args['key'])}" if request.args.get("key") else ""
    return Response(f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5><title>Detection results</title>
<style>body{{font:13px system-ui;margin:20px;background:#0f172a;color:#e2e8f0}}table{{border-collapse:collapse;width:100%}}td,th{{padding:6px 8px;border-bottom:1px solid #334155;text-align:left;vertical-align:top}}
.b{{padding:2px 8px;border-radius:99px;color:#fff;font-weight:600}}small{{color:#94a3b8}}</style>
<h2>Detection results <small>{' · '.join(f'{a}: {b}' for a, b in cnt.items())} · <a style="color:#7dd3fc" href="/result.json{k}">JSON</a></small></h2>
<table><tr><th>Time (IST)</th><th>IP</th><th>Verdict</th><th>Location / ISP</th><th>Path</th><th>User-Agent</th><th>Why</th></tr>{tr}</table>""", mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 3000)))
