import os, re, json, time, secrets, threading, html, base64, ipaddress, hmac, hashlib
from collections import OrderedDict, deque
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote
import requests
from flask import Flask, request, g, jsonify, Response, abort, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
import demo_site

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.getenv("TRUST_PROXY", 1)), x_proto=1)
DATA = os.path.join(BASE, "data"); os.makedirs(DATA, exist_ok=True)
FILE = os.path.join(DATA, "visits.jsonl")
LOCK = threading.Lock()

# ------------------------------------------------------------------ config
UPSTREAM = (os.getenv("UPSTREAM_URL") or "").rstrip("/")      # empty -> built-in portal
MODE = os.getenv("MODE", "enforce")                           # enforce | monitor
SECRET = (os.getenv("GW_SECRET") or secrets.token_hex(16)).encode()
BLOCK_AT = int(os.getenv("BLOCK_AT", 60))                     # static (header/IP/rate) risk that blocks at once
SOFT_AT = int(os.getenv("SOFT_AT", 25))                       # only used when CHALLENGE_MODE=auto
CHALLENGE_MODE = os.getenv("CHALLENGE_MODE", "off")           # off = nobody ever sees an interstitial | auto
LATE_ACTION = os.getenv("LATE_ACTION", "block")               # block | log  (verdict from background JS scoring)
BAN_MS = int(os.getenv("BAN_SECS", 900)) * 1000
PASS_S = int(os.getenv("PASS_SECS", 3600))
MIN_CHROME = int(os.getenv("MIN_CHROME", 110))
BAD_JA3 = {x.strip() for x in os.getenv("BAD_JA3", "").split(",") if x.strip()}
ALLOW = re.compile(os.getenv("ALLOW_RE")) if os.getenv("ALLOW_RE") else None
RESULT_PATH = os.getenv("RESULT_PATH", "/result")
RESULT_KEY = os.getenv("RESULT_KEY")                          # unset => results page is disabled (404)
# disguised asset / decoy paths (nothing here says "detect", "trap", "gateway", "bot" ...)
ASSET_JS = os.getenv("ASSET_JS", "/assets/app.min.js")
ASSET_M = os.getenv("ASSET_COLLECT", "/assets/m")
ASSET_X = os.getenv("ASSET_COLLECT_X", "/assets/e")
ASSET_S = os.getenv("ASSET_STATUS", "/assets/s")
TRAP_A = os.getenv("TRAP_LINK_PATH", "/legal/terms-of-service")
TRAP_B = os.getenv("TRAP_DOC_PATH", "/docs/developer-guide")
LURES = ["/ops-console", "/exports"]                          # listed as Disallow in robots.txt
CK_VID, CK_PASS, CK_T = "sid", "_gp", "_ts"
demo_site.TRAP_LINK, demo_site.TRAP_DOC = TRAP_A, TRAP_B
AI_IP_FEEDS = [u.strip() for u in os.getenv("AI_IP_FEEDS",
    "https://openai.com/gptbot.json,https://openai.com/chatgpt-user.json,https://openai.com/searchbot.json,"
    "https://www.perplexity.ai/perplexitybot.json,https://www.perplexity.ai/perplexity-user.json").split(",") if u.strip()]

V = OrderedDict(); HITS = {}; FP = {}; XF = {}; GEO = {}; TRAP_IPS = {}
FAV = {}; REQ = {}; BAN = {}; WARM = set(); GWLOG = deque(maxlen=1500)

def save(v):
    with LOCK, open(FILE, "a") as f: f.write(json.dumps(v) + "\n")

try:
    for l in open(FILE):
        try: o = json.loads(l); V[o["id"]] = o
        except Exception: pass
except FileNotFoundError: pass

AI_UA = re.compile(r"GPTBot|ChatGPT|OAI-SearchBot|OpenAI|ClaudeBot|Claude-User|Claude-SearchBot|Claude-Web|anthropic|PerplexityBot|Perplexity|Google-Extended|Google-CloudVertexBot|Gemini|Bytespider|CCBot|Amazonbot|Applebot-Extended|cohere|Meta-ExternalAgent|meta-externalfetcher|MistralAI|DuckAssistBot|YouBot|Diffbot|ImagesiftBot|Timpibot|AI2Bot|Manus|browser-use|Operator|Firecrawl|Jina", re.I)
SCRAPER_UA = re.compile(r"curl|wget|python|requests|aiohttp|httpx|urllib|scrapy|axios|node-fetch|undici|got/|go-http|java/|okhttp|libwww|php|ruby|perl|httpclient|colly|jsdom|cheerio|phantom|crawler|spider|scraper|\bbot\b", re.I)
AI_ORG = re.compile(r"anthropic|openai|perplexity|browserbase|steel\.dev|apify|zyte|bright ?data|luminati|oxylabs|smartproxy|scrapingbee|scraperapi|serpapi|firecrawl|cohere|mistral|hugging ?face", re.I)
PLAT = {"Windows": "Windows", "macOS": "Macintosh", "Android": "Android", "iOS": "iPhone|iPad", "Linux": "Linux|X11", "Chrome OS": "CrOS"}
KEEP = ["accept","accept-language","accept-encoding","referer","sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-user","sec-ch-ua","sec-ch-ua-platform","sec-ch-ua-mobile","upgrade-insecure-requests","signature-agent","signature-input","cf-ipcountry","cf-bot-score","cf-ja3-hash","x-forwarded-for"]

# ------------------------------------------------------------------ published AI crawler IP ranges
AI_NETS = []
def load_feeds():
    nets = []
    for u in AI_IP_FEEDS:
        try:
            j = requests.get(u, timeout=8, headers={"User-Agent": "Mozilla/5.0"}).json()
            for p in j.get("prefixes", []):
                c = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if c: nets.append(ipaddress.ip_network(c, strict=False))
        except Exception: pass
    if nets: AI_NETS[:] = nets

def feeds_loop():
    while True:
        load_feeds(); time.sleep(6 * 3600)
threading.Thread(target=feeds_loop, daemon=True).start()

def in_ai_net(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    return any(a in n for n in AI_NETS if n.version == a.version)

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
    if ip in TRAP_IPS: v["traps"].extend(TRAP_IPS[ip])
    V[v["id"]] = v
    if len(V) > 5000: V.popitem(last=False)
    bg_geo(v); return v

def visit_for(ip):
    v = V.get(request.cookies.get(CK_VID, ""))
    return v if v and v["ip"] == ip else mk()

# ------------------------------------------------------------------ client collector (served under a neutral name)
EXTRA_JS = r"""
(function(){
var sc=document.currentScript,vid=sc&&(sc.dataset.k||sc.dataset.vid);if(!vid)return;
var W=window,N=navigator,D=document,t0=performance.now(),X={},I={m:0,k:0,t:0,s:0,c:0,ut:0},first=null,fr=0;
function T(f,d){try{return f()}catch(e){return d}}
X.cores=N.hardwareConcurrency||0;X.mem=N.deviceMemory||0;X.tp=N.maxTouchPoints||0;
X.pl=N.plugins?N.plugins.length:-1;X.lang=N.language||"";X.langs=(N.languages||[]).length;
X.tz=T(function(){return Intl.DateTimeFormat().resolvedOptions().timeZone},"");
X.scr=[screen.width,screen.height,screen.availWidth,screen.availHeight,W.devicePixelRatio||1,screen.colorDepth];
X.win=[W.innerWidth,W.innerHeight,W.outerWidth,W.outerHeight];
X.evl=T(function(){return eval.toString().length},0);
X.mq=[T(function(){return matchMedia("(pointer:fine)").matches},null),T(function(){return matchMedia("(hover:hover)").matches},null),T(function(){return matchMedia("(pointer:coarse)").matches},null)];
X.uad=T(function(){var u=N.userAgentData;return u?{b:u.brands.map(function(b){return b.brand}).join(","),m:u.mobile,p:u.platform}:null},null);
X.stk=T(function(){return /puppeteer|playwright|selenium|webdriver|__pw|pptr/i.test(new Error().stack||"")?1:0},0);
X.ifr=T(function(){var f=D.createElement("iframe");f.style.display="none";D.documentElement.appendChild(f);var w=f.contentWindow,r=w?[w.navigator.webdriver===true?1:0,w.navigator.platform!==N.platform?1:0,w.navigator.userAgent!==N.userAgent?1:0]:[0,0,0];D.documentElement.removeChild(f);return r},[0,0,0]);
X.cv=T(function(){var c=D.createElement("canvas");c.width=220;c.height=40;var x=c.getContext("2d");x.textBaseline="top";x.font="14px Arial";x.fillStyle="#f60";x.fillRect(1,1,60,20);x.fillStyle="#069";x.fillText("Cwm fjordbank \ud83d\ude03",2,12);x.fillStyle="rgba(102,204,0,.6)";x.fillText("quick brown",4,18);var s=c.toDataURL(),h=0;for(var i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))|0;return h+"."+s.length},"err");
X.gl=T(function(){var c=D.createElement("canvas"),g=c.getContext("webgl")||c.getContext("experimental-webgl");if(!g)return null;var e=g.getExtension("WEBGL_debug_renderer_info");return e?g.getParameter(e.UNMASKED_VENDOR_WEBGL)+"|"+g.getParameter(e.UNMASKED_RENDERER_WEBGL):"noext"},null);
X.fonts=T(function(){var b=["monospace","sans-serif","serif"],f=["Arial","Verdana","Times New Roman","Courier New","Georgia","Trebuchet MS","Tahoma","Calibri","Cambria","Segoe UI","Helvetica","Menlo","Consolas","Roboto","Ubuntu","DejaVu Sans","Noto Sans","Comic Sans MS","Impact","Lucida Console"],c=D.createElement("canvas").getContext("2d"),s="mmmmmmmmmmlli",w={},n=0;b.forEach(function(k){c.font="72px "+k;w[k]=c.measureText(s).width});f.forEach(function(x){for(var i=0;i<3;i++){c.font="72px '"+x+"',"+b[i];if(c.measureText(s).width!==w[b[i]]){n++;break}}});return n},-1);
(function l(){fr++;if(performance.now()-t0<700)requestAnimationFrame(l)})();
function mark(k,e){if(first===null)first=Math.round(performance.now()-t0);I[k]++;if(e&&e.isTrusted===false)I.ut++}
var o={passive:true,capture:true};
D.addEventListener("mousemove",function(e){mark("m",e)},o);D.addEventListener("keydown",function(e){mark("k",e)},o);
D.addEventListener("touchstart",function(e){mark("t",e)},o);D.addEventListener("scroll",function(e){mark("s",e)},o);D.addEventListener("click",function(e){mark("c",e)},o);
function snap(){var x={};for(var k in X)x[k]=X[k];x.I=I;x.first=first;x.fr=fr;x.dur=Math.round(performance.now()-t0);x.vis=D.visibilityState;x.foc=T(function(){return D.hasFocus()},null);x.voices=T(function(){return speechSynthesis.getVoices().length},-1);return x}
function send(fin){var b=JSON.stringify({vid:vid,final:fin?1:0,x:snap()});try{if(fin&&N.sendBeacon)N.sendBeacon("__X__",new Blob([b],{type:"application/json"}));else fetch("__X__",{method:"POST",headers:{"Content-Type":"application/json"},body:b,keepalive:true,credentials:"same-origin"})}catch(e){}}
setTimeout(function(){send(0)},1500);setTimeout(function(){send(0)},9000);
addEventListener("pagehide",function(){send(1)});D.addEventListener("visibilitychange",function(){if(D.visibilityState==="hidden")send(1)});
})();
"""

def build_js():
    try: base = open(os.path.join(BASE, "public", "d.js"), encoding="utf8").read()
    except FileNotFoundError: base = ""
    base = base.replace("/api/collect", ASSET_M)
    shim = "(function(){var s=document.currentScript;if(s&&s.dataset.k&&!s.dataset.vid)s.setAttribute('data-vid',s.dataset.k)})();\n"
    return shim + base + "\n" + EXTRA_JS.replace("__X__", ASSET_X)
JS_BODY = build_js()

def asset_js():
    r = Response(JS_BODY, mimetype="application/javascript"); r.headers["Cache-Control"] = "public, max-age=1800"; return r
app.add_url_rule(ASSET_JS, "asset_js", asset_js)

def _common():
    b = request.get_json(force=True, silent=True) or {}
    v = V.get(b.get("vid"))
    return (v if v and v["ip"] == ip_of() else None), b

def collect():
    v, b = _common()
    if not v: return "", 204
    v["js"] = True; v["env"] = v.get("env") or b.get("env"); v["beh"] = b.get("beh"); v["beat"] = int(time.time() * 1000)
    fp = (b.get("env") or {}).get("fp")
    if fp: FP.setdefault(fp, set()).add(v["ip"]); v["fpIps"] = len(FP[fp])
    if b.get("final") or not v.get("saved"): v["saved"] = True; save(v)
    return "", 204

def collect_x():
    v, b = _common()
    if not v: return "", 204
    x = b.get("x") or {}; v["js"] = True; v["x"] = x
    if x.get("cv") and x["cv"] != "err":
        k = "|".join(str(x.get(f)) for f in ("cv", "gl", "cores", "tz")) + "|" + str(x.get("scr"))
        XF.setdefault(k, set()).add(v["ip"]); v["xfIps"] = len(XF[k])
    if b.get("final") or not v.get("xsaved"): v["xsaved"] = True; save(v)
    return "", 204

app.add_url_rule(ASSET_M, "collect", collect, methods=["POST"])
app.add_url_rule("/api/collect", "collect_legacy", collect, methods=["POST"])   # fallback if d.js keeps the old path
app.add_url_rule(ASSET_X, "collect_x", collect_x, methods=["POST"])

# ------------------------------------------------------------------ verdict (static visit record -> label)
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
    if "ai" in traps: return out("AI Agent", 96, ["Followed hidden decoy link meant for agents"])
    if in_ai_net(v.get("ip", "")): return out("AI Agent", 95, ["IP inside a published AI-crawler range"])
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
    if "link" in traps: add("sc", 60, "Followed hidden crawler decoy link")
    if "robots" in traps: add("sc", 60, "Requested a path disallowed in robots.txt")
    if "form" in traps: add("sc", 60, "Filled hidden form field")
    if geo.get("hosting"): add("au", 15, f"Datacenter/hosting IP ({geo.get('isp','')})")
    if geo.get("proxy"): add("au", 8, "Proxy/VPN/Tor IP")
    blob = " ".join(str(geo.get(k, "")) for k in ("isp", "org", "as"))
    if AI_ORG.search(blob): add("au", 60, "Network belongs to AI/scraping infrastructure: " + blob[:60])
    if not v.get("js"):
        if s["sc"] >= 50 or age > 8000: return out("Web Scraper", 60 + min(s["sc"], 39), R + ["No JavaScript executed"])
        return out("Pending", 0, ["Waiting for JS beacon"])
    # ---- Browser environment (collector 1)
    chromium = "Chrome/" in ua; desktop = not re.search(r"Mobile|Android|iPhone|iPad", ua)
    plat = e.get("plat") or ""; win = e.get("win") or []; scr = e.get("scr") or []
    if e.get("ua") and e["ua"] != ua: add("au", 40, "JS UA ≠ HTTP UA (spoofed header)")
    if e.get("wd"): add("au", 60, "navigator.webdriver = true")
    if re.search("Headless", (e.get("ua") or "") + (e.get("brands") or ""), re.I): add("au", 60, "HeadlessChrome")
    if e.get("auto"): add("au", 60, "Automation globals: " + ",".join(e["auto"]))
    if e.get("cdp"): add("au", 25, "CDP/DevTools protocol attached")
    if re.search(r"swiftshader|llvmpipe|software|offscreen", e.get("gl") or "", re.I): add("au", 30, "Software WebGL: " + str(e.get("gl")))
    if e.get("gl") is None and "env" in v and v.get("env"): add("au", 10, "WebGL unavailable")
    if e.get("tamper"): add("au", 40, "Navigator props overridden: " + ",".join(e["tamper"]))
    if e.get("nonNative"): add("au", 35, "Patched native functions (stealth plugin)")
    if chromium and not e.get("chrome") and v.get("env"): add("au", 20, "Chrome UA but no window.chrome")
    if chromium and desktop and e.get("plugins") == 0: add("au", 15, "No plugins on desktop Chrome")
    if v.get("env") and not e.get("langs"): add("au", 25, "Empty navigator.languages")
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
    # ---- Browser environment (collector 2). Strong signals count fully; weak ones are capped so a
    # privacy-hardened but genuine browser can never reach the block threshold on weak signals alone.
    x = v.get("x") or {}
    if x:
        WK = []; wk = lambda p, w: WK.append((p, w))
        evl = x.get("evl"); ff = "Firefox/" in ua; sf = "Safari/" in ua and "Chrome/" not in ua and "Chromium" not in ua
        if evl:
            if chromium and evl != 33: add("au", 35, f"JS engine does not match Chrome UA (eval length {evl})")
            elif (ff or sf) and evl != 37: add("au", 35, f"JS engine does not match Firefox/Safari UA (eval length {evl})")
        if x.get("stk"): add("au", 50, "Automation framework visible in JS stack trace")
        ifr = list(x.get("ifr") or []) + [0, 0, 0]
        if ifr[0]: add("au", 50, "webdriver flag inside iframe")
        if ifr[1] or ifr[2]: add("au", 40, "iframe navigator differs from top window (patched navigator)")
        uad = x.get("uad")
        if uad:
            if re.search("Headless", uad.get("b") or "", re.I): add("au", 60, "HeadlessChrome in userAgentData")
            mob = bool(re.search(r"Mobile|Android|iPhone|iPad", ua))
            if uad.get("m") is not None and bool(uad["m"]) != mob: add("au", 20, "userAgentData.mobile ≠ UA")
            up = uad.get("p")
            if up in PLAT and not re.search(PLAT[up], ua): add("au", 25, "userAgentData.platform ≠ UA OS")
            hp = h.get("sec-ch-ua-platform", "").replace('"', "")
            if hp and up and hp != up: add("au", 20, "Client-hint platform header ≠ JS platform")
        hl = (h.get("accept-language") or "").split(",")[0].split("-")[0].strip().lower(); jl = (x.get("lang") or "").split("-")[0].lower()
        if hl and jl and hl != jl and hl != "*": add("au", 15, "Accept-Language ≠ navigator.language")
        if v.get("xfIps", 0) >= 8: add("au", 30, f"Same canvas/GPU/screen fingerprint from {v['xfIps']} IPs")
        w4 = x.get("win") or []; s4 = x.get("scr") or []; mq = (list(x.get("mq") or []) + [None, None, None])[:3]; I = x.get("I") or {}
        tp0 = (x.get("tp") or 0) == 0
        if 0 < (x.get("cores") or 0) <= 1: wk(5, "1 logical CPU")
        if x.get("voices") == 0 and ("Windows" in ua or "Macintosh" in ua): wk(8, "No speech-synthesis voices")
        if 0 <= x.get("fonts", -1) <= 2 and ("Windows" in ua or "Macintosh" in ua): wk(15, "Almost no system fonts")
        if x.get("cv") == "err": wk(10, "Canvas unavailable")
        if desktop and tp0 and mq[0] is False: wk(15, "Desktop UA without a fine pointer")
        if desktop and tp0 and mq[1] is False: wk(10, "Desktop UA without hover capability")
        if desktop and len(w4) == 4 and w4[0] and w4[2] == w4[0] and w4[3] == w4[1]: wk(12, "Window has no browser chrome (outer == inner)")
        if desktop and len(w4) == 4 and len(s4) >= 2 and s4[0] == w4[0] and s4[1] == w4[1]: wk(8, "Viewport equals screen size")
        if x.get("fr") == 0 and (x.get("dur") or 0) > 1500 and x.get("vis") == "visible": wk(15, "No animation frames while visible")
        if x.get("foc") is False and x.get("vis") == "visible": wk(5, "Page visible but never focused")
        if (x.get("dur") or 0) >= 20000 and sum(I.get(k, 0) for k in ("m", "k", "t", "s", "c")) == 0: wk(10, "No interaction of any kind after 20s")
        if x.get("first") is not None and x["first"] < 100: wk(20, "First interaction faster than human reaction time")
        if (I.get("ut") or 0) and not (b and b.get("untrusted")): add("ai", 60, "Synthetic events seen by collector")
        s["au"] += min(sum(p for p, _ in WK), 30); R.extend(w for _, w in WK)
    # ---- Behaviour (collector 1)
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
    total = s["au"] + s["ai"]
    interact = (bool(b) and ((b.get("clicks") or 0) + (b.get("keys") or 0) > 0)) or (bool(x) and sum((x.get("I") or {}).get(k, 0) for k in ("k", "c")) > 0)
    if s["ai"] >= 40 or (total >= 40 and interact): return out("AI Agent", 60 + total / 2)
    if total >= 40: return out("Web Scraper", 55 + total / 2, R + ["Automated browser, no interaction"])
    if s["sc"] >= 50: return out("Web Scraper", 60 + s["sc"] / 2)
    proof = bool(b) and ((((b.get("mv") or 0) >= 20 and (b.get("spdCV") or 0) > .3 and (b.get("straight") or 0) < .97 and (b.get("jumps") or 0) <= 1)) or (b.get("touch") or 0) >= 5)
    if proof and total < 40 and s["ai"] < 20 and s["sc"] < 25: return out("Human", 95 - total * 2 - s["sc"], R + ["Natural mouse/touch dynamics"])
    if total < 25 and s["ai"] < 20 and s["sc"] < 25:
        return out("Human", max(55, 85 - total * 2 - s["sc"]), R + ["Passive checks clean: JS ran, no automation signals"])
    return out("Unverified", 30, R + ["JS ran, but signals are borderline"])

# ------------------------------------------------------------------ results page (hidden unless RESULT_KEY is set and correct)
IST = timezone(timedelta(hours=5, minutes=30))
esc = lambda x: html.escape(str(x if x is not None else ""))
COL = {"Human": "#16a34a", "AI Agent": "#dc2626", "Web Scraper": "#ea580c", "Unverified": "#ca8a04", "Pending": "#64748b"}
COLA = {"allow": "#16a34a", "block": "#dc2626", "challenge": "#ca8a04"}

def grow(x):
    c = COLA.get(x["action"].split(":")[-1], "#64748b"); q = "?" + x["q"] if x["q"] else ""
    why = "<br>".join(esc(r) for r in x["why"]); ts = datetime.fromtimestamp(x["t"] / 1000, IST).strftime("%I:%M:%S %p")
    return (f"<tr><td>{ts}</td><td>{esc(x['ip'])}</td><td><span class=b style='background:{c}'>{esc(x['action'])}</span></td>"
            f"<td>{x['risk']}</td><td>{esc(x['m'])} {esc(x['p'] + q)} <small>{x['st'] or ''}</small></td><td><small>{why}</small></td></tr>")

def _authed():
    return bool(RESULT_KEY) and hmac.compare_digest(request.args.get("key", ""), RESULT_KEY)

def result():
    if not _authed(): abort(404)
    n = int(request.args.get("n", 200))
    rows = [(v, classify(v)) for v in sorted(V.values(), key=lambda x: -x["t"])[:n]]
    if request.path.endswith(".json"):
        return jsonify([{"time": datetime.fromtimestamp(v["t"] / 1000, timezone.utc).isoformat(), "ip": v["ip"],
            "verdict": c["label"], "confidence": c["conf"], "reasons": c["reasons"], "scores": c["score"], "path": v["path"],
            "ua": v["ua"], "geo": v.get("geo"), "headers": v["h"], "env": v.get("env"), "extra": v.get("x"), "behavior": v.get("beh"), "traps": v["traps"]} for v, c in rows])
    cnt = {}
    for _, c in rows: cnt[c["label"]] = cnt.get(c["label"], 0) + 1
    tr = "".join(f"""<tr><td>{datetime.fromtimestamp(v['t']/1000, IST).strftime('%d %b %Y, %I:%M:%S %p')}</td><td>{esc(v['ip'])}</td>
<td><span class=b style="background:{COL[c['label']]}">{c['label']}</span> {c['conf']}%</td>
<td>{esc(', '.join(x for x in [(v.get('geo') or {}).get('city'), (v.get('geo') or {}).get('country')] if x))}<br><small>{esc((v.get('geo') or {}).get('isp',''))}{' · DATACENTER' if (v.get('geo') or {}).get('hosting') else ''}</small></td>
<td>{esc(v['path'])}</td><td><small>{esc(v['ua'])}</small></td><td><small>{'<br>'.join(esc(r) for r in c['reasons'])}</small></td></tr>""" for v, c in rows)
    gtr = "".join(grow(x) for x in list(GWLOG)[::-1][:150])
    k = f"?key={esc(request.args['key'])}"
    return Response(f"""<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=5><title>Results</title>
<style>body{{font:13px system-ui;margin:20px;background:#0f172a;color:#e2e8f0}}table{{border-collapse:collapse;width:100%}}td,th{{padding:6px 8px;border-bottom:1px solid #334155;text-align:left;vertical-align:top}}
.b{{padding:2px 8px;border-radius:99px;color:#fff;font-weight:600}}small{{color:#94a3b8}}</style>
<h2>Visitors <small>{' · '.join(f'{a}: {b}' for a, b in cnt.items())} · <a style="color:#7dd3fc" href="{RESULT_PATH}.json{k}">JSON</a></small></h2>
<table><tr><th>Time (IST)</th><th>IP</th><th>Verdict</th><th>Location / ISP</th><th>Path</th><th>User-Agent</th><th>Why</th></tr>{tr}</table><h2>Requests <small>(mode: {MODE})</small></h2><table><tr><th>Time (IST)</th><th>IP</th><th>Action</th><th>Risk</th><th>Request</th><th>Why</th></tr>{gtr}</table>""", mimetype="text/html")
app.add_url_rule(RESULT_PATH, "result", result)
app.add_url_rule(RESULT_PATH + ".json", "result_json", result)

def gw_json():
    if not _authed(): abort(404)
    return jsonify(list(GWLOG)[::-1])
app.add_url_rule(RESULT_PATH + "/requests.json", "gw_json", gw_json)

# ------------------------------------------------------------------ gateway (runs BEFORE the site)
ID_RE = re.compile(r"(?<=/)(\d+|[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{16,})(?=/|$)", re.I)
PROBE = re.compile(r"\.(env|git|svn|bak|sql|old|swp|ini|pem|key)\b|/\.(git|aws|ssh|docker)|wp-(admin|login|content|includes)|phpmyadmin|/actuator|/server-status|/cgi-bin|/etc/passwd|/console\b", re.I)
PAYLOAD = re.compile(r"union(\s|\+|/\*.*?\*/)+select|<script|javascript:|\bor\b\s+\d+=\d+|\.\./|\$\{jndi|;\s*(cat|ls|wget|curl|nc|bash|sh)\s|base64_decode|information_schema|sleep\(\d+\)", re.I)
STATIC = re.compile(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|webp|map)$", re.I)
EXEMPT = {ASSET_JS, ASSET_M, ASSET_X, ASSET_S, "/api/collect", "/favicon.ico", "/robots.txt"}
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization", "trailer", "content-length", "content-encoding", "host", "cookie"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

def _sig(ip, ua, exp):
    return hmac.new(SECRET, f"{ip}|{hashlib.sha256(ua.encode()).hexdigest()[:12]}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]

def mint(ip, ua):
    exp = int(time.time()) + PASS_S; return f"{exp}.{_sig(ip, ua, exp)}"

def valid_pass(ip, ua):
    try:
        exp, sig = request.cookies.get(CK_PASS, "").split(".")
        return int(exp) > time.time() and hmac.compare_digest(sig, _sig(ip, ua, exp))
    except Exception: return False

def gw_score(ip, t, rec):
    """Server-side only: headers, IP/ASN intel, request rhythm, navigation shape. No JS needed."""
    R = []; s = 0
    def add(p, w):
        nonlocal s; s += p; R.append(w)
    H = request.headers; ua = H.get("User-Agent", "")
    m = AI_UA.search(ua)
    if m: add(100, "Declared AI UA: " + m.group(0))
    if H.get("Signature-Agent") or H.get("Signature-Input"): add(100, "Signed bot request")
    if in_ai_net(ip): add(100, "IP inside a published AI-crawler range")
    if not ua: add(60, "No User-Agent")
    if SCRAPER_UA.search(ua): add(70, "HTTP-library/crawler UA")
    if re.search("HeadlessChrome", ua): add(70, "HeadlessChrome UA")
    if H.get("CF-JA3-Hash") and H["CF-JA3-Hash"] in BAD_JA3: add(40, "TLS fingerprint on deny-list")
    if "Mozilla/5.0" in ua:
        if not H.get("Accept-Language"): add(25, "Missing Accept-Language")
        if not H.get("Sec-Fetch-Mode"): add(25, "Missing Sec-Fetch-*")
        ae = H.get("Accept-Encoding", ""); acc = H.get("Accept", ""); dest = H.get("Sec-Fetch-Dest", "")
        mode = H.get("Sec-Fetch-Mode", ""); site = H.get("Sec-Fetch-Site", ""); ch = H.get("Sec-CH-UA", "")
        if "gzip" not in ae: add(15, "No gzip in Accept-Encoding")
        elif "br" not in ae and "Chrome/" in ua and request.is_secure: add(8, "Chrome UA without br encoding")
        if request.method == "GET" and (dest == "document" or mode == "navigate") and "text/html" not in acc: add(25, "Navigation without text/html in Accept")
        if dest == "document" and mode and mode != "navigate": add(25, "Sec-Fetch-Dest/Mode inconsistent")
        if mode == "navigate" and "Chrome/" in ua and not H.get("Upgrade-Insecure-Requests"): add(10, "Chrome navigation missing Upgrade-Insecure-Requests")
        if site == "none" and H.get("Referer"): add(20, "Sec-Fetch-Site none but Referer present")
        if site == "same-origin" and mode == "navigate" and not H.get("Referer"): add(15, "same-origin navigation without Referer")
        if re.search("Headless", ch, re.I): add(70, "HeadlessChrome in client hints")
        mo = H.get("Sec-CH-UA-Mobile")
        if mo and ((mo == "?1") != bool(re.search(r"Mobile|Android|iPhone", ua))): add(20, "Sec-CH-UA-Mobile ≠ UA")
        cm = re.search(r"Chrome/(\d+)", ua)
        if cm:
            cvn = int(cm.group(1))
            if cvn < MIN_CHROME: add(15, f"Very old Chrome ({cvn})")
            hm = re.search(r'"(?:Google Chrome|Chromium)";v="(\d+)"', ch)
            if hm and int(hm.group(1)) != cvn: add(25, "UA Chrome version ≠ client-hint version")
            if ch and "Chromium" not in ch and "Google Chrome" not in ch: add(15, "Chrome UA but unexpected client-hint brands")
        if H.get("X-Requested-With") and "Android" not in ua: add(10, "X-Requested-With on non-Android")
    if request.method == "HEAD": add(10, "HEAD request")
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
    # session-shape checks
    pages = [x for x in recent if x.get("html")]
    if len(pages) >= 3 and not any(x.get("ck") for x in pages): add(25, "Cookies never sent back (no cookie jar)")
    if len(pages) >= 4 and ip not in FAV: add(10, "Several pages loaded but favicon never requested")
    seq = pages + ([rec] if rec.get("html") else [])
    if len(seq) >= 4:
        gaps = [b["t"] - a["t"] for a, b in zip(seq, seq[1:]) if a["p"] != b["p"]]
        if len(gaps) >= 3 and sum(1 for gp in gaps[-5:] if gp < 700) >= 3: add(25, "Page-to-page faster than human reading")
    if len([x for x in pages if x["p"] not in ("/", "") and not x.get("ref")]) >= 5: add(20, "Direct deep-link navigation without Referer (5+)")
    geo = GEO.get(ip)
    if geo is None and ip not in WARM:
        WARM.add(ip); threading.Thread(target=lookup, args=(ip,), daemon=True).start()
    if geo and geo.get("hosting"): add(25, "Datacenter IP (" + str(geo.get("isp", "")) + ")")
    if geo and geo.get("proxy"): add(10, "Proxy/VPN IP")
    if geo and AI_ORG.search(" ".join(str(geo.get(k, "")) for k in ("isp", "org", "as"))): add(60, "AI/scraping infrastructure network")
    try:
        if H.get("CF-Bot-Score") and int(H["CF-Bot-Score"]) < 30: add(40, "Cloudflare bot score " + H["CF-Bot-Score"])
    except ValueError: pass
    return s, R

CHALLENGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Just a moment…</title>
<style>body{font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0;background:#f8fafc;color:#0f172a;text-align:center}p{color:#64748b}</style>
<div><h2>Just a moment…</h2><p id=m>Checking your connection.</p></div>
<script src="__JS__" data-k="__VID__"></script>
<script>let n=0;const iv=setInterval(()=>{fetch('__S__',{credentials:'same-origin'}).then(r=>r.json()).then(j=>{if(j.pass){clearInterval(iv);location.reload()}else if(++n>25){document.getElementById('m').textContent='Unable to continue. Please enable JavaScript and try again.'}}).catch(()=>{})},400)</script>"""

BLOCK_HTML = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
def forbidden(): return Response(BLOCK_HTML, 403, mimetype="text/html")

def flagged_late(ip):
    v = V.get(request.cookies.get(CK_VID, ""))
    if not v or v["ip"] != ip: return None
    c = classify(v)
    if c["label"] == "AI Agent" or (c["label"] == "Web Scraper" and (v.get("js") or v.get("traps"))): return c["reasons"]
    return None

def lure_kind(path):
    p = path.rstrip("/") or "/"
    if p == TRAP_A: return "link"
    if p == TRAP_B: return "ai"
    if any(p == l or p.startswith(l + "/") for l in LURES): return "robots"
    return None

@app.before_request
def gateway():
    p = request.path
    if p in EXEMPT or (ALLOW and ALLOW.search(p)) or _is_result(p): return
    ip, t = ip_of(), int(time.time() * 1000); ua = request.headers.get("User-Agent", "")
    html_get = request.method == "GET" and "text/html" in request.headers.get("Accept", "")
    rec = {"t": t, "ip": ip, "p": p, "tpl": ID_RE.sub("{id}", p), "q": request.query_string.decode("utf8", "ignore")[:200],
           "m": request.method, "ua": ua[:200], "st": None, "html": html_get,
           "ck": bool(request.cookies.get(CK_T)), "ref": bool(request.headers.get("Referer"))}
    g.gw = rec
    if request.method == "POST":
        request.get_data(cache=True)                                        # cache body first so form parsing doesn't eat it
    if request.method == "POST" and request.form.get("website"):          # hidden honeypot field
        v = visit_for(ip); g.visit = v
        if "form" not in v["traps"]: v["traps"].append("form"); save(v)
    if BAN.get(ip, 0) > t: act, risk, why = "block", 100, ["IP temporarily banned"]
    else:
        late = flagged_late(ip)                                             # background verdict, re-checked every request
        if late and LATE_ACTION == "block":
            BAN[ip] = t + BAN_MS
            act, risk, why = "block", 100, ["Background checks: " + "; ".join(late[:3])]
        else:
            risk, why = gw_score(ip, t, rec)
            if risk >= BLOCK_AT: act = "block"
            elif valid_pass(ip, ua): act = "allow"
            elif CHALLENGE_MODE == "auto" and risk >= SOFT_AT: act = "challenge"
            else: act = "allow"
            if risk >= 100: BAN[ip] = t + BAN_MS
    REQ.setdefault(ip, deque(maxlen=400)).append(rec)
    if len(REQ) > 20000: REQ.pop(next(iter(REQ)))
    rec.update(action=("monitor:" if MODE == "monitor" else "") + act, risk=risk, why=why); GWLOG.append(rec)
    if MODE == "monitor" or act == "allow":
        if html_get: v = visit_for(ip); g.visit = v; g.inject = v["id"]   # keep scoring in the background
        return
    if act == "block": return forbidden()
    if html_get:
        v = visit_for(ip); g.visit = v
        return Response(CHALLENGE.replace("__VID__", v["id"]).replace("__JS__", ASSET_JS).replace("__S__", ASSET_S),
                        mimetype="text/html", headers={"Cache-Control": "no-store"})
    return forbidden()

def _is_result(p): return p == RESULT_PATH or p.startswith(RESULT_PATH + ".") or p.startswith(RESULT_PATH + "/")

@app.after_request
def finish(r):
    v = getattr(g, "visit", None)
    if v: r.set_cookie(CK_VID, v["id"], max_age=3600, samesite="Lax")
    if r.mimetype == "text/html" and not request.cookies.get(CK_T):
        r.set_cookie(CK_T, secrets.token_hex(4), max_age=86400 * 30, samesite="Lax")
    vid = g.get("inject")
    if vid and r.mimetype == "text/html" and r.status_code == 200 and not r.direct_passthrough and not r.is_streamed:
        r.set_data(r.get_data() + f'<script src="{ASSET_JS}" data-k="{vid}"></script>'.encode())
    rec = g.get("gw")
    if rec: rec["st"] = r.status_code
    r.headers["Server"] = "nginx"
    kind = lure_kind(request.path)
    if kind:
        ip = ip_of(); v = getattr(g, "visit", None) or V.get(request.cookies.get(CK_VID, ""))
        if v and v["ip"] == ip:
            if kind not in v["traps"]: v["traps"].append(kind); save(v)
        else:
            TRAP_IPS.setdefault(ip, [])
            if kind not in TRAP_IPS[ip]: TRAP_IPS[ip].append(kind)
            syn = {"id": secrets.token_hex(6), "t": int(time.time() * 1000), "ip": ip, "path": request.full_path.rstrip("?")[:200],
                   "ua": request.headers.get("User-Agent", ""), "h": {}, "https": request.is_secure, "rate": 0, "traps": [kind], "js": False}
            V[syn["id"]] = syn
            if len(V) > 5000: V.popitem(last=False)
            save(syn)
    return r

# ------------------------------------------------------------------ routes that look like a normal site
def gw_status():
    ip, ua = ip_of(), request.headers.get("User-Agent", ""); v = V.get(request.cookies.get(CK_VID, ""))
    if v and v["ip"] == ip and classify(v)["label"] == "Human":
        r = jsonify({"pass": True})
        r.set_cookie(CK_PASS, mint(ip, ua), max_age=PASS_S, httponly=True, samesite="Lax", secure=request.is_secure)
        return r
    return jsonify({"pass": False})
app.add_url_rule(ASSET_S, "gw_status", gw_status)

ICON = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
def favicon():
    FAV[ip_of()] = int(time.time()); return Response(ICON, mimetype="image/png", headers={"Cache-Control": "public, max-age=86400"})
app.add_url_rule("/favicon.ico", "favicon", favicon)

def robots():
    body = "User-agent: *\n" + "".join(f"Disallow: {l}/\n" for l in LURES) + "Allow: /\n"
    return Response(body, mimetype="text/plain")
app.add_url_rule("/robots.txt", "robots", robots)

def trap_terms(): return demo_site.page("Terms of Service", "<h1>Terms of Service</h1><p class=m>Last updated 1 March 2026</p><p>Access to the KRB Orbital portal and data products is provided subject to these terms. Public specifications may be used with attribution. Live telemetry and data products are licensed to registered accounts only and may not be redistributed without written consent.</p>", None)
def trap_docs(): return demo_site.page("Developer Guide", "<h1>Developer Guide</h1><p>Programmatic access is available through the public <a href='/api'>API</a>. Authenticated endpoints require a session issued at sign-in. Rate limits apply to all clients.</p>", None)
def lure(rest=None): return redirect("/login")
app.add_url_rule(TRAP_A, "trap_terms", trap_terms)
app.add_url_rule(TRAP_B, "trap_docs", trap_docs)
for _l in LURES:
    app.add_url_rule(_l, "lure_" + _l.strip("/"), lure)
    app.add_url_rule(_l + "/<path:rest>", "lure2_" + _l.strip("/"), lure)

@app.route("/", defaults={"p": ""}, methods=METHODS)
@app.route("/<path:p>", methods=METHODS)
def upstream(p):
    if UPSTREAM:
        h = {k: v for k, v in request.headers if k.lower() not in HOP}; h["X-Forwarded-For"] = ip_of()
        ck = {k: v for k, v in request.cookies.items() if k not in (CK_PASS, CK_VID, CK_T)}
        r = requests.request(request.method, f"{UPSTREAM}/{p}", params=request.args, headers=h, cookies=ck,
                             data=request.get_data(), allow_redirects=False, stream=True, timeout=30)
        hs = [(k, v) for k, v in getattr(r.raw.headers, "iteritems", r.raw.headers.items)() if k.lower() not in HOP]
        return Response(r.iter_content(8192), r.status_code, hs)
    return demo_site.handle(p, request, SECRET)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 3000)))
