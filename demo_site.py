"""KRB Orbital satellite telemetry portal."""

import math, time, hmac, html, io

from datetime import datetime, timezone
from flask import Response, jsonify, redirect

esc = html.escape

# Decoy link targets. app.py overwrites these from env at start-up.
TRAP_LINK = "/legal/terms-of-service"
TRAP_DOC = "/docs/developer-guide"

USERS = {"guest": ("guest123", "viewer"), "analyst": ("Telemetry#7", "analyst"), "operator": ("Orbit@2026", "operator")}
RANK = {"viewer": 1, "analyst": 2, "operator": 3}
SATS = [
 dict(id=1, name="KESTREL-1", mission="Earth observation (multispectral)", orbit="Sun-synchronous LEO", alt=512, incl=97.4, period=94.6, launch="2023-03-14", norad="58211"),
 dict(id=2, name="AURORA-2", mission="Polar weather & aurora imaging", orbit="Polar LEO", alt=640, incl=98.1, period=97.5, launch="2023-11-02", norad="58870"),
 dict(id=3, name="NIMBUS-3", mission="Atmospheric sounding (GNSS-RO)", orbit="Mid-inclination LEO", alt=480, incl=52.0, period=94.0, launch="2024-06-21", norad="60112"),
 dict(id=4, name="VEGA-4", mission="Maritime AIS tracking", orbit="LEO", alt=550, incl=53.0, period=95.6, launch="2024-09-09", norad="60544"),
 dict(id=5, name="SENTINEL-5", mission="Optical communications payload (laser downlink)", orbit="Sun-synchronous LEO", alt=585, incl=97.7, period=96.2, launch="2025-02-27", norad="62003"),
]
CSS = "body{margin:0;font:15px/1.6 system-ui;background:#0b1020;color:#dbe4ff}a{color:#7cc4ff;text-decoration:none;margin-left:6px}header{display:flex;gap:14px;align-items:center;padding:14px 24px;background:#0f1730;border-bottom:1px solid #1e2a4a}header b{margin-right:auto;letter-spacing:.08em}main{max-width:980px;margin:28px auto;padding:0 20px}table{width:100%;border-collapse:collapse}td,th{padding:8px 10px;border-bottom:1px solid #1e2a4a;text-align:left}.card{background:#111a36;border:1px solid #1e2a4a;border-radius:10px;padding:16px;margin:12px 0}.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}input,button{font:inherit;padding:9px 12px;border-radius:6px;border:1px solid #2a3a66;background:#0b1020;color:#dbe4ff}button{background:#2563eb;border:0;cursor:pointer}small,.m{color:#8b9bc7}.ok{color:#4ade80}.bad{color:#f87171}code{background:#0b1020;padding:2px 6px;border-radius:4px}footer{max-width:980px;margin:40px auto 24px;padding:0 20px;color:#8b9bc7;font-size:13px}"

def tel(s, t):
    P = s["period"] * 60; ph = (t % P) / P; a = 2 * math.pi * ph; sun = math.sin(a) > 0
    return {"time": datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "sat": s["name"],
            "lat": round(s["incl"] * math.sin(a) if s["incl"] < 90 else 90 * math.sin(a), 3),
            "lon": round(((ph * 360 - t / 240.0 + s["id"] * 40) % 360) - 180, 3),
            "alt_km": round(s["alt"] + 4 * math.sin(2 * a), 2), "battery_pct": round(72 + 18 * math.sin(a + s["id"]), 1),
            "panel_w": round(140 * math.sin(a), 1) if sun else 0.0, "temp_c": round(18 + 9 * math.sin(1.5 * a + s["id"]), 1),
            "rssi_dbm": round(-96 + 7 * math.sin(t / 37 + s["id"]), 1), "mode": "SUNLIT" if sun else "ECLIPSE"}

def spark(vals, w=320, h=50):
    lo, hi = min(vals), max(vals); r = (hi - lo) or 1
    pts = " ".join(f"{i * w / (len(vals) - 1):.1f},{h - (v - lo) / r * h:.1f}" for i, v in enumerate(vals))
    return f"<svg width={w} height={h}><polyline fill=none stroke='#60a5fa' stroke-width=2 points='{pts}'/></svg>"

def mk_sess(u, secret):
    exp = int(time.time()) + 3600
    return f"{u}.{exp}.{hmac.new(secret, f'{u}|{exp}'.encode(), 'sha256').hexdigest()[:24]}"

def who(req, secret):
    try:
        u, exp, sig = req.cookies.get("sess", "").split(".")
        ok = hmac.compare_digest(sig, hmac.new(secret, f"{u}|{exp}".encode(), "sha256").hexdigest()[:24])
        return u if ok and int(exp) > time.time() and u in USERS else None
    except Exception: return None

def page(title, body, u, status=200):
    nav = '<a href="/satellites">Satellites</a><a href="/api">API</a>' + (f'<a href="/dashboard">Dashboard</a><a href="/logout">Logout ({esc(u)})</a>' if u else '<a href="/login">Sign in</a>')
    foot = "<footer>© 2026 KRB Orbital · Mission operations portal</footer>"
    return Response(f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{esc(title)} · KRB Orbital</title><style>{CSS}</style><header><b>◉ KRB ORBITAL</b>{nav}</header><main>{body}</main>{foot}", status, mimetype="text/html")

def sat_of(x):
    return next((s for s in SATS if str(s["id"]) == x), None)

def need(u, role="viewer"): return u and RANK[USERS[u][1]] >= RANK[role]

def handle(p, req, secret):
    u = who(req, secret); t = int(time.time()); p = p.rstrip("/")
    if p == "":
        cards = "".join(f"<div class=card><b><a href='/satellites/{s['id']}'>{s['name']}</a></b><br><small>{s['mission']}</small><br><small>{s['orbit']} · {s['alt']} km</small></div>" for s in SATS)
        hide = "style='position:absolute;left:-9999px;top:-9999px' tabindex=-1 aria-hidden=true"
        decoy = f"<a href='{TRAP_LINK}' {hide}>Terms of Service</a><a href='{TRAP_DOC}' {hide}>Documentation</a>"
        return page("Home", f"<h1>Satellite Telemetry Portal</h1><p class=m>Mission operations and open-data access for the KRB constellation. Public specifications are open; live telemetry and data products need an account.</p><div class=g>{cards}</div>{decoy}", u)
    if p == "login":
        err = ""
        if req.method == "POST":
            n, pw = req.form.get("username", ""), req.form.get("password", "")
            if n in USERS and hmac.compare_digest(USERS[n][0], pw):
                r = redirect("/dashboard"); r.set_cookie("sess", mk_sess(n, secret), max_age=3600, httponly=True, samesite="Lax"); return r
            err = "<p class=bad>Invalid username or password.</p>"
            return page("Sign in", LOGIN.replace("__ERR__", err), u, 401)
        return page("Sign in", LOGIN.replace("__ERR__", ""), u)
    if p == "logout":
        r = redirect("/"); r.delete_cookie("sess"); return r
    if p == "satellites":
        rows = "".join(f"<tr><td><a href='/satellites/{s['id']}'>{s['name']}</a></td><td>{s['mission']}</td><td>{s['orbit']}</td><td>{s['alt']} km</td><td>{s['launch']}</td></tr>" for s in SATS)
        return page("Satellites", f"<h1>Constellation</h1><table><tr><th>Name</th><th>Mission</th><th>Orbit</th><th>Alt</th><th>Launched</th></tr>{rows}</table>", u)
    if p.startswith("satellites/"):
        s = sat_of(p.split("/")[1])
        if not s: return page("Not found", "<h1>404</h1>", u, 404)
        spec = f"<div class=card><h1>{s['name']}</h1><p>{s['mission']}</p><small>NORAD {s['norad']} · {s['orbit']} · inclination {s['incl']}° · period {s['period']} min · launched {s['launch']}</small></div>"
        if not u: return page(s["name"], spec + "<div class=card>🔒 <a href='/login'>Sign in</a> to view live telemetry.</div>", u)
        d = tel(s, t); hist = [tel(s, t - 120 * i)["battery_pct"] for i in range(30, -1, -1)]
        rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in d.items())
        extra = f"<p><a href='/data/{s['id']}.csv'>⬇ Download last 60 min (CSV)</a></p>" if need(u, "analyst") else "<p class=m>CSV export requires an analyst account.</p>"
        cmd = "<div class=card><b>Command queue</b><table><tr><td>T+00:12</td><td>Attitude trim (reaction wheel 2)</td><td>queued</td></tr><tr><td>T+00:47</td><td>Downlink X-band · pass over Svalbard</td><td>scheduled</td></tr></table></div>" if need(u, "operator") else ""
        return page(s["name"], f"{spec}<div class=card><b>Live telemetry</b><table>{rows}</table><p class=m>Battery, last hour</p>{spark(hist)}{extra}</div>{cmd}", u)
    if p == "dashboard":
        if not u: return redirect("/login")
        cards = "".join((lambda d: f"<div class=card><b><a href='/satellites/{s['id']}'>{s['name']}</a></b> <small>{d['mode']}</small><br>🔋 {d['battery_pct']}% · 🌡 {d['temp_c']}°C · 📶 {d['rssi_dbm']} dBm<br><small>{d['lat']}°, {d['lon']}° · {d['alt_km']} km</small></div>")(tel(s, t)) for s in SATS)
        return page("Dashboard", f"<h1>Fleet overview</h1><p class=m>Signed in as <b>{esc(u)}</b> ({USERS[u][1]})</p><div class=g>{cards}</div>", u)
    if p == "api":
        return page("API", "<h1>API</h1><table><tr><td><code>GET /api/satellites</code></td><td>public</td></tr><tr><td><code>GET /api/satellites/{id}</code></td><td>public</td></tr><tr><td><code>GET /api/satellites/{id}/telemetry</code></td><td>login</td></tr><tr><td><code>GET /api/passes/{n}</code></td><td>analyst</td></tr><tr><td><code>GET /data/{id}.csv</code></td><td>analyst</td></tr></table>", u)
    if p == "api/satellites": return jsonify(SATS)
    if p.startswith("api/satellites/"):
        parts = p.split("/"); s = sat_of(parts[2]) if len(parts) > 2 else None
        if not s: return jsonify(error="not found"), 404
        if len(parts) == 3: return jsonify(s)
        if parts[3] == "telemetry":
            if not u: return jsonify(error="authentication required"), 401
            return jsonify(tel(s, t))
    if p.startswith("api/passes/") and p[11:].isdigit():
        if not need(u, "analyst"): return jsonify(error="analyst role required"), 401 if not u else 403
        n = int(p[11:])
        if n > 500: return jsonify(error="not found"), 404
        s = SATS[n % 5]; aos = t - 86400 + n * 1550
        return jsonify(id=n, sat=s["name"], station=["Svalbard", "Bengaluru", "Kiruna", "Fairbanks"][n % 4], aos=aos, los=aos + 420 + n % 160, max_elev_deg=round(18 + (n * 7) % 70, 1))
    if p.startswith("data/") and p.endswith(".csv"):
        s = sat_of(p[5:-4])
        if not need(u, "analyst"): return jsonify(error="analyst role required"), 401 if not u else 403
        if not s: return jsonify(error="not found"), 404
        rows = [tel(s, t - 60 * i) for i in range(60, -1, -1)]; buf = io.StringIO(); buf.write(",".join(rows[0]) + "\n")
        for r in rows: buf.write(",".join(str(v) for v in r.values()) + "\n")
        return Response(buf.getvalue(), mimetype="text/csv")
    return page("Not found", "<h1>404</h1><p>That page doesn't exist.</p>", u, 404)

# "website" is a honeypot field: invisible to people, tempting to form-filling bots/agents.
LOGIN = """<h1>Sign in</h1>__ERR__<form method=post class=card><p><input name=username placeholder=Username autocomplete=username></p><p><input name=password type=password placeholder=Password autocomplete=current-password></p><p style="position:absolute;left:-9999px;top:-9999px" aria-hidden=true><input name=website tabindex=-1 autocomplete=off></p><button>Sign in</button></form>"""
