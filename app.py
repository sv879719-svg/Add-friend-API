from flask import Flask, request, jsonify, make_response
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

SESSION_TTL_SECONDS = 5 * 60
CHECKPOINT_SECONDS = 20
CHECKPOINT_COUNT = 8
BOT_USERNAME = "ujjawalxbotv2xbot"
SECRET_KEY = os.environ.get("VERIFY_SECRET", "change-me-in-production-verify-secret")
BAN_FILE = os.environ.get("BAN_FILE", "/tmp/verification_bans.json")

sessions = {}
rate_buckets = defaultdict(deque)

SECURITY_TITLES = [
    "Cyber Monitoring Active",
    "Human Validation Running",
    "Security Layer Enabled",
    "Real Activity Detection",
    "Bot Prevention Scan",
    "Advanced Protection Active",
    "Browser Integrity Check",
    "Final Human Presence Lock",
]

CHECKPOINTS = [
    "Pointer entropy and natural movement scan",
    "Touch or mouse behavior consistency analysis",
    "Scroll-depth validation and viewport telemetry",
    "Click cadence and focus integrity inspection",
    "Browser fingerprint and session binding review",
    "Automation/emulation risk correlation",
    "Background token rotation and packet integrity",
    "Final active-presence confirmation gate",
]


def _now():
    return int(time.time())


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",")[0].strip() or request.remote_addr or "0.0.0.0")


def _fingerprint_hash(raw=None):
    value = raw or request.headers.get("X-Client-Fingerprint", "") or request.cookies.get("vf_fp", "")
    ua = request.headers.get("User-Agent", "")
    return hashlib.sha256(f"{value}|{ua}".encode()).hexdigest()


def _load_bans():
    try:
        with open(BAN_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_bans(data):
    os.makedirs(os.path.dirname(BAN_FILE), exist_ok=True)
    with open(BAN_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def _ban_key(ip=None, fp=None):
    return hashlib.sha256(f"{ip or _client_ip()}:{fp or _fingerprint_hash()}".encode()).hexdigest()


def _ban_status(ip=None, fp=None):
    bans = _load_bans()
    record = bans.get(_ban_key(ip, fp))
    if not record:
        return None
    if record.get("permanent") or record.get("until", 0) > _now():
        return record
    del bans[_ban_key(ip, fp)]
    _save_bans(bans)
    return None


def _register_threat(reason, permanent=False):
    bans = _load_bans()
    key = _ban_key()
    previous = bans.get(key, {})
    attempts = int(previous.get("attempts", 0)) + 1
    bans[key] = {
        "attempts": attempts,
        "reason": reason,
        "ip_hash": hashlib.sha256(_client_ip().encode()).hexdigest(),
        "fingerprint": _fingerprint_hash(),
        "created": previous.get("created", _now()),
        "updated": _now(),
        "until": _now() + 86400,
        "permanent": permanent or attempts > 1,
    }
    _save_bans(bans)
    return bans[key]


def _token(payload):
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _verify_token(token):
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        padded = body + "=" * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except Exception:
        return None


def rate_limit(limit=40, window=60):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            key = f"{_client_ip()}:{request.path}"
            bucket = rate_buckets[key]
            now = time.time()
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= limit:
                _register_threat("rate_limit_exceeded")
                return jsonify({"error": "rate_limited"}), 429
            bucket.append(now)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def session_or_error(session_id):
    session = sessions.get(session_id)
    if not session:
        return None, (jsonify({"error": "invalid_session"}), 404)
    if session["expires_at"] <= _now():
        sessions.pop(session_id, None)
        return None, (jsonify({"error": "session_expired"}), 410)
    if session["ip"] != _client_ip() or session["fp"] != _fingerprint_hash():
        _register_threat("session_binding_mismatch")
        return None, (jsonify({"error": "security_lock"}), 403)
    return session, None


@app.before_request
def block_banned_clients():
    if request.path.startswith("/api/"):
        ban = _ban_status()
        if ban:
            return jsonify({"error": "banned", "permanent": ban.get("permanent"), "until": ban.get("until"), "reason": ban.get("reason")}), 403


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                y = (x - int(x)) * 128
                z = (y - int(y)) * 128
                n = (z - int(z)) * 128
                m = (n - int(n)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            y = (x - int(x)) * 128
            z = (y - int(y)) * 128
            n = (z - int(z)) * 128
            return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
    return xxx[int(x)]


def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain_text, AES.block_size)).hex()


@app.route('/')
def index():
    return make_response(INDEX_HTML)


@app.route('/api/session/start', methods=['POST'])
@rate_limit(limit=12, window=60)
def start_session():
    payload = request.get_json(silent=True) or {}
    fp_raw = payload.get("fingerprint", "")[:512]
    fp = _fingerprint_hash(fp_raw)
    session_id = secrets.token_urlsafe(24)
    section_ids = [f"SEC-{secrets.token_hex(5).upper()}" for _ in range(CHECKPOINT_COUNT)]
    now = _now()
    sessions[session_id] = {
        "id": session_id,
        "ip": _client_ip(),
        "fp": fp,
        "created": now,
        "expires_at": now + SESSION_TTL_SECONDS,
        "current": 0,
        "section_ids": section_ids,
        "checkpoint_started": now,
        "completed": [],
        "confirmed": False,
        "events": [],
    }
    resp = jsonify({
        "sessionId": session_id,
        "token": _token({"sid": session_id, "step": 0, "exp": now + SESSION_TTL_SECONDS}),
        "expiresAt": sessions[session_id]["expires_at"],
        "checkpointSeconds": CHECKPOINT_SECONDS,
        "checkpoints": [{"title": SECURITY_TITLES[i], "body": CHECKPOINTS[i], "sectionId": section_ids[i]} for i in range(CHECKPOINT_COUNT)],
    })
    resp.set_cookie("vf_fp", fp, max_age=86400, httponly=True, samesite="Strict", secure=False)
    return resp


@app.route('/api/session/heartbeat', methods=['POST'])
@rate_limit(limit=90, window=60)
def heartbeat():
    payload = request.get_json(silent=True) or {}
    session, error = session_or_error(payload.get("sessionId"))
    if error:
        return error
    session["events"].append({"t": _now(), "type": payload.get("type", "heartbeat")[:40]})
    return jsonify({"ok": True, "serverTime": _now(), "expiresAt": session["expires_at"], "activeUsers": max(128, len(sessions) + 247)})


@app.route('/api/checkpoint/complete', methods=['POST'])
@rate_limit(limit=35, window=60)
def complete_checkpoint():
    payload = request.get_json(silent=True) or {}
    session, error = session_or_error(payload.get("sessionId"))
    if error:
        return error
    token_payload = _verify_token(payload.get("token", ""))
    index = int(payload.get("index", -1))
    if (not token_payload or token_payload.get("sid") != session["id"] or
            token_payload.get("step") != index or token_payload.get("exp", 0) < _now()):
        _register_threat("token_tampering")
        return jsonify({"error": "token_tampering"}), 403
    if index != session["current"] or payload.get("sectionId") != session["section_ids"][index]:
        _register_threat("section_skip_or_id_mismatch")
        return jsonify({"error": "section_validation_failed"}), 403
    elapsed = _now() - session["checkpoint_started"]
    signals = payload.get("signals", {})
    if elapsed < CHECKPOINT_SECONDS or signals.get("movement", 0) < 4 or signals.get("clicks", 0) < 1 or signals.get("scrolls", 0) < 1:
        _register_threat("speed_or_fake_interaction")
        return jsonify({"error": "human_activity_required"}), 403
    session["completed"].append(index)
    session["current"] += 1
    session["checkpoint_started"] = _now()
    done = session["current"] >= CHECKPOINT_COUNT
    return jsonify({
        "ok": True,
        "complete": done,
        "nextToken": None if done else _token({"sid": session["id"], "step": session["current"], "exp": session["expires_at"]}),
        "nextIndex": session["current"],
        "progress": int((len(session["completed"]) / CHECKPOINT_COUNT) * 100),
    })


@app.route('/api/session/confirm', methods=['POST'])
@rate_limit(limit=10, window=60)
def confirm_session():
    payload = request.get_json(silent=True) or {}
    session, error = session_or_error(payload.get("sessionId"))
    if error:
        return error
    if session["current"] < CHECKPOINT_COUNT:
        _register_threat("early_confirmation")
        return jsonify({"error": "verification_incomplete"}), 403
    session["confirmed"] = True
    start = f"verify_{session['id'][:10]}"
    return jsonify({"ok": True, "telegramUrl": f"https://t.me/{BOT_USERNAME}?start={start}", "startCommand": f"/start {start}"})


@app.route('/add_fr', methods=['GET'])
def add_friend():
    token = request.args.get('token')
    target_id = request.args.get('uid')
    if not token or not target_id:
        return jsonify({"error": "Token and ID are required"}), 400
    url = "https://clientbp.ggpolarbear.com/RequestAddingFriend"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB51",
        "Host": "clientbp.ggpolarbear.com",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "/"
    }
    data0 = "08c8b5cfea1810" + Encrypt_ID(target_id) + "18012008"
    response = requests.post(url, headers=headers, data=bytes.fromhex(encrypt_api(data0)), verify=False, timeout=15)
    if response.status_code == 200:
        return jsonify({"message": "REQUEST SENT GOOD!"}), 200
    return jsonify({"error": "Upstream request failed"}), 502


INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Quantum Human Verification</title><script src="https://cdn.tailwindcss.com"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800;900&display=swap" rel="stylesheet"><style>body{font-family:Inter,sans-serif;background:#020711;color:#e8fbff;overflow-x:hidden}.gridbg{background-image:linear-gradient(rgba(0,212,255,.09) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.09) 1px,transparent 1px);background-size:34px 34px}.glass{background:linear-gradient(135deg,rgba(7,22,42,.78),rgba(2,10,22,.58));border:1px solid rgba(0,225,255,.24);box-shadow:0 0 50px rgba(0,153,255,.17),inset 0 0 24px rgba(90,221,255,.06);backdrop-filter:blur(18px)}.glow{box-shadow:0 0 28px rgba(0,217,255,.45)}.scan:before{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent,rgba(0,238,255,.13),transparent);height:32%;animation:scan 2.8s linear infinite}@keyframes scan{0%{transform:translateY(-120%)}100%{transform:translateY(320%)}}.particle{position:fixed;width:3px;height:3px;background:#00eaff;border-radius:99px;opacity:.55;animation:float 9s linear infinite}@keyframes float{to{transform:translateY(-105vh) translateX(40px);opacity:0}}.locked{filter:grayscale(.5);opacity:.55}.logline{animation:fadein .35s ease}@keyframes fadein{from{opacity:0;transform:translateY(8px)}}button:disabled{opacity:.35;cursor:not-allowed}</style></head><body class="gridbg min-h-screen select-none"><div id="particles"></div><div id="loader" class="fixed inset-0 z-50 flex items-center justify-center bg-[#020711]"><div class="text-center"><div class="mx-auto mb-7 h-24 w-24 rounded-full border-4 border-cyan-300/20 border-t-cyan-300 animate-spin glow"></div><h1 class="text-3xl font-black tracking-tight">Initializing Secure Human Verification</h1><p class="mt-3 text-cyan-200/70">Binding browser fingerprint • rotating encrypted session tokens • activating live monitoring</p></div></div><div id="expired" class="hidden fixed inset-0 z-50 bg-black/90 items-center justify-center p-6"><div class="glass max-w-md rounded-3xl p-8 text-center"><div class="text-5xl mb-4">⚠️</div><h2 class="text-3xl font-black text-red-200">Session Expired</h2><p class="mt-3 text-slate-300">Your 5-minute secure session window ended. Restarting from checkpoint one is required.</p><button onclick="location.reload()" class="mt-6 rounded-2xl bg-cyan-300 px-6 py-3 font-black text-slate-950 glow">Restart Verification</button></div></div><main class="mx-auto max-w-7xl px-4 py-6"><header class="glass rounded-3xl p-5 md:p-7 flex flex-col gap-5 md:flex-row md:items-center md:justify-between"><div><p class="text-cyan-300 font-bold tracking-[.3em] text-xs">QUANTUM SHIELD ACCESS GATE</p><h1 class="mt-2 text-3xl md:text-5xl font-black">Real Human Verification</h1><p class="mt-2 text-slate-300">Complete eight timed security checkpoints. Natural movement, scrolling, and click behavior are required.</p></div><div class="grid grid-cols-3 gap-3 text-center"><div class="glass rounded-2xl p-3"><p id="counter" class="text-2xl font-black text-cyan-300">247</p><p class="text-xs text-slate-400">Online</p></div><div class="glass rounded-2xl p-3"><p class="text-2xl font-black text-emerald-300">99.99%</p><p class="text-xs text-slate-400">Uptime</p></div><div class="glass rounded-2xl p-3"><p id="ttl" class="text-2xl font-black text-amber-200">05:00</p><p class="text-xs text-slate-400">Expires</p></div></div></header><section class="mt-5 grid lg:grid-cols-[1fr_360px] gap-5"><div><div class="glass rounded-3xl p-5 sticky top-3 z-20"><div class="flex justify-between text-sm font-bold"><span>Verification Progress</span><span id="pct">0%</span></div><div class="mt-3 h-3 rounded-full bg-slate-900 overflow-hidden"><div id="bar" class="h-full w-0 bg-gradient-to-r from-blue-500 via-cyan-300 to-emerald-300 glow"></div></div></div><div id="sections" class="space-y-5 mt-5"></div><div id="success" class="hidden glass rounded-3xl p-8 text-center mt-5"><div class="text-6xl">✅</div><h2 class="mt-4 text-4xl font-black text-emerald-200">Verification Successful</h2><p class="mt-3 text-slate-300">A second confirmation is required before Telegram handoff.</p><button id="confirm" class="mt-6 rounded-2xl bg-emerald-300 text-slate-950 px-7 py-4 font-black glow">Run Second Confirmation</button><p id="cmd" class="mt-4 text-cyan-200"></p></div></div><aside class="glass rounded-3xl p-5 h-fit sticky top-3"><div class="flex items-center gap-3"><span class="h-3 w-3 rounded-full bg-emerald-300 animate-pulse"></span><h3 class="font-black text-xl">Live Cyber Monitor</h3></div><div class="mt-4 grid grid-cols-2 gap-3 text-sm"><div class="rounded-2xl bg-cyan-300/10 p-3"><p class="text-slate-400">Server</p><b class="text-emerald-300">Operational</b></div><div class="rounded-2xl bg-cyan-300/10 p-3"><p class="text-slate-400">Threats</p><b id="threats" class="text-cyan-300">0</b></div></div><div id="logs" class="mt-4 h-[470px] overflow-hidden space-y-2 text-xs text-slate-300"></div></aside></section></main><script>
const $=s=>document.querySelector(s), state={sessionId:null,token:null,expiresAt:0,index:0,sections:[],signals:{movement:0,clicks:0,scrolls:0,touch:0},ready:false,threats:0};
function fp(){return btoa([navigator.userAgent,screen.width,screen.height,screen.colorDepth,navigator.hardwareConcurrency,navigator.language,Intl.DateTimeFormat().resolvedOptions().timeZone].join('|')).slice(0,500)}
function log(m,t='cyan'){const el=document.createElement('div');el.className='logline rounded-xl border border-cyan-300/10 bg-slate-950/60 p-2';el.innerHTML=`<span class="text-${t}-300">●</span> ${new Date().toLocaleTimeString()} — ${m}`;$('#logs').prepend(el)}
function particles(){for(let i=0;i<70;i++){let p=document.createElement('i');p.className='particle';p.style.left=Math.random()*100+'vw';p.style.top=100+Math.random()*100+'vh';p.style.animationDelay=Math.random()*9+'s';document.body.appendChild(p)}}
function resetSignals(){state.signals={movement:0,clicks:0,scrolls:0,touch:0};state.ready=false}
function sectionTpl(c,i){return `<article id="${c.sectionId}" data-i="${i}" class="checkpoint glass rounded-3xl p-5 md:p-8 relative overflow-hidden scan ${i?'locked':''}"><p class="text-xs text-cyan-300 font-black tracking-[.28em]">SECTION ID: ${c.sectionId}</p><h2 class="mt-3 text-2xl md:text-4xl font-black">${c.title}</h2><p class="mt-2 text-slate-300">${c.body}</p><div class="mt-5 grid md:grid-cols-4 gap-3 text-sm"><b class="rounded-2xl bg-slate-950/70 p-3">Move: <span class="mv">0</span></b><b class="rounded-2xl bg-slate-950/70 p-3">Touch: <span class="tc">0</span></b><b class="rounded-2xl bg-slate-950/70 p-3">Scroll: <span class="sc">0</span></b><b class="rounded-2xl bg-slate-950/70 p-3">Click: <span class="cl">0</span></b></div><div class="mt-5 flex flex-col md:flex-row gap-4 md:items-center md:justify-between"><div><p class="text-slate-400 text-sm">Secure timer</p><p class="timer text-4xl font-black text-cyan-200">20s</p></div><button disabled class="continue rounded-2xl bg-cyan-300 px-6 py-4 font-black text-slate-950 glow">Continue Verification</button></div></article>`}
async function api(path,body){let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Client-Fingerprint':fp()},body:JSON.stringify(body||{})});let j=await r.json().catch(()=>({}));if(!r.ok){if(j.error==='session_expired') expire(); else threat(j.error||'security violation'); throw new Error(j.error||'api');}return j}
function threat(m){state.threats++;$('#threats').textContent=state.threats;log('Threat alert: '+m,'red')}
function expire(){$('#expired').classList.remove('hidden');$('#expired').classList.add('flex')}
function wireProtection(){document.addEventListener('contextmenu',e=>{e.preventDefault();threat('right click blocked')});document.addEventListener('keydown',e=>{let k=e.key.toLowerCase();if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['i','j','c'].includes(k))||(e.ctrlKey&&['u','s','p'].includes(k))){e.preventDefault();threat('inspect shortcut blocked')}});['copy','paste','cut'].forEach(x=>document.addEventListener(x,e=>{e.preventDefault();threat(x+' blocked')}));let last=performance.now();setInterval(()=>{let n=performance.now();if(n-last>2200) threat('debug pause anomaly');last=n},1200)}
function updateActive(){let sec=document.querySelector(`[data-i="${state.index}"]`);if(!sec)return;sec.querySelector('.mv').textContent=state.signals.movement;sec.querySelector('.tc').textContent=state.signals.touch;sec.querySelector('.sc').textContent=state.signals.scrolls;sec.querySelector('.cl').textContent=state.signals.clicks}
function detect(){addEventListener('mousemove',()=>{if(state.ready)return;state.signals.movement++;updateActive()},{passive:true});addEventListener('touchmove',()=>{state.signals.touch++;state.signals.movement++;updateActive()},{passive:true});addEventListener('scroll',()=>{state.signals.scrolls++;updateActive()},{passive:true});addEventListener('click',e=>{if(!e.isTrusted)threat('untrusted click rejected');state.signals.clicks++;updateActive()},{passive:true})}
function startTimer(){resetSignals();let sec=document.querySelector(`[data-i="${state.index}"]`), left=20, btn=sec.querySelector('.continue'), timer=sec.querySelector('.timer');let int=setInterval(()=>{left--;timer.textContent=left+'s';let human=state.signals.movement>=4&&state.signals.clicks>=1&&state.signals.scrolls>=1;if(left<=0){clearInterval(int);state.ready=human;btn.disabled=!human;if(human){btn.textContent='Continue Verification';gsap.fromTo(btn,{scale:.9,opacity:.2},{scale:1,opacity:1,duration:.45});log('Checkpoint '+(state.index+1)+' unlocked after real activity','emerald')}else{timer.textContent='Activity required';log('Timer complete, waiting for movement + scroll + click','amber');let wait=setInterval(()=>{human=state.signals.movement>=4&&state.signals.clicks>=1&&state.signals.scrolls>=1;if(human){clearInterval(wait);state.ready=true;btn.disabled=false;timer.textContent='Unlocked';log('Human activity confirmed','emerald')}},500)}}},1000);btn.onclick=async()=>{if(!state.ready)return;let out=await api('/api/checkpoint/complete',{sessionId:state.sessionId,token:state.token,index:state.index,sectionId:state.sections[state.index].sectionId,signals:state.signals});$('#bar').style.width=out.progress+'%';$('#pct').textContent=out.progress+'%';if(out.complete){$('#success').classList.remove('hidden');$('#success').scrollIntoView({behavior:'smooth'});log('Primary verification successful','emerald')}else{state.token=out.nextToken;state.index=out.nextIndex;document.querySelector(`[data-i="${state.index}"]`).classList.remove('locked');document.querySelector(`[data-i="${state.index}"]`).scrollIntoView({behavior:'smooth'});startTimer()}}}
async function init(){particles();wireProtection();detect();let s=await api('/api/session/start',{fingerprint:fp()});Object.assign(state,{sessionId:s.sessionId,token:s.token,expiresAt:s.expiresAt,sections:s.checkpoints});$('#sections').innerHTML=s.checkpoints.map(sectionTpl).join('');setTimeout(()=>{$('#loader').style.display='none';gsap.from('.glass',{y:20,opacity:0,stagger:.05});startTimer();log('Encrypted verification session established','emerald')},1200);setInterval(async()=>{try{let h=await api('/api/session/heartbeat',{sessionId:state.sessionId,type:'heartbeat'});$('#counter').textContent=h.activeUsers}catch(e){}},8000);setInterval(()=>{let left=state.expiresAt-Math.floor(Date.now()/1000);if(left<=0)expire();$('#ttl').textContent=String(Math.floor(left/60)).padStart(2,'0')+':'+String(left%60).padStart(2,'0')},500)}
$('#confirm')?.addEventListener('click',async()=>{let c=await api('/api/session/confirm',{sessionId:state.sessionId});$('#cmd').textContent='Telegram command: '+c.startCommand;log('Second confirmation complete. Redirecting to Telegram.','emerald');setTimeout(()=>location.href=c.telegramUrl,900)});
init().catch(e=>{threat('startup failed '+e.message)});
</script></body></html>'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
