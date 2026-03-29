"""
NetWatch Pro — Authentication
Supports both Cloudflare Tunnel (HTTPS) and direct LAN access (HTTP).

Cookie security is determined per-request:
  - Request came through Cloudflare → secure=True  (CF delivers HTTPS to browser)
  - Direct LAN access (HTTP)        → secure=False (plain HTTP, no TLS)
"""

import os, time, secrets, hashlib, hmac, logging, threading
from functools import wraps
from collections import defaultdict
from flask import request, jsonify, make_response, redirect

log = logging.getLogger(__name__)

SESSION_COOKIE   = 'nw_session'
SESSION_LIFETIME = 8 * 3600
MAX_ATTEMPTS     = 5
ATTEMPT_WINDOW   = 60
TOKEN_BYTES      = 32


def _is_via_cloudflare() -> bool:
    """Detect if this specific request came through Cloudflare."""
    # CF-Connecting-IP is only added by Cloudflare's edge — not spoofable
    # because CF strips any client-sent CF-* headers before adding its own
    return bool(request.headers.get('CF-Connecting-IP'))


def _client_ip() -> str:
    """Real client IP — CF-Connecting-IP when behind CF, else remote_addr."""
    if _is_via_cloudflare():
        return request.headers.get('CF-Connecting-IP', '').strip()
    xff = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    return xff or request.remote_addr or '0.0.0.0'


class AuthManager:
    def __init__(self):
        self._lock     = threading.Lock()
        self._sessions = {}
        self._attempts = defaultdict(list)

        # Password priority: NETWATCH_PASSWORD → PIHOLE_PASSWORD → default
        self._password = (
            os.environ.get('NETWATCH_PASSWORD', '').strip() or
            os.environ.get('PIHOLE_PASSWORD',   '').strip() or
            'changeme123'
        )
        if self._password == 'changeme123':
            log.warning("⚠  Default password in use — set NETWATCH_PASSWORD in docker-compose.yml!")
        else:
            log.info("Auth: password loaded from environment")

        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def set_password(self, pw: str):
        if pw:
            self._password = pw
            log.info("Auth: password updated")

    # ── Rate limiting ────────────────────────────────────────────

    def _is_rate_limited(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            self._attempts[ip] = [t for t in self._attempts[ip] if now - t < ATTEMPT_WINDOW]
            return len(self._attempts[ip]) >= MAX_ATTEMPTS

    def _record_attempt(self, ip: str):
        with self._lock:
            self._attempts[ip].append(time.time())

    def _attempts_remaining(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            recent = [t for t in self._attempts[ip] if now - t < ATTEMPT_WINDOW]
            return max(0, MAX_ATTEMPTS - len(recent))

    # ── Password check ────────────────────────────────────────────

    def _check_password(self, candidate: str) -> bool:
        if not candidate:
            return False
        h1 = hashlib.sha256(candidate.encode()).digest()
        h2 = hashlib.sha256(self._password.encode()).digest()
        return hmac.compare_digest(h1, h2)

    # ── Sessions ──────────────────────────────────────────────────

    def create_session(self, ip: str) -> str:
        token = secrets.token_hex(TOKEN_BYTES)
        now   = time.time()
        with self._lock:
            self._sessions[token] = {'created': now, 'last_seen': now, 'ip': ip}
        return token

    def validate_session(self, token: str) -> bool:
        if not token:
            return False
        now = time.time()
        with self._lock:
            sess = self._sessions.get(token)
            if not sess:
                return False
            if now - sess['created'] > SESSION_LIFETIME:
                del self._sessions[token]
                return False
            sess['last_seen'] = now
            return True

    def destroy_session(self, token: str):
        with self._lock:
            self._sessions.pop(token, None)

    def _cleanup_loop(self):
        while True:
            time.sleep(600)
            now = time.time()
            with self._lock:
                for t in [k for k, v in self._sessions.items()
                          if now - v['created'] > SESSION_LIFETIME]:
                    del self._sessions[t]

    # ── Login / Logout ────────────────────────────────────────────

    def handle_login(self):
        ip = _client_ip()

        if self._is_rate_limited(ip):
            log.warning(f"Auth: rate limited {ip}")
            return jsonify({'ok': False, 'error': 'Too many attempts. Wait 60 seconds.',
                            'limited': True}), 429

        data     = request.get_json(silent=True) or {}
        password = data.get('password', '')
        self._record_attempt(ip)

        if not self._check_password(password):
            remaining = self._attempts_remaining(ip)
            log.warning(f"Auth: bad password from {ip} ({remaining} left)")
            return jsonify({'ok': False,
                            'error': f'Wrong password. {remaining} attempts remaining.',
                            'remaining': remaining}), 401

        token = self.create_session(ip)

        # KEY FIX: secure=True only when the request arrived via HTTPS (Cloudflare)
        # When accessing via local HTTP, secure=False so cookie is stored
        via_cf = _is_via_cloudflare()
        log.info(f"Auth: login OK from {ip} (via_cf={via_cf})")

        response = make_response(jsonify({'ok': True}))
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly = True,
            secure   = via_cf,      # True over HTTPS/CF, False over plain HTTP
            samesite = 'Lax',
            max_age  = SESSION_LIFETIME,
            path     = '/',
        )
        return response

    def handle_logout(self):
        token = request.cookies.get(SESSION_COOKIE, '')
        self.destroy_session(token)
        resp = make_response(jsonify({'ok': True}))
        resp.delete_cookie(SESSION_COOKIE, path='/')
        return resp

    def handle_check(self):
        token = request.cookies.get(SESSION_COOKIE, '')
        valid = self.validate_session(token)
        return jsonify({'authenticated': valid, 'via_cf': _is_via_cloudflare()})

    # ── Middleware ────────────────────────────────────────────────

    def require_auth(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.cookies.get(SESSION_COOKIE, '')
            if self.validate_session(token):
                return f(*args, **kwargs)
            if request.path.startswith('/api/'):
                return jsonify({'ok': False, 'error': 'Not authenticated',
                                'login_required': True}), 401
            return redirect('/login')
        return decorated

    def require_auth_ws(self, sid: str) -> bool:
        token = request.cookies.get(SESSION_COOKIE, '')
        if self.validate_session(token):
            return True
        log.warning(f"Auth: WS rejected {sid}")
        return False


auth = AuthManager()
