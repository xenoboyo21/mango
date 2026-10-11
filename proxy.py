#!/usr/bin/env python3
"""
A small web proxy. Python 3.8+, no dependencies.

  python3 proxy.py
      then open http://127.0.0.1:8080

  HOST=0.0.0.0 PORT=8080 PROXY_PASSWORD=choose-one python3 proxy.py
      reachable from other devices (a password is required for that)

You type a web address, this machine fetches the page, and sends it back to you
with its links rewritten so every click keeps going through the proxy.
"""
import base64, hmac, html, ipaddress, json, os, re, socket, sys
import urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urldefrag, urlencode, urljoin, urlparse

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
PASSWORD = os.environ.get("PROXY_PASSWORD", "")
MAX_BYTES = 25 * 1024 * 1024
TIMEOUT = 20
UA = "Mozilla/5.0 (compatible; SimpleWebProxy/1.0)"

HOME = b"""<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Web proxy</title>
<style>body{font:18px/1.5 system-ui,sans-serif;max-width:34rem;margin:20vh auto 0;padding:0 1.25rem;color-scheme:light}
form{display:flex;gap:.5rem}input{flex:1;font:inherit;padding:.6rem .8rem;border:2px solid #222;border-radius:0}
button{font:inherit;padding:.6rem 1.1rem;border:2px solid #222;background:#222;color:#fff;cursor:pointer}</style>
<h1>Web proxy</h1>
<form action="/go"><input name="url" placeholder="example.com" autofocus autocomplete="off"
aria-label="Website address"><button>Open</button></form>"""

# Patches fetch() and XMLHttpRequest in proxied pages so their requests also go through the proxy.
SHIM = """<script>(function(){var B=%s;function P(u){u=String(u);if(u.indexOf("/go?url=")===0)return u;
try{var a=new URL(u,B).href;if(/^https?:/.test(a))return "/go?url="+encodeURIComponent(a)}catch(e){}return u}
var F=window.fetch;if(F)window.fetch=function(i,o){if(typeof i==="string"||i instanceof URL)i=P(i);return F.call(this,i,o)};
var X=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=P(u);return X.apply(this,arguments)}})();</script>"""

BAR = ('<form action="/go" style="position:fixed;left:0;right:0;bottom:0;z-index:2147483647;margin:0;'
       'padding:6px;background:#222;display:flex;gap:6px"><input name="url" value="%s" '
       'style="flex:1;font:14px sans-serif;padding:5px"><button style="font:14px sans-serif;padding:5px 12px">'
       'Go</button></form>')

ATTR = re.compile(r"""(\s(?:href|src|action|poster|data-src)\s*=\s*)(["'])(.*?)\2""", re.I | re.S)
FORM = re.compile(r"<form\b([^>]*)>", re.I | re.S)
STYLE = re.compile(r"(<style\b[^>]*>)(.*?)(</style>)", re.I | re.S)
CSS_URL = re.compile(r"""url\(\s*(["']?)(.*?)\1\s*\)""", re.I)
CSS_IMPORT = re.compile(r"""@import\s+(["'])(.*?)\1""", re.I)
SKIP = ("#", "javascript:", "data:", "mailto:", "tel:", "blob:", "about:")


def check_host(url):
    """Only public http(s) addresses are allowed, so the proxy can't be pointed at your own network."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Only http and https addresses work.")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        raise ValueError("That site's address couldn't be found.")
    for info in infos:
        if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
            raise ValueError("That address is private or local, so it's blocked.")


def wrap(base, ref):
    ref = html.unescape(ref).strip()
    if not ref or ref.lower().startswith(SKIP) or ref == "/go" or ref.startswith("/go?url="):
        return ref
    absolute, frag = urldefrag(urljoin(base, ref))
    return "/go?url=" + quote(absolute, safe="") + ("#" + frag if frag else "")


def rewrite_css(css, base):
    css = CSS_URL.sub(lambda m: "url(%s%s%s)" % (m.group(1), wrap(base, m.group(2)), m.group(1)), css)
    return CSS_IMPORT.sub(lambda m: "@import %s%s%s" % (m.group(1), wrap(base, m.group(2)), m.group(1)), css)


def rewrite_form(m, base):
    attrs = m.group(1)
    method = re.search(r"""method\s*=\s*["']?(\w+)""", attrs, re.I)
    if method and method.group(1).lower() == "post":
        return m.group(0)  # POST keeps its ?url= in the action, handled by the attribute rewrite
    action = re.search(r"""\saction\s*=\s*(["'])(.*?)\1""", attrs, re.I | re.S)
    target = urljoin(base, html.unescape(action.group(2))) if action and action.group(2).strip() else base
    attrs = re.sub(r"""\saction\s*=\s*(["']).*?\1""", "", attrs, flags=re.I | re.S)
    # A GET form replaces the query string, so the real target travels as a hidden field.
    return '<form%s action="/go"><input type="hidden" name="__target" value="%s">' % (
        attrs, html.escape(target, quote=True))


def rewrite_html(text, base):
    page_url = base
    tag = re.search(r"""<base\b[^>]*\shref\s*=\s*(["'])(.*?)\1""", text, re.I | re.S)
    if tag:
        base = urljoin(base, html.unescape(tag.group(2)))
    text = re.sub(r"<base\b[^>]*>", "", text, flags=re.I)
    text = re.sub(r"""\s(?:integrity|nonce)\s*=\s*(["']).*?\1""", "", text, flags=re.I | re.S)
    text = FORM.sub(lambda m: rewrite_form(m, base), text)
    text = ATTR.sub(lambda m: m.group(1) + m.group(2) + wrap(base, m.group(3)) + m.group(2), text)
    text = STYLE.sub(lambda m: m.group(1) + rewrite_css(m.group(2), base) + m.group(3), text)
    shim = SHIM % json.dumps(base).replace("</", "<\\/")
    if re.search(r"<head\b[^>]*>", text, re.I):
        text = re.sub(r"(<head\b[^>]*>)", lambda m: m.group(1) + shim, text, count=1, flags=re.I)
    else:
        text = shim + text
    return re.sub(r"(<body\b[^>]*>)", lambda m: m.group(1) + BAR % html.escape(page_url, quote=True),
                  text, count=1, flags=re.I)


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_host(urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(SafeRedirect)


class Handler(BaseHTTPRequestHandler):
    server_version = "SimpleProxy"

    def reply(self, code, body, ctype="text/html; charset=utf-8", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def fail(self, code, msg):
        page = ("<!doctype html><meta charset=utf-8><body style='font:18px system-ui;max-width:34rem;"
                "margin:20vh auto;padding:0 1rem'><h1>Couldn't load that page</h1><p>%s</p>"
                "<p><a href='/'>Try another address</a></p>" % html.escape(msg)).encode()
        self.reply(code, page)

    def authed(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            given = base64.b64decode(h[6:]).decode().split(":", 1)[1]
        except Exception:
            return False
        return hmac.compare_digest(given, PASSWORD)

    def do_GET(self):
        self.serve(False)

    def do_POST(self):
        self.serve(True)

    def fetch(self, url, post):
        check_host(url)
        body = None
        if post:
            body = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), MAX_BYTES))
        req = urllib.request.Request(url, data=body, method="POST" if post else "GET")
        req.add_header("User-Agent", self.headers.get("User-Agent", UA))
        req.add_header("Accept", self.headers.get("Accept", "*/*"))
        req.add_header("Accept-Language", self.headers.get("Accept-Language", "en"))
        req.add_header("Accept-Encoding", "identity")
        if post and self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
        try:
            resp = OPENER.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            resp = e  # error pages are still pages worth showing
        data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("That response is too large for this proxy.")
        return resp, data

    def serve(self, post):
        if PASSWORD and not self.authed():
            return self.reply(401, b"Password required", "text/plain",
                              [("WWW-Authenticate", 'Basic realm="proxy"')])
        parts = urlparse(self.path)
        if parts.path == "/" and not post:
            return self.reply(200, HOME)
        if parts.path != "/go":
            return self.guess_from_referer()
        query = parse_qs(parts.query, keep_blank_values=True)
        if "__target" in query:
            target = query.pop("__target")[0]
            url = urlparse(target)._replace(query=urlencode(query, doseq=True), fragment="").geturl()
        else:
            url = (query.get("url") or [""])[0].strip()
        if not url:
            return self.fail(400, "Enter a web address.")
        if not re.match(r"https?://", url, re.I):
            url = "https://" + url
        try:
            resp, data = self.fetch(url, post)
        except ValueError as e:
            return self.fail(400, str(e))
        except (urllib.error.URLError, OSError) as e:
            return self.fail(502, "The site didn't respond (%s)." % getattr(e, "reason", e))

        final = resp.geturl()
        ctype = resp.headers.get("Content-Type", "application/octet-stream")
        mime = ctype.split(";")[0].strip().lower()
        if mime in ("text/html", "application/xhtml+xml", "text/css"):
            try:
                text = data.decode(resp.headers.get_content_charset() or "utf-8", "replace")
            except LookupError:
                text = data.decode("utf-8", "replace")
            data = (rewrite_css(text, final) if mime == "text/css" else rewrite_html(text, final)).encode()
            ctype = mime + "; charset=utf-8"
        extra = [("X-Content-Type-Options", "nosniff")]
        if resp.headers.get("Content-Disposition"):
            extra.append(("Content-Disposition", resp.headers["Content-Disposition"]))
        self.reply(resp.getcode(), data, ctype, extra)

    def guess_from_referer(self):
        """Pages sometimes build relative URLs in JavaScript; send those back through the proxy."""
        ref = urlparse(self.headers.get("Referer", ""))
        q = parse_qs(ref.query)
        base = (q.get("url") or q.get("__target") or [""])[0]
        if ref.path != "/go" or not base:
            return self.fail(404, "Nothing here.")
        self.send_response(302)
        self.send_header("Location", "/go?url=" + quote(urljoin(base, self.path), safe=""))
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    if HOST not in ("127.0.0.1", "localhost", "::1") and not PASSWORD:
        sys.exit("Refusing to listen on a public address without a password. Set PROXY_PASSWORD.")
    print("Proxy running at http://%s:%d" % (HOST, PORT))
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
