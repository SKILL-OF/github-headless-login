#!/usr/bin/env python3
"""
github-headless-login.py — autonomous GitHub web login + PAT issuance

Usage:
    assemble-password.sh | python3 github-headless-login.py [--username USER] [--pat-name NAME]

Reads the account password from stdin (first line).
Generates the TOTP code internally from the encrypted vault (via generate-totp.sh).
Logs in to GitHub.com via the web form — no browser, no human.
Creates a classic PAT with the requested scopes and prints it to stdout.

Pipe the output to:
    gh auth login --with-token

Environment:
    GITHUB_USERNAME   account to log in as (default: aurora-thesean)
    GH_PAT_NAME       PAT name prefix   (default: aurora-agent)
    GH_PAT_SCOPES     comma-separated   (default: repo,gist,read:org,workflow)
    AGE_KEY           path to age key   (forwarded to generate-totp.sh)
    TOTP_VAULT        path to TOTP vault (forwarded to generate-totp.sh)

Security:
    - Password read from stdin; never appears in a process cmdline or temp file.
    - TOTP read via subprocess stdout; never passed as an argument.
    - Cookie jar is in-memory only (http.cookiejar.CookieJar).
    - No credentials written to disk at any point.
"""

import sys
import os
import re
import subprocess
import datetime
import argparse
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import html.parser


# ---------------------------------------------------------------------------
# HTML parsing helpers
# ---------------------------------------------------------------------------

class AllFormsParser(html.parser.HTMLParser):
    """Extract all forms with their actions, inputs, and select defaults."""

    def __init__(self):
        super().__init__()
        self.forms = []            # list of {action, fields}
        self._current = None
        self._select_name = None   # current <select name=...>
        self._select_default = None
        self._first_option = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self._current = {'action': attrs.get('action', ''), 'fields': {}}
        if self._current is None:
            return
        if tag == 'input':
            name = attrs.get('name', '')
            value = attrs.get('value', '')
            if name:
                self._current['fields'][name] = value
        elif tag == 'select':
            self._select_name = attrs.get('name', '')
            self._select_default = None
            self._first_option = None
        elif tag == 'option' and self._select_name:
            val = attrs.get('value', '')
            if self._first_option is None:
                self._first_option = val
            if 'selected' in attrs:
                self._select_default = val

    def handle_endtag(self, tag):
        if tag == 'select' and self._select_name and self._current is not None:
            # Use the selected option, or fall back to the first option
            chosen = self._select_default if self._select_default is not None else self._first_option
            if chosen is not None:
                self._current['fields'][self._select_name] = chosen
            self._select_name = None
            self._select_default = None
            self._first_option = None
        if tag == 'form' and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_form(html_bytes, want_field=None):
    """Return (action, {name: value}) for the best matching form.

    If want_field is given, prefer the form that contains that field name.
    Falls back to the first form.
    """
    p = AllFormsParser()
    p.feed(html_bytes.decode('utf-8', errors='replace'))
    if not p.forms:
        return '', {}
    if want_field:
        for form in p.forms:
            if want_field in form['fields']:
                return form['action'], form['fields']
    return p.forms[0]['action'], p.forms[0]['fields']


def find_pat_value(html_bytes):
    """Scan the PAT confirmation page for the newly issued token value."""
    text = html_bytes.decode('utf-8', errors='replace')
    # GitHub shows the new token in various contexts depending on UI version.
    # Try narrower patterns first (less false-positive risk), then fall back.
    for pat in [
        r'value="(ghp_[A-Za-z0-9]{36,})"',
        r'value="(github_pat_[A-Za-z0-9_]{80,})"',
        r'"(ghp_[A-Za-z0-9]{36,})"',
        r'"(github_pat_[A-Za-z0-9_]{80,})"',
        # No-quotes fallback: token appeared in plain text / data attribute
        r'(ghp_[A-Za-z0-9]{36,})',
        r'(github_pat_[A-Za-z0-9_]{80,})',
    ]:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# HTTP opener (in-memory cookie jar, follows redirects, keeps Referer)
# ---------------------------------------------------------------------------

class RefererHandler(urllib.request.BaseHandler):
    def http_request(self, req):
        return req
    https_request = http_request


def make_opener():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler(),
    )
    opener.addheaders = [
        ('User-Agent',
         'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'),
        ('Accept',
         'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
        ('Accept-Language', 'en-US,en;q=0.5'),
        ('Accept-Encoding', 'identity'),
        ('DNT', '1'),
        ('Connection', 'keep-alive'),
        ('Upgrade-Insecure-Requests', '1'),
    ]
    return opener, jar


def get(opener, url, referer=None):
    req = urllib.request.Request(url)
    if referer:
        req.add_header('Referer', referer)
    return opener.open(req)


def post(opener, url, fields, referer=None):
    data = urllib.parse.urlencode(fields, doseq=True).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    if referer:
        req.add_header('Referer', referer)
    return opener.open(req)


def final_url(resp):
    return resp.geturl()


# ---------------------------------------------------------------------------
# Auth steps
# ---------------------------------------------------------------------------

BASE = 'https://github.com'


def step_login(opener, username, password):
    print("[1/4] Fetching login page...", file=sys.stderr)
    resp = get(opener, f'{BASE}/login')
    _, fields = parse_form(resp.read(), want_field='authenticity_token')

    if 'authenticity_token' not in fields:
        raise RuntimeError("Login page: could not find authenticity_token")

    # Fill in credentials; preserve all hidden fields (timestamp, timestamp_secret, etc.)
    fields['login'] = username
    fields['password'] = password
    fields.setdefault('webauthn-conditional', 'undefined')
    fields.setdefault('webauthn-support', 'unknown')
    fields.setdefault('webauthn-iuvpaa-support', 'unknown')
    fields.setdefault('trusted_device', '')
    fields.setdefault('return_to', '')
    fields.setdefault('commit', 'Sign in')

    print("[2/4] Submitting credentials...", file=sys.stderr)
    resp = post(opener, f'{BASE}/session', fields, referer=f'{BASE}/login')
    return resp


def step_2fa(opener, debug=False):
    url = f'{BASE}/sessions/two-factor'
    print("[3/4] Fetching 2FA page...", file=sys.stderr)
    resp = get(opener, url)
    body = resp.read()

    # Parse ALL forms so we can debug which one has otp
    p = AllFormsParser()
    p.feed(body.decode('utf-8', errors='replace'))
    if debug:
        print(f"    2FA page: {len(p.forms)} form(s) found", file=sys.stderr)
        for i, f in enumerate(p.forms):
            print(f"      form[{i}] action={f['action']!r} fields={list(f['fields'].keys())}", file=sys.stderr)

    action, fields = parse_form(body, want_field='otp')

    if not fields:
        # Try without want_field (take first form)
        action, fields = parse_form(body)
        print(f"    WARNING: no form with 'otp' field found; using first form", file=sys.stderr)

    if 'authenticity_token' not in fields:
        raise RuntimeError("2FA page: could not find authenticity_token")

    # Generate TOTP at the last moment to avoid window expiry
    print("    Generating TOTP code...", file=sys.stderr)
    totp_code = get_totp()
    # GitHub uses 'app_otp' for TOTP, 'otp' is a legacy alias; set both
    otp_field = 'app_otp' if 'app_otp' in fields else 'otp'
    fields[otp_field] = totp_code
    fields.setdefault('commit', 'Verify')

    post_url = url  # default: same page
    if action.startswith('/'):
        post_url = BASE + action
    elif action:
        post_url = action

    print(f"    POST {post_url}  fields={[k for k in fields if k != 'authenticity_token']}", file=sys.stderr)
    resp = post(opener, post_url, fields, referer=url)

    # Check response
    after_url = resp.geturl()
    print(f"    After 2FA POST → {after_url}", file=sys.stderr)
    if 'two-factor' in after_url or 'sessions' in after_url:
        # Still on 2FA page — extract error message if any
        after_body = resp.read().decode('utf-8', errors='replace')
        import re
        errs = re.findall(r'(?:flash|alert)[^>]*>\s*<[^/][^>]*>\s*([^<]{5,200})', after_body)
        if errs:
            print(f"    GitHub message: {errs[0].strip()}", file=sys.stderr)

    return resp


def step_sudo(opener, password):
    """Handle GitHub sudo re-confirmation (required before sensitive settings)."""
    url = f'{BASE}/sessions/sudo'
    print("    [sudo] Fetching sudo confirmation page...", file=sys.stderr)
    resp = get(opener, url)
    action, fields = parse_form(resp.read(), want_field='sudo_login')
    if not fields:
        action, fields = parse_form(resp.read())
    print(f"    [sudo] form fields: {list(fields.keys())}", file=sys.stderr)
    # sudo form uses 'sudo_login' (username) and 'password' or 'sudo_password'
    if 'sudo_login' in fields:
        fields['sudo_login'] = fields.get('sudo_login', '')
    pwd_field = next((k for k in ('password', 'sudo_password') if k in fields), 'password')
    fields[pwd_field] = password
    fields.setdefault('commit', 'Confirm')
    post_url = (BASE + action) if action.startswith('/') else url
    print(f"    [sudo] POST {post_url}", file=sys.stderr)
    resp = post(opener, post_url, fields, referer=url)
    print(f"    [sudo] After POST → {resp.geturl()}", file=sys.stderr)
    return resp


def step_create_pat(opener, name, scopes, password=None):
    new_url = f'{BASE}/settings/tokens/new'
    print("[4/4] Creating PAT...", file=sys.stderr)
    resp = get(opener, new_url, referer=f'{BASE}/settings/tokens')
    body = resp.read()
    final = resp.geturl()
    print(f"    GET tokens/new → {final}", file=sys.stderr)

    # GitHub requires sudo re-confirmation before creating tokens
    if 'sessions/sudo' in final or ('login' in final and 'settings' not in final):
        print("    Sudo re-confirmation required...", file=sys.stderr)
        if password is None:
            raise RuntimeError("Sudo required but no password available")
        step_sudo(opener, password)
        resp = get(opener, new_url, referer=f'{BASE}/settings/tokens')
        body = resp.read()
        final = resp.geturl()
        print(f"    GET tokens/new (after sudo) → {final}", file=sys.stderr)

    # Find the token-creation form (action=/settings/tokens)
    p2 = AllFormsParser()
    p2.feed(body.decode('utf-8', errors='replace'))
    tok_form = next((f for f in p2.forms if '/settings/tokens' in f['action'] and
                     'authenticity_token' in f['fields']), None)
    if tok_form is None:
        print(f"    Available forms: {[(f['action'], list(f['fields'].keys())) for f in p2.forms]}", file=sys.stderr)
        raise RuntimeError(f"PAT page: token creation form not found at {final}")

    fields = dict(tok_form['fields'])
    post_url = BASE + tok_form['action'] if tok_form['action'].startswith('/') else tok_form['action']

    # Detect field naming convention: oauth_access[...] vs token[...]
    if 'oauth_access[description]' in fields:
        desc_field = 'oauth_access[description]'
        scope_field = 'oauth_access[scopes][]'
        expiry_field = 'oauth_access[default_expires_at]'
    else:
        desc_field = 'token[description]'
        scope_field = 'token[scopes][]'
        expiry_field = 'token[expires_at]'

    fields[desc_field] = name
    # Leave expiry_field at the form's default — don't override with '' (GitHub rejects empty)
    # Remove pre-filled scope value; we submit our own multi-value list
    fields.pop(scope_field, None)

    scope_pairs = [(scope_field, s) for s in scopes]
    other_pairs = [(k, v) for k, v in fields.items()]

    print(f"    Submitting PAT form → {post_url}", file=sys.stderr)
    print(f"    Fields+values (non-secret): {[(k,v) for k,v in dict(other_pairs + scope_pairs).items() if 'auth' not in k]}", file=sys.stderr)
    data = urllib.parse.urlencode(other_pairs + scope_pairs, doseq=True).encode()
    req = urllib.request.Request(post_url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('Referer', new_url)
    resp = opener.open(req)
    body_bytes = resp.read()
    body_text = body_bytes.decode('utf-8', errors='replace')
    print(f"    POST response URL: {resp.geturl()}", file=sys.stderr)

    # Search full body for token value
    token_val = find_pat_value(body_bytes)
    if token_val:
        return token_val

    # Dump body to temp file for diagnosis (filtered to exclude sensitive content)
    dump_path = '/tmp/gh-pat-response.html'
    try:
        with open(dump_path, 'wb') as f:
            f.write(body_bytes)
        print(f"    Body dumped to {dump_path} ({len(body_bytes)} bytes)", file=sys.stderr)
    except Exception:
        pass

    # Not found — extract error messages (strip HTML/SVG tags to get plain text)
    import re, html as _html
    def _strip_tags(s):
        return _html.unescape(re.sub(r'<[^>]+>', ' ', s))
    # Find flash/alert containers and strip their markup
    flash_blocks = re.findall(
        r'class="[^"]*(?:flash-error|alert-error|js-flash-container|error-summary|flash)[^"]*"[^>]*>(.*?)</(?:div|p|span|li)',
        body_text, re.S | re.I)
    flash_texts = [_strip_tags(b).strip() for b in flash_blocks]
    flash_texts = [t for t in flash_texts if len(t) > 3 and not t.startswith('M') and not t.startswith('m')]
    if flash_texts:
        print(f"    GitHub flash: {flash_texts[:3]}", file=sys.stderr)
    # Also try data-flash-error attribute or aria-label
    aria_errors = re.findall(r'aria-label="([^"]{5,200})"', body_text)
    aria_errors = [e for e in aria_errors if any(w in e.lower() for w in ('error', 'invalid', 'require', 'fail'))]
    if aria_errors:
        print(f"    Aria errors: {aria_errors[:3]}", file=sys.stderr)
    # Look for flash messages in JSON islands
    flashes = re.findall(r'"flash(?:es)?":\s*\[([^\]]+)\]', body_text)
    if flashes:
        print(f"    Flash JSON: {flashes[:2]}", file=sys.stderr)
    # Dump select field values actually submitted (for expiry diagnosis)
    print(f"    Submitted expiry field: {expiry_field!r} = {fields.get(expiry_field, '(not in fields)')!r}", file=sys.stderr)
    # Check if token appears anywhere without quotes
    any_tok = re.findall(r'ghp_[A-Za-z0-9]{10,}', body_text)
    print(f"    ghp_ in body: {bool(any_tok)} {any_tok[:1]}", file=sys.stderr)
    raise RuntimeError("Could not extract PAT from response page")


# ---------------------------------------------------------------------------
# TOTP helper — calls generate-totp.sh in the same directory
# ---------------------------------------------------------------------------

def get_totp():
    # generate-totp.sh lives in SKILL-OF/card-key-derivation, not this repo
    # Check env override first, then fall back to sibling skill install
    totp_script = os.environ.get(
        'GENERATE_TOTP_SCRIPT',
        os.path.expanduser('~/.local/lib/skills/card-key-derivation/scripts/generate-totp.sh')
    )
    env = {**os.environ}   # forward AGE_KEY / TOTP_VAULT if set
    result = subprocess.run(
        ['bash', totp_script],
        capture_output=True, text=True, env=env
    )
    if result.returncode != 0:
        raise RuntimeError(f"generate-totp.sh failed: {result.stderr.strip()}")
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--username', default=os.environ.get('GITHUB_USERNAME', 'aurora-thesean'))
    ap.add_argument('--pat-name', default=os.environ.get('GH_PAT_NAME', 'aurora-agent'))
    ap.add_argument('--scopes',
                    default=os.environ.get('GH_PAT_SCOPES', 'repo,gist,read:org,workflow'))
    args = ap.parse_args()

    password = sys.stdin.readline().rstrip('\n')
    if not password:
        print("error: empty password on stdin", file=sys.stderr)
        sys.exit(1)

    scopes = [s.strip() for s in args.scopes.split(',') if s.strip()]
    pat_name = f"{args.pat_name}-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}"

    opener, _ = make_opener()

    try:
        resp = step_login(opener, args.username, password)
        loc = final_url(resp)

        if 'two-factor' in loc or 'sessions/two-factor' in loc:
            resp = step_2fa(opener, debug=True)
            loc = final_url(resp)

        # If we're still on a 2FA or login page, auth failed
        if 'login' in loc or 'two-factor' in loc or 'sessions' in loc:
            raise RuntimeError(f"Authentication failed — ended up at: {loc}")

        pat = step_create_pat(opener, pat_name, scopes, password=password)

    finally:
        # Explicitly clear the password from local scope
        password = None

    # PAT to stdout — caller pipes to: gh auth login --with-token
    print(pat)
    print(f"PAT issued: {pat_name}  scopes: {args.scopes}", file=sys.stderr)


if __name__ == '__main__':
    main()
