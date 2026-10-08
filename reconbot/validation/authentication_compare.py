"""Conservative comparison of form responses; differences never prove acceptance."""
import hashlib
import html
import json
import re
from urllib.parse import quote, quote_plus, urljoin, urlsplit



def http_issue(mode: str, code: int) -> str | None:
    """Explain endpoint failures without changing their outcome or guessing URLs."""
    if code == 404:
        return 'HTTP 404: Login URL was not found. Check the exact login endpoint.'
    if code == 405:
        return ('HTTP 405: This URL does not accept POST. Check the form action URL.' if mode == 'form'
                else 'HTTP 405: This URL does not accept GET. Check the HTTP Basic endpoint.')
    if code == 400:
        return 'HTTP 400: The login request was rejected. Check field names and additional form values.'
    if code == 403:
        return 'HTTP 403: Access was denied. Check endpoint requirements; acceptance was not established.'
    if 500 <= code < 600:
        return 'HTTP 5xx: The server could not complete the login request. Check server health before retrying.'
    return None


def response_problem(config: dict, response: tuple) -> tuple[str, str] | None:
    code, text, location, headers = response
    if code == 429 or headers.get('retry-after') or config['lockoutValue'] and config['lockoutValue'].casefold() in text.casefold():
        return 'blocked', 'Rate limit or configured lockout indicator detected; stopped.'
    if not (200 <= code < 300 or code == 401 or code in (301, 302, 303, 307, 308)):
        return 'inconclusive', http_issue(config['mode'], code) or 'Automatic comparison received an unexpected HTTP response; stopped.'
    if 300 <= code < 400:
        try:
            origin, destination = urlsplit(config['url']), urlsplit(urljoin(config['url'], location))
            key = lambda value: (value.scheme, value.hostname, value.port or (443 if value.scheme == 'https' else 80))
            if not location or key(origin) != key(destination) or destination.username or destination.password:
                return 'inconclusive', 'Automatic comparison received an invalid or external redirect; stopped.'
        except ValueError:
            return 'inconclusive', 'Automatic comparison received an invalid or external redirect; stopped.'
    if 200 <= code < 300 and not text.strip():
        return 'inconclusive', 'Automatic comparison received an empty response; stopped.'
    return None


def fingerprint(config: dict, response: tuple, username: str, password: str) -> dict:
    code, text, location, headers = response
    # Exclude exact submitted-value reflections from comparison only. Original
    # credentials and responses are not rewritten. Arbitrary dynamic tokens,
    # cookies, timestamps and content changes are not guessed away.
    def normalized(value):
        variants = set()
        for credential in (username, password):
            if len(credential) >= 4:
                variants.update((credential, html.escape(credential), quote(credential, safe=''), quote_plus(credential), json.dumps(credential)[1:-1]))
        for variant in sorted(variants, key=len, reverse=True):
            value = value.replace(variant, '__submitted_value__')
        return re.sub(r'\s+', ' ', value).strip()
    body = normalized(text)
    return dict(statusCode=code, bodyHash=hashlib.sha256(body.encode('utf-8')).hexdigest(), bodyLength=len(body), location=normalized(urljoin(config['url'], location)) if location else '', contentType=headers.get('content-type', '').split(';')[0].lower())
