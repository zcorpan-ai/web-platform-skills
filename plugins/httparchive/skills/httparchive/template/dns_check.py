# Cloudflare DoH blocklist lookups, shared by harness.py (skips malware hosts before loading) and
# nsfw_check.py (flags adult hosts). 'security' (1.1.1.2) blocks malware; 'family' (1.1.1.3) blocks
# malware and adult content.
import json, urllib.parse, urllib.request

RESOLVERS = {'security': 'security.cloudflare-dns.com', 'family': 'family.cloudflare-dns.com'}
_cache = {}


def blocked(host, resolver):
    """True if the resolver blocks the host, False if not, None if the lookup failed."""
    key = (host, resolver)
    if key not in _cache:
        req = urllib.request.Request(
            f'https://{RESOLVERS[resolver]}/dns-query?' + urllib.parse.urlencode({'name': host, 'type': 'A'}),
            headers={'accept': 'application/dns-json'})
        try:
            answers = json.load(urllib.request.urlopen(req, timeout=10)).get('Answer', [])
            _cache[key] = any(a.get('data') == '0.0.0.0' for a in answers)
        except Exception:
            return None  # not cached, so a later call retries
    return _cache[key]
