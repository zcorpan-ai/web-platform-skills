# Keeps live runs off malware hosts, and does Cloudflare DoH blocklist lookups for nsfw_check.py
# (adult hosts). 'security' (1.1.1.2) blocks malware; 'family' (1.1.1.3) blocks malware and adult
# content.
# - Every request: chrome_local_state() (harness.launch() writes it) and firefox_prefs() send all of
#   the browser's DNS to the security resolver, with no fallback, so subresources, frames, workers
#   and redirect targets on its list fail to load too.
# - Hosts listed locally, e.g. by a security team: one per line, or hosts-file lines (`0.0.0.0 host`,
#   e.g. URLhaus's hostfile), in security/*.txt next to this file (gitignored); a listed host's
#   subdomains count too. chrome_args() and firefox_prefs() make them unreachable.
# - page_blocked(url) is the pre-check before loading a page: a clean "not loaded" record.
# Usage: dns_check.py <sample.jsonl|pages.csv>...   (lists sample pages page_blocked() skips)
import csv, functools, glob, json, os, re, sys, urllib.parse, urllib.request

RESOLVERS = {'security': 'security.cloudflare-dns.com', 'family': 'family.cloudflare-dns.com'}
DOH = f"https://{RESOLVERS['security']}/dns-query"
HOST = re.compile(r'^[a-z0-9.-]+\.[a-z0-9-]+$')
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


@functools.cache
def local_hosts():
    out = set()
    for path in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security', '*.txt')):
        for line in open(path, encoding='utf-8', errors='replace'):
            words = line.split('#', 1)[0].split()
            h = (words[-1] if words else '').lower().strip('.')
            if HOST.match(h) and h not in ('localhost', '0.0.0.0'):
                out.add(h)
    return frozenset(out)


def listed(host):
    parts = (host or '').lower().split('.')
    return any('.'.join(parts[i:]) in local_hosts() for i in range(len(parts) - 1))


def page_blocked(url):
    """Why not to load the page, or None. Fails closed: a lookup failing twice skips the page."""
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        return None
    if listed(host):
        return 'host on the local blocklist; not loaded'
    for _ in range(2):
        malware = blocked(host, 'security')
        if malware is not None:
            return 'malware DNS block; not loaded' if malware else None
    return 'malware DNS lookup failed; not loaded'


def chrome_local_state():
    # Chrome reads DoH settings from Local State; no switch sets them. It ignores them when the
    # machine has Chrome policies: the smoke test checks it still blocks.
    return {'dns_over_https': {'mode': 'secure', 'templates': DOH}}


def chrome_args():
    rules = ', '.join(f'MAP {h} ~NOTFOUND, MAP *.{h} ~NOTFOUND' for h in sorted(local_hosts()))
    return [f'--host-resolver-rules={rules}'] if rules else []


def firefox_prefs():
    prefs = {'network.trr.mode': 3, 'network.trr.uri': DOH}
    if local_hosts():
        # A PAC sending listed hosts to a closed port; network.dns.localDomains would point them at
        # localhost, where a local server may answer.
        hosts = json.dumps(sorted(local_hosts()))
        pac = (f'function FindProxyForURL(u, h) {{ var l = {hosts}; for (var i = 0; i < l.length; i++) '
               "if (h == l[i] || dnsDomainIs(h, '.' + l[i])) return 'PROXY 127.0.0.1:9'; return 'DIRECT'; }")
        prefs |= {'network.proxy.type': 2, 'network.proxy.failover_direct': False,
                  'network.proxy.autoconfig_url': 'data:application/x-ns-proxy-autoconfig,' + urllib.parse.quote(pac)}
    return prefs


if __name__ == '__main__':
    print(len(local_hosts()), 'hosts listed locally')
    for path in sys.argv[1:]:
        rows = list(csv.DictReader(open(path))) if path.endswith('.csv') else [json.loads(l) for l in open(path)]
        hits = [(r['page'], why) for r in rows for why in [page_blocked(r['page'])] if why]
        print(f'{path}: {len(hits)} of {len(rows)} pages skipped', *(f'{p}: {w}' for p, w in hits), sep='\n  ')
