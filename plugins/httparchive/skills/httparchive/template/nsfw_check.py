# Flags adult pages in compare.py's output, so they're marked nsfw and their images aren't
# committed (a repro test is the evidence). Page signals, in order: an adult <meta name="rating">
# (recorded by harness.py), the host or a parent domain being on the OISD NSFW list, and, only if
# neither matched, the host being blocked by Cloudflare's family resolver but not its security
# resolver (blocked by both is malware, which harness.py doesn't load). Writes <out-dir>/nsfw.csv
# (idx, page, reasons). Rerunning recomputes these reasons (keeping them where a lookup failed)
# and keeps rows added by hand. Run after compare.py and before analyze.py. The OISD list is
# cached for 24h in $XDG_CACHE_HOME/httparchive/ (default ~/.cache).
# check() is the image check, used by publish_check.py on staged images: NudeNet (pip install
# nudenet) finding exposed nudity in a 400px tile. It errs toward flagging: nude paintings and
# sculpture get flagged, lingerie and swimwear pass. Adult content without nudity isn't caught, so
# also flag by eye. Downscaled images (review pairs) are caught less often.
# Usage: nsfw_check.py <out-dir>
import csv, json, os, re, sys, time, urllib.parse, urllib.request
from PIL import Image
import dns_check, ocr_check

ADULT_RATING = re.compile(r'RTA-5042-1996-1400-1577-RTA|\badult\b', re.I)
EXPOSED = {'FEMALE_GENITALIA_EXPOSED', 'MALE_GENITALIA_EXPOSED', 'FEMALE_BREAST_EXPOSED',
           'ANUS_EXPOSED', 'BUTTOCKS_EXPOSED'}
THRESHOLD = 0.4  # tuned on adult, lingerie, swimwear, painting and other pages
OISD_URL = 'https://nsfw.oisd.nl/domainswild2'
RATING, OISD, FAMILY = 'adult rating meta', 'OISD NSFW list', 'Cloudflare family DNS block'
AUTO_REASONS = {RATING, OISD, FAMILY, 'family DNS block'}  # the last from older versions
_detector = None


def backend():
    global _detector
    if _detector is None:
        try:
            from nudenet import NudeDetector
        except ImportError:
            return None
        _detector = NudeDetector()
    return _detector


def check(paths):
    """Returns [(path, x, y, label, score)] for exposed nudity in any tile of the images."""
    det = backend()
    hits = []
    for path in paths:
        for x, y, tile in ocr_check.tiles(Image.open(path), tile=400, overlap=66, scale=1):
            for d in det.detect(ocr_check.png_bytes(tile)):
                if d['class'] in EXPOSED and d['score'] >= THRESHOLD:
                    hits.append((path, x, y, d['class'], round(d['score'], 2)))
    return hits


def oisd_domains():
    """Returns the OISD NSFW list's domains (each also covers its subdomains), or None."""
    cache_dir = os.path.join(os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache'), 'httparchive')
    path = os.path.join(cache_dir, 'oisd-nsfw.txt')
    if not os.path.exists(path) or time.time() - os.path.getmtime(path) > 86400:
        try:
            data = urllib.request.urlopen(OISD_URL, timeout=120).read().decode()
            if len(data.splitlines()) < 100000:
                raise ValueError(f'only {len(data.splitlines())} lines')
            os.makedirs(cache_dir, exist_ok=True)
            with open(path + '.tmp', 'w') as f:
                f.write(data)
            os.replace(path + '.tmp', path)
        except Exception as e:
            print(f"OISD NSFW list download failed ({e}); {'using the cached copy' if os.path.exists(path) else 'skipping it'}")
            if not os.path.exists(path):
                return None
    domains = set()
    for line in open(path):
        line = line.strip().lower()
        if line.startswith('# version:'):
            print('OISD NSFW list version', line.split(':', 1)[1].strip())
        elif line and not line.startswith('#'):
            domains.add(line)
    return domains


def oisd_listed(host, domains):
    labels = host.lower().rstrip('.').split('.')
    return any('.'.join(labels[i:]) in domains for i in range(len(labels)))


def flag_pages(out_dir):
    """Returns ({idx: (page, {reason})}, {idx of unflagged pages where a lookup failed}) from the
    recorded ratings, the OISD list and family DNS."""
    flags, unknown, domains = {}, set(), oisd_domains()
    for r in map(json.loads, open(f'{out_dir}/results.jsonl')):
        reasons = set()
        for v in (r.get(t) or {} for t in ('A', 'A2', 'B')):
            if any(ADULT_RATING.search(m.get('rating') or '') for m in [v] + v.get('frames', [])):
                reasons.add(RATING)
        host = urllib.parse.urlsplit(r['page']).hostname
        if host and domains and oisd_listed(host, domains):
            reasons.add(OISD)
        if host and not reasons:
            family = dns_check.blocked(host, 'family')
            if family is None or domains is None:
                unknown.add(r['idx'])
            if family is None:
                print('family DNS lookup failed for', host)
            elif family:
                malware = dns_check.blocked(host, 'security')
                if malware:
                    print('malware DNS block, not flagged:', host)
                else:
                    reasons.add(FAMILY)
                    if malware is None:
                        print('security DNS lookup failed for', host, '(flagged as adult)')
        if reasons:
            flags[r['idx']] = (r['page'], reasons)
    return flags, unknown


if __name__ == '__main__':
    out_dir = sys.argv[1]
    path = f'{out_dir}/nsfw.csv'
    flags, old = {}, {}
    if os.path.exists(path):
        old = {int(r['idx']): (r['page'], set(filter(None, r['reasons'].split('; '))))
               for r in csv.DictReader(open(path))}
    found, unknown = flag_pages(out_dir)
    for idx, (page, reasons) in old.items():
        # Drop automatic reasons, to be recomputed, unless this run couldn't check the page.
        kept = reasons if idx in unknown else reasons - AUTO_REASONS
        if kept or not reasons:
            flags[idx] = (page, kept)
    for idx, (page, reasons) in found.items():
        flags.setdefault(idx, (page, set()))[1].update(reasons)
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['idx', 'page', 'reasons'])
        for idx in sorted(flags):
            w.writerow([idx, flags[idx][0], '; '.join(sorted(flags[idx][1]))])
    print(len(flags), 'pages flagged in', path)
