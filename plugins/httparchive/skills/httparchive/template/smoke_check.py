# Checks a setup's protections before a live run, in the browser itself (not harness.visit()'s
# pre-check): no browser process runs with --no-sandbox, and Cloudflare's malware test domain, the
# Safe Browsing test page (Google's; Mozilla's in Firefox), and a host from security/*.txt fail to load as a page; the malware domain
# and the listed host also fail as a subresource (fetch from a local page). Exits 1 on any failure.
# Usage: smoke_check.py chrome|firefox <binary> [--setup before|after]
import argparse, asyncio, json, subprocess, sys
import dns_check, harness

MALWARE = 'https://malware.testcategory.com/'
SUBRESOURCE_PAGE = """<!doctype html><body>pending<script>
Promise.all(%s.map(u => fetch(u, {mode: 'no-cors', cache: 'no-store'}).then(() => 'loaded', () => 'blocked')))
  .then(r => document.body.textContent = 'result ' + JSON.stringify(r));
</script>"""


def targets():
    listed = sorted(dns_check.local_hosts())
    host = f'https://{listed[0]}/' if listed else None
    if not host:
        print('WARN no host in security/*.txt; listed-host checks skipped')
    pages = [MALWARE, harness.SAFE_BROWSING_TEST] + ([host] if host else [])
    subs = [MALWARE] + ([host] if host else [])
    return pages, subs


def no_sandbox_processes():
    ps = subprocess.run(['ps', '-axww', '-o', 'pid=,args='], capture_output=True, text=True).stdout
    return [l.strip()[:200] for l in ps.splitlines() if '--no-sandbox' in l and 'smoke_check' not in l]


def serve_subresource_page(subs):
    import os, tempfile
    d = tempfile.mkdtemp(prefix='httparchive-smoke-')
    with open(os.path.join(d, 'index.html'), 'w') as f:
        f.write(SUBRESOURCE_PAGE % json.dumps(subs))
    return harness.serve(d)


def report(results):
    ok = True
    for what, passed in results:
        print('ok  ' if passed else 'FAIL', what)
        ok &= passed
    return ok


async def chrome(binary, setup, pages, subs):
    from playwright.async_api import async_playwright
    results = []
    async with async_playwright() as p:
        br = await harness.launch(p, binary, setup)
        try:
            bad = no_sandbox_processes()
            results.append(('no process with --no-sandbox' + ''.join('\n     ' + b for b in bad), not bad))
            for url in pages:
                ctx = await br.new_context()
                try:
                    pg = await ctx.new_page()
                    try:
                        await pg.goto(url, timeout=20000)
                        loaded = not pg.url.startswith('chrome-error:')
                    except Exception:
                        loaded = False
                finally:
                    await ctx.close()
                results.append((f'{url} blocked as a page', not loaded))
            ctx = await br.new_context()
            try:
                pg = await ctx.new_page()
                await pg.goto(serve_subresource_page(subs))
                await pg.wait_for_function("document.body.textContent.startsWith('result')", timeout=30000)
                r = json.loads((await pg.evaluate('document.body.textContent'))[len('result '):])
            finally:
                await ctx.close()
            results += [(f'{u} blocked as a subresource', v == 'blocked') for u, v in zip(subs, r)]
        finally:
            await br.close()
    return results


def firefox(binary, setup, pages, subs):
    import harness_firefox
    results = []
    with harness_firefox.Session(binary, setup) as s:
        bad = no_sandbox_processes()
        results.append(('no process with --no-sandbox' + ''.join('\n     ' + b for b in bad), not bad))
        # Firefox doesn't block Google's test page everywhere; Session waited for its own test page.
        for url in [harness_firefox.MOZ_TEST if u == harness.SAFE_BROWSING_TEST else u for u in pages]:
            rec = s.visit(url, precheck=False, wait=0)
            loaded = 'error' not in rec  # error pages are errors too
            results.append((f'{url} blocked as a page', not loaded))
        rec = s.visit(serve_subresource_page(subs), precheck=False, wait=5000)
        text = rec.get('text', '')
        r = json.loads(text[len('result '):]) if text.startswith('result') else ['unknown'] * len(subs)
        results += [(f'{u} blocked as a subresource', v == 'blocked') for u, v in zip(subs, r)]
    return results


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('browser', choices=['chrome', 'firefox'])
    ap.add_argument('binary')
    ap.add_argument('--setup', default='before', choices=['before', 'after'])
    a = ap.parse_args()
    pages, subs = targets()
    res = asyncio.run(chrome(a.binary, a.setup, pages, subs)) if a.browser == 'chrome' else firefox(a.binary, a.setup, pages, subs)
    sys.exit(0 if report(res) else 1)
