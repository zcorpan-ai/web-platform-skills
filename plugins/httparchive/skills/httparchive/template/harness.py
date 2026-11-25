# Shared by compare.py and recheck.py: launches the before/after browsers and visits a page the
# way the HTTP Archive crawl does (desktop 1366x768; mobile 360x640, DPR 3, mobile UA, touch).
import asyncio, atexit, difflib, functools, http.server, json, os, re, shutil, socket, tempfile, threading
from PIL import Image, ImageChops
import change, dns_check

MEASURE_JS = """
() => ({
  url: location.href,
  contentType: document.contentType,
  title: document.title,
  rating: [...document.querySelectorAll('meta[name="rating" i]')].map(m => m.content).join(' ').slice(0, 100),
  text: (document.body ? document.body.innerText : document.documentElement ? document.documentElement.textContent : '').slice(0, 3000),
  scrollWidth: document.documentElement ? document.documentElement.scrollWidth : 0,
  scrollHeight: document.documentElement ? document.documentElement.scrollHeight : 0,
})
"""


URL_QUERY = re.compile(r'([a-z][a-z0-9+.-]*://[^\s?#;"\'<>]+)[?#;][^\s"\'<>]*', re.I)
POSITION = re.compile(r'(?::\d+){1,2}\)?$')  # a stack frame's :line:col after the URL
DATA_URL = re.compile(r'\b(data:[^,\s"\'<>]{0,100},)[^\s"\'<>)]{20,}', re.I)
CC_HOST = re.compile(r'\b(google|bing|yahoo|amazon|facebook)\.(?:co\.)?(?!com\b|net\b|org\b)[a-z]{2}\b')
ORIGIN = re.compile(r'[a-z][a-z0-9+.-]*://[^/?#\s]*', re.I)


def scrub(s):
    """Drop query strings, fragments and `;` parameters from URLs (any scheme), keeping stack frames'
    :line:col, and data: URL payloads, and mask country-specific hosts: live loads put tracking IDs,
    tokens and location hints there, and run output gets published."""
    if not isinstance(s, str):
        return s
    s = URL_QUERY.sub(lambda m: m.group(1) + ''.join(POSITION.findall(m.group(0)[len(m.group(1)):])), s)
    return CC_HOST.sub(r'\1.<cc>', DATA_URL.sub(r'\1<payload>', s))


def clip(s, n):
    """Cut s to about n characters at a space: a cut-off host or token can read as another (a host cut
    to `facebook.ne` looks country-specific)."""
    return s if len(s) <= n else (s[:n].rsplit(' ', 1)[0] if ' ' in s[:n] else s[:n]) + ' …'


def scrub_record(rec):
    """Call on each result before writing it, after the text ratios are computed: drops page text,
    titles and final URLs (geo-targeted content and geo redirects identify the tester) and cuts
    frame URLs to their origin."""
    for v in [rec] + [rec.get(t) for t in ('A', 'A2', 'B')]:
        if not isinstance(v, dict):
            continue
        for k in ('text', 'title', 'url'):
            v.pop(k, None)
        for fr in v.get('frames', []):
            fr.pop('text', None)
            fr.pop('title', None)
            m = ORIGIN.match(fr.get('url') or '')
            fr['url'] = m.group(0) if m else None
    return rec


# Live runs load arbitrary crawled pages: keep Chrome's sandbox on (Playwright adds --no-sandbox unless
# chromium_sandbox=True), and drop Playwright's --disable-background-networking (stops Safe Browsing
# list updates) and --disable-component-update (stops security components such as CRLSets).
SAFE = {'chromium_sandbox': True, 'ignore_default_args': ['--disable-background-networking', '--disable-component-update']}


LISTS = os.path.join(tempfile.mkdtemp(prefix='httparchive-lists-'), 'Safe Browsing')
atexit.register(shutil.rmtree, os.path.dirname(LISTS), ignore_errors=True)


def profile():
    # A profile whose DNS goes through the malware-blocking resolver (dns_check.py), with this run's
    # Safe Browsing lists once a launch has them (a new profile takes minutes to fetch its own).
    d = tempfile.mkdtemp(prefix='httparchive-profile-')
    if os.path.isdir(LISTS):
        shutil.copytree(LISTS, os.path.join(d, 'Safe Browsing'))
    with open(os.path.join(d, 'Local State'), 'w') as f:
        json.dump(dns_check.chrome_local_state(), f)
    return d


SAFE_BROWSING_TEST = 'https://testsafebrowsing.appspot.com/s/malware.html'


async def wait_for_safe_browsing(browser, seconds=600):
    # Until Google's test page is blocked, live pages would load unchecked.
    loop = asyncio.get_running_loop()
    start = loop.time()
    while loop.time() - start < seconds:
        ctx = await browser.new_context()
        try:
            page = await ctx.new_page()
            await page.goto(SAFE_BROWSING_TEST, timeout=15000)
            listed = 'Malware Page Example' in await page.evaluate('document.body ? document.body.innerText : ""')
        except Exception as e:
            listed = 'ERR_BLOCKED_BY_CLIENT' not in str(e)  # blocked; other errors: try again
        finally:
            await ctx.close()
        if not listed:
            return round(loop.time() - start)
        await asyncio.sleep(10)
    raise SystemExit(f'Safe Browsing still lets {SAFE_BROWSING_TEST} load after {seconds}s; not loading live pages')


async def desktop_ua(browser):
    # Headless Chrome sends HeadlessChrome/<version>, which bot defenses and some sites treat differently.
    ua = (await (await browser.new_browser_cdp_session()).send('Browser.getVersion'))['userAgent']
    return ua.replace('HeadlessChrome/', 'Chrome/')


class SafeBrowser:
    """A Browser launched with a profile() (Playwright's launch() takes no profile): new_context()
    gives isolated contexts in it."""

    def __init__(self, persistent, profile_dir, ua):
        self.persistent, self.dir, self.ua = persistent, profile_dir, ua
        self.browser = persistent.browser
        self.version = self.browser.version

    async def new_context(self, **kwargs):
        return await self.browser.new_context(**kwargs)

    def is_connected(self):
        return self.browser.is_connected()

    async def close(self):
        try:
            await self.persistent.close()
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)


class ExtensionBrowser:
    """Stands in for a Browser when a setup loads an extension: each new_context() launches a fresh
    persistent profile (extensions don't run in Playwright's default contexts) and loads the
    extension through CDP, since branded Chrome ignores --load-extension."""

    def __init__(self, p, executable, args, extension, version, ua):
        self.p, self.executable, self.args, self.version, self.ua = p, executable, args, version, ua
        self.extension = os.path.abspath(extension)
        self.dirs = []

    async def new_context(self, **kwargs):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        self.dirs.append(profile())  # with the lists launch() waited for
        ctx = await self.p.chromium.launch_persistent_context(
            self.dirs[-1], executable_path=self.executable, chromium_sandbox=True,
            ignore_default_args=SAFE['ignore_default_args'] + ['--disable-extensions'],
            args=self.args + ['--enable-unsafe-extension-debugging', f'--remote-debugging-port={port}'], **kwargs)
        cdp = await self.p.chromium.connect_over_cdp(f'http://127.0.0.1:{port}')
        await (await cdp.new_browser_cdp_session()).send('Extensions.loadUnpacked', {'path': self.extension})
        return ctx

    async def close(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)


async def launch(p, executable, setup):
    args = change.BEFORE_ARGS if setup == 'before' else change.AFTER_ARGS
    extension = change.BEFORE_EXTENSION if setup == 'before' else change.AFTER_EXTENSION
    if any(a.startswith(('--no-sandbox', '--disable-background-networking', '--safebrowsing-disable')) for a in args):
        raise SystemExit('refusing to load live pages without the sandbox or Safe Browsing: ' + ' '.join(args))
    args = args + dns_check.chrome_args()
    d = profile()
    browser = SafeBrowser(await p.chromium.launch_persistent_context(d, executable_path=executable, args=args, **SAFE),
                          d, None)
    browser.ua = await desktop_ua(browser.browser)
    print(setup, f'Safe Browsing on after {await wait_for_safe_browsing(browser)}s', flush=True)
    if not os.path.isdir(LISTS):
        shutil.copytree(os.path.join(d, 'Safe Browsing'), LISTS)
    if not extension:
        return browser
    await browser.close()
    return ExtensionBrowser(p, executable, args, extension, browser.version, browser.ua)


async def measure(frame):
    m = await frame.evaluate(MEASURE_JS)
    m['url'] = scrub(m['url'])
    if change.EXTRA_MEASURE_JS:
        m['extra'] = await frame.evaluate(change.EXTRA_MEASURE_JS)
    return m


async def visit(browser, url, client, setup, shot=None, wait=3000, full_page=True):
    skip = await asyncio.to_thread(dns_check.page_blocked, url)
    if skip:
        return {'error': skip, 'pageErrors': [], 'console': []}
    mobile = client == 'mobile'
    major = browser.version.split('.')[0]
    ctx = await browser.new_context(
        viewport={'width': 360, 'height': 640} if mobile else {'width': 1366, 'height': 768},
        device_scale_factor=3 if mobile else 1, is_mobile=mobile, has_touch=mobile,
        user_agent=('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) '
                    f'Chrome/{major}.0.0.0 Mobile Safari/537.36') if mobile else browser.ua,
        ignore_https_errors=True)
    for js in (change.INIT_JS, change.AFTER_INIT_JS if setup == 'after' else None):
        if js:
            await ctx.add_init_script(js)
    page = await ctx.new_page()
    errors, console = [], []
    page.on('pageerror', lambda e: errors.append(clip(scrub(str(e)), 300)))
    page.on('console', lambda m: m.type in ('error', 'warning') and len(console) < 20 and
            console.append(f'{m.type}: ' + clip(scrub(m.text), 300)))
    rec = {}
    try:
        resp = await page.goto(url, wait_until='domcontentloaded', timeout=30000)
        rec['status'] = resp.status if resp else None
        try:
            # Heavy pages can take minutes to fire load; measure them anyway.
            await page.wait_for_load_state('load', timeout=15000)
        except Exception:
            rec['loadTimeout'] = True
        await page.wait_for_timeout(wait)
        if setup == 'after' and change.AFTER_LOAD_JS:
            await page.evaluate(change.AFTER_LOAD_JS)
            await page.wait_for_timeout(wait)
        rec.update(await measure(page))
        frames = []
        for fr in page.frames[1:20]:
            try:
                fm = await measure(fr)
                frames.append(fm | {'text': fm['text'][:200]})
            except Exception as e:
                frames.append({'url': scrub(fr.url), 'error': clip(scrub(str(e)), 100)})
        rec['frames'] = frames
        if shot:
            # The top 4000px; Playwright trims the clip to the page. Uncut, tall pages (XML tree views,
            # long feeds) time out and make images too big to open or check.
            clip = {'x': 0, 'y': 0, 'width': 100000, 'height': 4000} if full_page else None
            await page.screenshot(path=shot, full_page=full_page, clip=clip, scale='css', timeout=20000)
            rec['shot'] = shot
    except Exception as e:
        rec['error'] = clip(scrub(str(e).splitlines()[0]), 300)
    rec['pageErrors'] = errors[:10]
    rec['console'] = console
    await ctx.close()
    return rec


async def guarded(coro, seconds=90):
    # page.evaluate and context.close have no timeout of their own; one hung page would stall the run.
    # Other errors (a crashed browser failing new_context) fail the visit, not the run.
    try:
        return await asyncio.wait_for(coro, seconds)
    except asyncio.TimeoutError:
        return {'error': f'visit timed out after {seconds}s', 'pageErrors': []}
    except Exception as e:
        return {'error': clip(scrub(f'{type(e).__name__}: ' + (str(e).splitlines() or [''])[0]), 300), 'pageErrors': []}


def serve(directory):
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Quiet, directory=directory))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f'http://127.0.0.1:{server.server_port}/'


def text_ratio(a, b):
    return round(difflib.SequenceMatcher(None, a.get('text', ''), b.get('text', '')).ratio(), 3)


def pixel_diff(a, b):
    """Fraction of pixels in the top 2000px that differ noticeably, or None without both shots."""
    try:
        ia, ib = Image.open(a).convert('RGB'), Image.open(b).convert('RGB')
    except Exception:
        return None
    w, h = min(ia.width, ib.width), min(ia.height, ib.height, 2000)
    if not w * h:
        return None
    hist = ImageChops.difference(ia.crop((0, 0, w, h)), ib.crop((0, 0, w, h))).convert('L').histogram()
    return round(sum(hist[17:]) / (w * h), 4)


def here(*parts):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), *parts)
