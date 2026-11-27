# Firefox counterpart of harness.py, with Selenium (BiDi) and geckodriver, for Firefox Nightly, release
# or a local build. Each session runs in a worker process in its own process group, so a visit that
# hangs is killed with its browser and geckodriver and the next visit gets a new session. Sessions:
# - turn Safe Browsing back on (Marionette turns it off) and wait until it blocks and Google's lists are
#   in (safe_browsing_on()), then seed later profiles with this run's lists;
# - send all DNS through the malware-blocking resolver and block the local list (dns_check.py);
# - keep downloads in the session's temp directory, never send crash reports, and leave
#   security.sandbox.* alone (refusing prefs or environment variables that lower it).
# Records have harness.visit()'s shape. Mobile is approximated with prefs (UA, meta viewport, touch,
# a 360px viewport) and keeps desktop defaults otherwise.
#   with harness_firefox.Session(firefox, 'before') as s:
#       rec = s.visit(url, 'desktop', shot='shots/x.png')
# Usage: harness_firefox.py <firefox> <url>...   (one record per URL, to check a setup by hand)
import atexit, json, os, re, shutil, signal, subprocess, sys, tempfile, time
import change, dns_check, harness

MOZ_TEST = 'https://itisatrap.org/firefox/its-an-attack.html'  # in Firefox's built-in test list
SAFE_PREFS = {
    'browser.safebrowsing.malware.enabled': True,
    'browser.safebrowsing.phishing.enabled': True,
    'browser.safebrowsing.blockedURIs.enabled': True,
    'browser.safebrowsing.downloads.enabled': True,
    'browser.crashReports.unsubmittedCheck.autoSubmit2': False,
    'browser.tabs.crashReporting.sendReport': False,
    'browser.download.folderList': 2,
    'browser.download.useDownloadDir': True,
    'browser.download.always_ask_before_handling_new_types': False,
}
# Prefs a setup may not set: they would turn off the sandbox, Safe Browsing, or the DNS and proxy
# settings that block malware hosts.
LOCKED = re.compile(r'^(security\.sandbox\.|browser\.safebrowsing\.|network\.trr\.|network\.proxy\.|network\.dns\.)')
LISTS = os.path.join(tempfile.mkdtemp(prefix='httparchive-fx-lists-'), 'safebrowsing')
atexit.register(shutil.rmtree, os.path.dirname(LISTS), ignore_errors=True)
VISIT_SECONDS = 90


def check_setup(prefs):
    bad = [k for k in prefs if LOCKED.match(k)]
    bad += [k for k in os.environ if k.startswith('MOZ_DISABLE_') and 'SANDBOX' in k]
    if bad:
        raise SystemExit('refusing to load live pages without the sandbox or Safe Browsing: ' + ', '.join(bad))


def firefox_version(binary):
    out = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=60).stdout
    m = re.search(r'(\d+)\.', out)
    return m.group(1) if m else '140'


class Session:
    """One Firefox session in a worker process group. visit() returns a record, or an error record
    when the visit takes over VISIT_SECONDS; the session then restarts."""

    def __init__(self, binary, setup, client='desktop', headless=True):
        prefs = change.BEFORE_PREFS if setup == 'before' else change.AFTER_PREFS
        check_setup(prefs)
        self.config = {'binary': binary, 'setup': setup, 'client': client, 'headless': headless,
                       'lists': LISTS, 'major': firefox_version(binary) if client == 'mobile' else None}
        self.proc = None
        self.start()

    def start(self):
        self.dir = tempfile.mkdtemp(prefix='httparchive-fx-')
        env = dict(os.environ, TMPDIR=self.dir, MOZ_CRASHREPORTER_DISABLE='1')
        self.proc = subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), '--worker', json.dumps(self.config | {'dir': self.dir})],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, start_new_session=True,
            cwd=os.path.dirname(os.path.abspath(__file__)))
        ready = self.read(900)  # the first session waits minutes for Safe Browsing lists
        if not ready or 'error' in ready:
            self.kill()
            raise SystemExit(f"Firefox {self.config['setup']}: {(ready or {}).get('error', 'worker did not start')}")
        self.version, self.build = ready['version'], ready['build']
        print(self.config['setup'], f"Firefox {self.version} ({self.build}), Safe Browsing on after {ready['safeBrowsing']}s", flush=True)

    def read(self, seconds):
        # A line from the worker, or None on timeout or exit.
        import selectors
        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        if not sel.select(seconds):
            return None
        line = self.proc.stdout.readline()
        return json.loads(line) if line else None

    def visit(self, url, client='desktop', shot=None, wait=3000, precheck=True):
        # precheck=False is for smoke_check.py only.
        if client != self.config['client']:
            raise ValueError(f"this session is for {self.config['client']}; start another for {client}")
        skip = precheck and dns_check.page_blocked(url)
        if skip:
            return {'error': skip, 'pageErrors': [], 'console': []}
        if self.proc is None:
            self.start()
        self.proc.stdin.write(json.dumps({'url': url, 'shot': shot, 'wait': wait}) + '\n')
        self.proc.stdin.flush()
        rec = self.read(VISIT_SECONDS)
        if rec is None:
            self.kill()
            self.proc = None
            return {'error': f'visit timed out after {VISIT_SECONDS}s', 'pageErrors': [], 'console': []}
        return rec

    def kill(self):
        if self.proc:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)

    def close(self):
        if self.proc:
            try:
                self.proc.stdin.write('quit\n')
                self.proc.stdin.flush()
                self.proc.wait(20)
            except Exception:
                pass
        self.kill()
        self.proc = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- worker ---

def options(c):
    from selenium.webdriver.firefox.options import Options
    o = Options()
    o.binary_location = c['binary']
    o.enable_bidi = True
    o.page_load_strategy = 'eager'
    if c['headless']:
        o.add_argument('-headless')
    prefs = SAFE_PREFS | dns_check.firefox_prefs() | {'browser.download.dir': os.path.join(c['dir'], 'downloads')}
    if c['client'] == 'mobile':
        m = c['major']
        prefs |= {'general.useragent.override': f'Mozilla/5.0 (Android 10; Mobile; rv:{m}.0) Gecko/{m}.0 Firefox/{m}.0',
                  'dom.meta-viewport.enabled': True, 'dom.w3c_touch_events.enabled': 1}
    prefs |= change.BEFORE_PREFS if c['setup'] == 'before' else change.AFTER_PREFS
    for k, v in prefs.items():
        o.set_preference(k, v)
    if os.path.isdir(c['lists']):
        from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
        seed = os.path.join(c['dir'], 'seed')
        shutil.copytree(c['lists'], os.path.join(seed, 'safebrowsing'))
        o.profile = FirefoxProfile(seed)
    return o


def google_lists_updated(profile_dir):
    try:
        prefs = open(os.path.join(profile_dir, 'prefs.js'), encoding='utf-8', errors='replace').read()
    except OSError:
        return False
    return bool(re.search(r'browser\.safebrowsing\.provider\.google[45]\.lastupdatetime', prefs))


def blocked(driver, url):
    try:
        driver.get(url)
        return 'about:blocked' in driver.execute_script('return document.documentURI')
    except Exception as e:
        return 'about:blocked' in str(e)


def safe_browsing_on(driver, seconds=600):
    # Until blocking is on and Google's lists are in, live pages would load unchecked. Firefox doesn't
    # block Google's test page everywhere (Nightly's real-time lookups are only simulated), so wait for
    # Mozilla's built-in test page to be blocked and for a completed Google list update.
    start = time.time()
    profile_dir = driver.capabilities['moz:profile']
    while time.time() - start < seconds:
        if blocked(driver, MOZ_TEST) and google_lists_updated(profile_dir):
            return round(time.time() - start)
        time.sleep(10)
    raise RuntimeError(f'Safe Browsing not on after {seconds}s ({MOZ_TEST} not blocked or no Google list update); '
                       'not loading live pages')


def resize(driver, w, h):
    # set_window_size includes the browser chrome; grow by the viewport's shortfall.
    driver.set_window_size(w, h)
    iw, ih = driver.execute_script('return [innerWidth, innerHeight]')
    driver.set_window_size(w + (w - iw), h + (h - ih))


MEASURE = 'return Object.assign((' + harness.MEASURE_JS.strip() + ')(), {status: ' \
          "(performance.getEntriesByType('navigation')[0] || {}).responseStatus || null})"


def measure(driver):
    m = driver.execute_script(MEASURE)
    m['url'] = harness.scrub(m['url'])
    if change.EXTRA_MEASURE_JS:
        m['extra'] = driver.execute_script(f'return ({change.EXTRA_MEASURE_JS})()')
    return m


def worker(c):
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from PIL import Image
    import io
    out = sys.stdout
    sys.stdout = sys.stderr  # keep stray prints off the protocol
    try:
        driver = webdriver.Firefox(options=options(c))
        driver.set_page_load_timeout(30)
        driver.set_script_timeout(30)
        sb = safe_browsing_on(driver)
        caps = driver.capabilities
        if not os.path.isdir(c['lists']):
            src = os.path.join(caps['moz:profile'], 'safebrowsing')
            if os.path.isdir(src):
                shutil.copytree(src, c['lists'], dirs_exist_ok=True)
        ext = change.BEFORE_EXTENSION if c['setup'] == 'before' else change.AFTER_EXTENSION
        if ext:
            driver.install_addon(os.path.abspath(ext), temporary=True)
        if change.INIT_JS:
            driver.script.pin('() => {' + change.INIT_JS + '\n}')
        if c['setup'] == 'after' and change.AFTER_INIT_JS:
            driver.script.pin('() => {' + change.AFTER_INIT_JS + '\n}')
        errors, console = [], []
        driver.script.add_javascript_error_handler(lambda e: errors.append(harness.clip(harness.scrub(e.text or ''), 300)))
        driver.script.add_console_message_handler(
            lambda e: e.level in ('error', 'warn') and len(console) < 20 and
            console.append(f"{'warning' if e.level == 'warn' else e.level}: " + harness.clip(harness.scrub(e.text or ''), 300)))
        mobile = c['client'] == 'mobile'
        resize(driver, *((360, 640) if mobile else (1366, 768)))
        print(json.dumps({'version': caps['browserVersion'], 'build': caps.get('moz:buildID'), 'safeBrowsing': sb}), file=out, flush=True)
    except Exception as e:
        print(json.dumps({'error': harness.clip(str(e).splitlines()[0] if str(e) else type(e).__name__, 300)}), file=out, flush=True)
        return
    for line in sys.stdin:
        if line.strip() == 'quit':
            break
        job = json.loads(line)
        errors.clear()
        console.clear()
        rec = {}
        try:
            driver.get(job['url'])  # returns at DOMContentLoaded (eager)
            doc = driver.execute_script('return document.documentURI')
            if doc.startswith(('about:neterror', 'about:blocked', 'about:certerror')):
                raise RuntimeError('error page ' + doc.split('?')[0] + ' ' + (re.search(r'[?&]e=(\w+)', doc) or [''])[0])
            end = time.time() + 15
            while driver.execute_script('return document.readyState') != 'complete':
                if time.time() > end:
                    rec['loadTimeout'] = True
                    break
                time.sleep(0.25)
            time.sleep(job['wait'] / 1000)
            if c['setup'] == 'after' and change.AFTER_LOAD_JS:
                driver.execute_script(f'return ({change.AFTER_LOAD_JS})()')
                time.sleep(job['wait'] / 1000)
            rec.update(measure(driver))
            frames = []
            for el in driver.find_elements(By.CSS_SELECTOR, 'iframe, frame')[:19]:
                try:
                    driver.switch_to.frame(el)
                    fm = measure(driver)
                    frames.append(fm | {'text': fm['text'][:200]})
                except Exception as e:
                    frames.append({'url': None, 'error': harness.clip(harness.scrub(str(e).splitlines()[0]), 100)})
                finally:
                    driver.switch_to.default_content()
            rec['frames'] = frames
            if job['shot']:
                # The top 4000px, like harness.py.
                img = Image.open(io.BytesIO(driver.get_full_page_screenshot_as_png()))
                img.crop((0, 0, img.width, min(img.height, 4000))).save(job['shot'])
                rec['shot'] = job['shot']
        except Exception as e:
            rec['error'] = harness.clip(harness.scrub((str(e).splitlines() or [type(e).__name__])[0]), 300)
        rec['pageErrors'] = errors[:10]
        rec['console'] = list(console)
        try:
            driver.get('about:blank')
        except Exception:
            pass
        print(json.dumps(rec), file=out, flush=True)
    driver.quit()


if __name__ == '__main__':
    if sys.argv[1:2] == ['--worker']:
        worker(json.loads(sys.argv[2]))
    else:
        with Session(sys.argv[1], 'before') as s:
            for u in sys.argv[2:]:
                print(u, json.dumps(harness.scrub_record({'A': s.visit(u)})['A']), flush=True)
