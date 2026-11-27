# Warns about credentials a steered session could misuse; enforces nothing and always exits 0.
# Checks: SSH to GitHub, a classic or OAuth `gh` token and its scopes, gcloud accounts or application
# default credentials that aren't service accounts, and whether this skill runs from a checkout the
# session can push from (a dry run). Prints no secrets.
# Usage: env_check.py
import json, os, shutil, subprocess

DOC = 'https://github.com/zcorpan-ai/web-platform-skills/blob/main/docs/httparchive-security.md#recommended-environment'


def run(cmd, timeout=20, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr
    except (OSError, subprocess.TimeoutExpired):
        return None, ''


def ssh():
    code, out = run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no',
                     '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', 'git@github.com'])
    if 'successfully authenticated' in out:
        return 'SSH to GitHub works: the session can push wherever that key can'


def gh():
    if not shutil.which('gh'):
        return None
    code, token = run(['gh', 'auth', 'token'])
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or (token.strip() if code == 0 else '')
    if not token.startswith(('ghp_', 'gho_')):
        return None  # none, or fine-grained (github_pat_) or app tokens
    code, out = run(['gh', 'api', '--include', 'user', '--jq', '.login'])
    scopes = next((l.split(':', 1)[1].strip() for l in out.splitlines() if l.lower().startswith('x-oauth-scopes:')), '?')
    return f"`gh` uses a classic token (scopes: {scopes or 'none'}), which covers every repo you can access"


def gcloud():
    out = []
    if shutil.which('gcloud'):
        code, text = run(['gcloud', 'auth', 'list', '--format=json'], timeout=60)
        try:
            accounts = [a['account'] for a in json.loads(text)] if code == 0 else []
        except ValueError:
            accounts = []
        people = [a for a in accounts if not a.endswith('.gserviceaccount.com')]
        if people:
            out.append(f'{len(people)} gcloud account(s) aren\'t service accounts; the session can switch to them with --account')
    cfg = os.environ.get('CLOUDSDK_CONFIG') or os.path.expanduser('~/.config/gcloud')
    adc = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') or os.path.join(cfg, 'application_default_credentials.json')
    try:
        if json.load(open(adc)).get('type') == 'authorized_user':
            out.append('application default credentials are a user account, not a service account')
    except (OSError, ValueError):
        pass
    return out


def checkout():
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.exists(os.path.join(here, '..', 'SKILL.md')):
        return None  # a copy in a research repo, not the skill
    code, top = run(['git', '-C', here, 'rev-parse', '--show-toplevel'])
    if code != 0 or not os.access(top.strip(), os.W_OK):
        return None
    # The session's own credentials, not your account's rights: a dry run writes nothing.
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/usr/bin/false', SSH_ASKPASS='/usr/bin/false')
    code, out = run(['git', '-C', here, 'push', '--dry-run', '--porcelain', 'origin', 'HEAD:refs/heads/env-check-probe'],
                    timeout=30, env=env)
    if code == 0:
        return f'this skill runs from a writable checkout ({top.strip()}) whose origin the session can push to'

if __name__ == '__main__':
    warnings = [w for w in [ssh(), gh(), *gcloud(), checkout()] if w]
    for w in warnings:
        print('WARN', w)
    print(f'{len(warnings)} warning(s). See {DOC}' if warnings else 'ok: no warnings')
