# Prints the installed skill's version as one line for a research repo's README, e.g.
# "0.30.0 (abc1234, with local changes)", "0.30.0 (abc1234)" or "0.30.0".
# Usage: python3 skill_version.py REPO_DIR
#   Version: "version" in the plugin's agent manifest (.claude-plugin/plugin.json, else
#   gemini-extension.json, two directories up from this script), else "unknown".
#   If the plugin directory is in a git checkout: the checkout's short HEAD, and whether
#   `git --no-optional-locks status --porcelain -- .` in the plugin directory shows changes. If
#   it does, `git diff HEAD -- .` plus untracked files' names (`git ls-files --others
#   --exclude-standard -- .`) go to REPO_DIR/skill-local.diff (gitignored; never publish it).
# Only reads the checkout; never writes to it.
import json, subprocess, sys
from pathlib import Path

MANIFESTS = ['.claude-plugin/plugin.json', 'gemini-extension.json']


def git(plugin, *args):
    r = subprocess.run(['git', '--no-optional-locks', *args], cwd=plugin,
                       capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def version(plugin):
    for name in MANIFESTS:
        try:
            v = json.loads((plugin / name).read_text()).get('version')
        except (OSError, ValueError):
            continue
        if v:
            return str(v)
    return 'unknown'


def main():
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 skill_version.py REPO_DIR')
    repo = Path(sys.argv[1])
    plugin = Path(__file__).resolve().parents[2]
    line = version(plugin)
    head = git(plugin, 'rev-parse', '--short', 'HEAD')
    if head:
        extra = [head.strip()]
        if git(plugin, 'status', '--porcelain', '--', '.'):
            diff = git(plugin, 'diff', 'HEAD', '--', '.') or ''
            untracked = git(plugin, 'ls-files', '--others', '--exclude-standard', '--', '.') or ''
            if untracked:
                diff += '\n# Untracked files:\n' + ''.join('# ' + f + '\n' for f in untracked.splitlines())
            (repo / 'skill-local.diff').write_text(diff)
            extra.append('with local changes')
        line += ' (' + ', '.join(extra) + ')'
    print(line)


main()
