# Security of `httparchive` runs

The `httparchive` and `httparchive-qa` skills load arbitrary public websites in real browsers, read
crawled response bodies, run billed BigQuery queries, and build a git repo meant to be published.
This page says what protects you during a run, what is enforced and what only the agent upholds, and
how to set up an environment that limits the damage when something gets through. For what a
published research repo can reveal, see [httparchive-privacy.md](httparchive-privacy.md).

## Threat model

Anything from the crawl or the live web can be written by an attacker: HTTP Archive and Common Crawl
are just public websites, including compromised sites, ad networks, and user-generated content
(comments, forum posts, listings) on legitimate ones. So can libraries, polyfills and extensions
under test, and comments on the issues and bugs the agent reads. The skills' source is public, so an
attacker can read every defense: the rules the agent follows, the scrubbing regexes, the paths the
publish check skips, the reviewer's brief format, and the blocklists in use.

What an attacker could go after:

- Credentials the session can reach: a GitHub token and SSH agent, gcloud credentials (every
  credentialed account, not only the active one), Claude Code's own login, and any file the OS user
  can read.
- Write access: pushing to repos you can push to, including skills other people install (a supply
  chain attack), posting issue or bug comments, creating gists.
- The billing account, by getting the agent to run large queries.
- The conclusion: a ship or spec decision rests on the published estimate, so data crafted to look
  compatible (or broken) is an attack even without any instruction in it.
- The tester's identity and location, through what gets published.
- The machine and its network, through a browser exploit, or a page reaching services on `localhost`
  or the LAN.

## What is enforced and what isn't

The template's scripts make the safe path the default and catch mistakes. They don't constrain an
agent that has been steered: the agent writes and adapts the research repo's scripts by design, and
can edit, skip or replace any of them. Only controls outside the agent's reach are guarantees.

| Property | Enforced by | Can the agent change it? |
|---|---|---|
| What the session's credentials can do (GitHub token scopes, IAM roles of the gcloud account) | GitHub, Google Cloud | No, but it can use any other credential the OS user has |
| Hard cap on BigQuery spend (custom quota) | Google Cloud | No |
| Per-query cap (`--maximum_bytes_billed`) and asking before billed queries | The agent passes the flag and asks | Yes |
| Secret scanning push protection, branch protection | GitHub | No (unless the token can change repo settings) |
| The browser's own sandbox, once launched with it | The browser and OS | It chooses the launch arguments |
| `harness.py` refusing `--no-sandbox` and Safe Browsing switches, waiting for Safe Browsing, malware DNS, local blocklist | Template scripts | Yes |
| The same for Firefox and Safari | Harness the agent writes from the skill's text | Yes |
| Scrubbing live-load output (`scrub()`, `scrub_record()`) | Template scripts | Yes |
| Pre-commit publish check, OCR and nudity checks | Git hook running `publish_check.py` | Yes (`--no-verify`, `core.hooksPath`, editing the scripts or `.publish-terms`) |
| `page-reviewer` having only Read, Glob and Grep | Claude Code | No, but its report goes back to the main agent |
| Claude Code permission rules, sandbox, managed settings | Claude Code, the OS | Not if set where the session can't write (managed settings) |
| Auto mode's classifier | Claude Code | No, but it's a per-action check, not a boundary |
| You running the push and comment commands yourself | The skill's text | Yes, if the session has push credentials |
| Everything else in SKILL.md (untrusted content rules, budget, scope) | The agent | Yes |

The skill's own files are writable too when installed from a git checkout or the plugin cache.

## Untrusted content and prompt injection

Crawl and page content reaches the main agent through query output (snippets of response bodies),
console and error strings in `results.jsonl`, issue comments, reviewers' reports, and page text from
browser MCP tools if those are used. The skills:

- Treat all of it as data, never instructions; approvals, the budget and the scope come only from
  you, in chat or as recorded in the README at kickoff.
- Hand page material (dossiers, review images, bodies to classify) only to the read-only
  `page-reviewer` agent, keep it out of the brief, and wrap quoted snippets in `<pasted_content>`
  tags with a fresh random id per brief, so a snippet can't close the tag.
- Treat reviewers' verdicts as claims: check any that cite instructions in the material, spot-check
  the rest, and write and run proposed tests itself rather than running code from a report.
- Scrub and clip strings at capture, and keep page text and titles out of stored results.
- Quote page strings in published text only in code spans, never as links or @mentions.
- Keep downloaded files in their own directories, pass them as path arguments, run Python reading
  them with `-I`, and install packages under test with `npm install --ignore-scripts`.
- Take skill-improvement notes only from the agent's own experience, not from content asking for
  changes.

Limits: none of this is a guarantee. A model can still be steered; 300 characters of console text
are enough for an instruction; the reviewer's report is itself a channel; and data can skew the
verdict without any instruction in it. Look at the repo and the review images before relying on the
conclusion.

## Browsers and malicious sites

Live runs load pages the agent has never seen. The template's harness:

- Launches Chrome with its sandbox (Playwright adds `--no-sandbox` otherwise) and refuses arguments
  that turn it or Safe Browsing off; for Firefox the skill asks for the Safe Browsing prefs that
  Marionette turns off, and never to lower `security.sandbox.*`.
- Keeps Safe Browsing and security component updates on, and waits until Google's Safe Browsing test
  page is blocked before loading any live page.
- Sends all of the browser's DNS through Cloudflare's malware-blocking resolver with no fallback, so
  subresources, frames and redirect targets on its list fail too, and makes hosts in the gitignored
  `security/*.txt` unreachable (a list from your security team, or a hosts file like URLhaus's).
- Checks each page's host before loading it, and skips the page if the lookup fails.
- Smoke-tests the setup: no browser process with `--no-sandbox`, and the malware test pages and a
  listed host fail to load as a page and as a subresource.

What that doesn't cover:

- Blocklists lag behind new malware hosts, and a site that isn't malware can still serve a stored
  prompt injection or a malicious ad.
- A renderer exploit plus a sandbox escape runs code as your OS user, with everything that user can
  reach. Up-to-date browsers get fixes first, but Canary and Nightly also carry new bugs, and local
  builds (debug, ASan, or without Google API keys and so without Safe Browsing, which makes the
  harness stop) differ from release.
- Pages can crash the browser; the harness relaunches it. Crash reporters can send the URL with the
  report.
- Pages can send requests to `localhost` and the LAN (local test servers, dev servers, routers),
  limited only by the browser's local network protections.
- Pages can download files: Playwright accepts them into a temporary directory; a Firefox profile
  saves them to its download directory unless the harness sets it.
- Extensions under test run with extension privileges.
- Browser MCP servers you've configured get none of the harness's protections, and put page text
  straight into the agent's context.

## Recommended environment

An unrestricted session (your everyday OS account, auto mode, all your credentials) has far more
reach than a run needs: an agent steered by page content could read and leak secrets, or push and
post, and only the auto mode classifier, if it catches it, stands in the way. A run needs much less:

- **Isolation.** Run in a VM, or at least a separate OS user, holding only what the run needs: a
  macOS VM for Safari TP, a Linux VM or container otherwise. This is the only boundary that contains
  a browser escape or a fully steered agent. Claude Code's own docs recommend a VM or a
  [devcontainer](https://code.claude.com/docs/en/devcontainer) for untrusted web content
  ([security](https://code.claude.com/docs/en/security),
  [sandbox environments](https://code.claude.com/docs/en/sandbox-environments)). Give it no route to
  your LAN, and route its traffic through a VPN or a cloud host if page operators shouldn't see your
  IP address.
- **Google Cloud.** A dedicated project for runs, and a service account with
  `roles/bigquery.jobUser` on the project and `roles/bigquery.dataEditor` on one scratch dataset
  (HTTP Archive's tables are public), plus `bigquery.jobs.list` (in `roles/bigquery.user`) for the
  skill's actual-cost check. Set the BigQuery custom quotas "Query usage per day" and "Query usage
  per day per user" on the project: they are the only hard cap on spend (budget alerts don't stop
  queries), and they bound what a leaked key can spend too. Keep your personal and organization
  accounts out of that gcloud configuration (a separate `CLOUDSDK_CONFIG` directory), or the agent
  can switch accounts with `--account`.
- **GitHub.** A run needs no write access: you create the repo, push, and post. Give the session no
  GitHub token, or a fine-grained read-only one for public repositories in `GH_TOKEN`, and no SSH
  agent. Publish from your normal shell. Protect `main` on repos you maintain, above all skills
  others install.
- **Claude Code.** Install the plugin from the marketplace rather than from a checkout you can push
  from. Claude Code's built-in Bash [sandbox](https://code.claude.com/docs/en/sandboxing) doesn't fit
  live runs: its network allowlist can't cover arbitrary sites, how browsers' own sandboxes behave
  inside it on macOS isn't documented, and an `excludedCommands` exception runs the browser with
  full access. [Permission rules](https://code.claude.com/docs/en/permissions) still help, enforced
  by Claude Code: `Read` deny rules for `~/.ssh`, `~/.config/gh` and `~/.config/gcloud` (they also
  block edits there, but reach Bash only for commands like `cat`, not a script that opens the file
  itself), `Edit` deny rules for the research repo's `hooks/` and `*_check.py` and the plugin's
  directory, and `permissions.blockWritesOutsideWorkingDirectories`. Put them in managed settings
  (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS), with
  `disableBypassPermissionsMode`, so the session can't loosen them. Treat them as speed bumps, not
  a boundary. Auto mode "does not guarantee safety", per its docs.
- **Before publishing**, run `publish_check.py` yourself from a copy the session couldn't write
  (e.g. the installed plugin's `template/`, if it's outside the session's reach), and diff the
  repo's `publish_check.py`, `*_check.py` and `hooks/` against the template.

## Limitations

- Prompt injection defenses are instructions to the agent, not guarantees.
- Malware blocklists, nudity detection, OCR and scrubbing are heuristics with known misses.
- The guarantees above hold only for what the environment enforces; in a default setup that's little
  more than the browsers' own sandboxes.
- Agents make mistakes; review the findings and images before relying on them.
