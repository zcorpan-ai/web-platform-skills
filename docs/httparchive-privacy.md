# Privacy of `httparchive` research repos

The `httparchive` and `httparchive-qa` skills build a git repo meant to be published: queries and
their output, samples, scripts, run output, review images, and a README. This page says what such a
repo can reveal and how the skills handle it. For security during a run, see
[httparchive-security.md](httparchive-security.md).

## What can identify you

- **Your IP address and location.** Live pages show them: block and captcha pages print your IP,
  sites geo-target text, ads, titles and redirects, search and shopping hosts are country-specific
  (`google.se`), and screenshots can show region or currency pickers. Before the first live load,
  the agent writes your public IP, city, region, country name and demonym to `.publish-terms`
  (gitignored). The harness scrubs output at capture (`scrub()`, `scrub_record()` in `harness.py`):
  it drops query strings, `data:` payloads, page text, titles and final URLs, and masks
  country-specific hosts. The pre-commit hook blocks commits containing the terms or any IP address,
  and OCRs staged images for them. Commit crops around the change rather than full pages where they
  suffice. OCR misses purely visual hints (flags, maps, logos), so the agent also looks at a sample
  by eye.
- **Your accounts.** The hook also blocks your home directory, OS username, git email, gcloud
  account and project, and BigQuery job IDs. The README gives bytes processed per query, not costs
  or the billing project.
- **Tokens.** Tracking IDs and session tokens in URLs and payloads are dropped by the scrubbing and
  caught by the hook's query string, base64 and hex patterns. Patterns GitHub's secret scanning alerts
  on (API keys, public client IDs) are blocked even in crawl data; the agent redacts them.
- **Your local setup.** `skill-local.diff` (local changes to the skill), `skill-notes.md` (notes for
  improving the skill) and `status.html` are gitignored, and the README says only whether the skill
  had local changes, not what they were.
- **That the research exists.** The agent offers a pull request with lessons for the skill only after
  you've published the research, since the PR would reveal it.

Whatever you publish, live loads from your own connection show every sampled site and its third
parties (ad networks, analytics) your IP address and when you visited. A VPN or a cloud host avoids
that, and keeps your own IP out of the output too.

## Other people's data

Crawl data and screenshots can hold personal data of a site's users and staff: names, email
addresses, comments, photos. Publish only what a finding needs. The skill quotes page strings only
when the finding needs them, in code spans, never as links or @mentions, so they can't ping or send
readers anywhere. Link evidence to committed review images rather than the live site.

The repo's MIT license covers its own scripts, analysis and text, not page content from the crawl
or the live web, or third-party code; the README's License section says so.

## Publishing is permanent

Before every push the agent runs `publish_check.py` over every blob in history, not only the latest
commit, and rewrites history to fix hits. Once pushed, force-pushing isn't enough: GitHub serves old
commits by SHA until the repo is deleted and recreated, and the data may already be copied. You run
the commands that create the repo, push, and post; the agent only gives them to you.

## Adult and illegal content

Sampled pages include adult sites. After each live run, `nsfw_check.py` flags pages with an adult
`<meta name="rating">`, a host on the OISD NSFW list, or a host blocked by Cloudflare's family
resolver, and `analyze.py` puts their review images in the gitignored `review-nsfw/`. The agent adds
pages it sees by eye. The pre-commit hook blocks staged images of flagged pages and images where
NudeNet finds nudity. Flagged pages are reviewed and reported like any other, marked `(nsfw)` where
cited, described only when a finding needs it and in neutral wording, with a minimal repro test as
the evidence instead of an image.

Limits: NudeNet catches exposed nudity, not other adult content, and less in downscaled images; it
also flags nude paintings. Violent, gory or hateful content isn't detected at all. Look at the
images you publish.

If a run surfaces illegal content, such as child sexual abuse material: stop, don't keep, commit or
send it to an agent, report it to a hotline ([NCMEC](https://report.cybertip.org/) in the US,
[IWF](https://report.iwf.org.uk/) in the UK, or another [INHOPE](https://www.inhope.org/) member),
and follow your employer's process.

## Limitations

- Scrubbing and the publish check are pattern matches, and OCR and nudity detection are
  heuristics: they catch common cases, not all. They're also scripts the agent can change (see
  [httparchive-security.md](httparchive-security.md#what-is-enforced-and-what-isnt)).
- Location can leak in ways no check sees: a page's layout or language, the choice of sites that
  loaded or were blocked.
- Review the repo before you push it.
