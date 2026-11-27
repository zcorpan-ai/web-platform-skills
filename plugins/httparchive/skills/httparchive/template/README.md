# Compat impact of <change> (<org/repo#issue>)

<!-- Fill in or delete every comment and placeholder. Take each number from a committed file and
     say which. No billing project, account, job IDs, or costs; bytes processed only, in TiB. -->

Proposed change: <what changes, in one or two sentences; which cases differ and which don't>.

## Options

<!-- Only with more than one option or variant: a small table, one row each, with its rule and
     what it does to example inputs; where superseded options came from. One sentence on the
     runs: A and A2 unchanged (A2 measures page noise), B with the option applied. -->

## Summary

<!-- For a reader who decides on shipping and reads only this far. Per option: what shipping it
     would break (seen in the sample, found only by code review, unknown), on what share of all
     pages (and of pages using the feature, where telling); what's behind it (sites, libraries,
     patterns, fixes shipped upstream); how the field rate (use counters) compares. Real cases,
     not argument structure. -->

## How much the data can tell

<!-- Sample design and how its size was set; what the bounds support; what the crawl and method
     can't see (pages the crawl doesn't visit, interaction, logged-in state, special cases in the
     change, other engines); a use counter that would close the gap. -->

## Scope

<!-- So a new context can resume the run: crawl date, clients and denominator, who decides,
     samples and strata, setups, budget, stopping rule, and a line of why for each setup, test
     value and stratum a reader could question. A few bullets. State the scope itself; don't
     mention the kickoff or when it was agreed. -->

## What breaks and why

<!-- Only if something breaks: the cause, traced to the spec or engine code, and each variant
     measured against the change's goal, with the one you'd recommend. The sections below hold
     the data; don't repeat it here. -->

## 1. HTTP Archive

<!-- If a Common Crawl corpus was used too: crawl, seed, WARC count, HTML responses, and which
     numbers come from it (cc.py pick/download). Its pages aren't only root pages. -->

<!-- Crawl date, table, clients, root and/or non-root pages. Each query file, what it selects
     (use counters with where they're incremented, or custom metric fields with a link to the
     metric's source at a commit), and its output file. -->

| | desktop | mobile |
|---|---|---|
| Pages crawled | | |
| <condition> | | |

## 2. Live comparison on a sample

<!-- sample.py's strata, seed, and size (sample.jsonl). The browser and version; the before and
     after setups (flags, build, or emulation, from change.py); the sanity check. compare.py's
     visits: A and A2 before, B after (before A2 on odd-numbered pages), crawl-like viewports, waits, what's
     recorded (scrubbed at capture); output in out/results.jsonl; DNS through Cloudflare's malware-blocking resolver,
     and pages it or security/ lists aren't loaded (not assessable).
     Adult pages flagged by nsfw_check.py (out/nsfw.csv). analyze.py's
     auto-ratings and how many pages were reviewed by hand (out/review/, out/review.csv);
     rechecks with recheck.py. -->

<!-- extrapolate.py output (out/summary.md): -->

| Stratum | Pages | Sampled | Broken | Worse | No visible change | Not assessable |
|---|---|---|---|---|---|---|

| Group | Broken | Worse | No visible change | Not assessable |
|---|---|---|---|---|

What's behind the ratings:

<!-- One bullet per stratum group and rating that matters: the pattern, named sites or
     libraries, the cause, and the review image (out/review/NNN.png) for the clearest case.
     Mark pages in out/nsfw.csv "(nsfw)" and link a repro test instead of an image. -->

## 3. Top-ranked pages

<!-- If the sample has few or no pages in the top rank buckets, run every top-ranked hit through
     the same steps (out-top<N>/) and report the results here. Otherwise delete this section. -->

## Query bytes

All on the <crawl date> crawl, run on <date>:

| Query | Bytes processed (TiB) |
|---|---|

## Reproduce

This run was done with version <version> of the [`httparchive` skill](https://github.com/zcorpan-ai/web-platform-skills/blob/main/docs/httparchive.md). The steps below are standalone and rerun the same analysis without the skill.

```sh
bq query --use_legacy_sql=false --format=csv --max_rows=1000000 < queries/hits.sql > queries/hits.csv
python3 sample.py queries/hits.csv sample.jsonl <seed> <n> <stratum-columns...>
python3 -m venv .venv && .venv/bin/pip install playwright pillow nudenet pyobjc-framework-Vision  # Vision for ocr_check.py on macOS; elsewhere install tesseract. No `playwright install`: the scripts drive an installed Chrome
.venv/bin/python compare.py "$CHROME" sample.jsonl out
.venv/bin/python nsfw_check.py out
.venv/bin/python analyze.py out
# review out/review/*.png by hand and fill in the empty ratings in out/review.csv
python3 extrapolate.py out/review.csv sample.jsonl <client's total pages> > out/summary.md
.venv/bin/python recheck.py "$CHROME" <url> <desktop|mobile> <out.png>
```

<!-- Browser, Playwright, and Pillow versions; anything that changed during the run (run.log);
     that live pages change, so a rerun won't match exactly; that screenshots (out*/shots/)
     aren't committed and compare.py regenerates them. -->

## License

MIT, see [LICENSE](LICENSE), for the scripts, analysis and text written for this research. Content from the crawl and the live web (`queries/`, `crawl/`, screenshots, page snippets) and third-party code (`vendor/`) belongs to its owners and isn't covered.

<!-- If the repo has patches to a browser (changes to an engine's code), add the line: Patches are under the license of the code they modify. -->
