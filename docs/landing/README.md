# The WARDEN landing — what it is and how it ships

One file: [`index.html`](index.html). Five languages (EN/RU/ES/FR/ZH) inlined, no external
assets — no CDN, no font host, no XHR — so the page can be served from anywhere and its
Content-Security-Policy can honestly say `default-src 'none'`.

English is **not** in the dictionary. It is snapshotted from the markup at load time, so the
default copy cannot drift away from what the page actually says; the four other languages are
a `DICT` object next to it. `?lang=ru` and the switcher both work, and the choice is
remembered.

## The numbers on it are tested, not typed

`test/landing.test.ts` in this package fails when the page disagrees with reality:

| Claim on the page | Checked against |
|---|---|
| ruleset version, rule count, block/advise split, name-surface count | `staticScanRuleset()` |
| the digest prefix in the verdict sample | the live ruleset digest |
| built-in threat records | `new ThreatFeed().builtins.length` |
| 1 108 / 17 491 / 2 787 / 492, and `50 → 6` | [`docs/mcp-survey.md`](../mcp-survey.md) |
| that `50 → 6` is labelled a re-run rather than published data | the survey's own provenance note — only the v2/v3 run is committed as data |
| the test count in the hero badge | `docs/badges/tests.svg`, which the badge generator writes from a real run |
| every `data-i18n` key | present and non-empty in all four dictionaries, with no unused keys |

So changing a rule and forgetting the landing is a red test, not a wrong page. That mattered
once already: 0.3.0 shipped with the source at one ruleset version and the published package
at another.

## Where it is served

**Live now:** <https://warden.modelmarket.dev/> — nginx on the host that serves
`use.modelmarket.dev`, from `/var/www/warden.modelmarket.dev/index.html`. Deploy from the
monorepo:

```bash
./scripts/deploy_warden_landing.sh --remote root@<host>            # update the page
./scripts/deploy_warden_landing.sh --remote root@<host> --install-nginx   # + the site config
./scripts/deploy_warden_landing.sh --remote root@<host> --issue-cert      # first time only
```

The script runs the landing test before uploading, checksums the uploaded file, and verifies
that the CSP and `X-Content-Type-Options` headers actually arrive on the wire — a header
written in a config is not a header a browser received, and this site shipped without its CSP
the first time for exactly that reason (`add_header` in an nginx `location` **replaces** the
inherited ones instead of merging, which is why the headers live in
`deploy/nginx/warden-security-headers.conf` and are included per location).

## GitHub Pages — handoff

`.github/workflows/pages.yml` is committed and ready. It needs two things done once, by
someone with admin on the repo:

1. **Create the repository** `alexar76/warden` (empty) and let the satellite mirror push into
   it — the same step the npm release already needs, see the `warden` entry in
   `scripts/satellite-map.yaml`.
2. **Settings → Pages → Build and deployment → Source: GitHub Actions.** That is all; the
   workflow uploads `docs/landing` as the artifact root, so the site lands on
   `https://alexar76.github.io/warden/` and not on `/warden/landing/`.

After that it publishes itself on every push that touches `docs/landing/**`, `src/**` or the
survey, and can be run by hand from the Actions tab. Nothing else needs configuring: no
secrets, no custom domain, no Jekyll (the artifact is uploaded as-is).

If a custom domain is wanted on Pages later, `warden.modelmarket.dev` is already pointed at
the nginx host — so use a second name rather than repointing that one, or the live site goes
down during the switch.
