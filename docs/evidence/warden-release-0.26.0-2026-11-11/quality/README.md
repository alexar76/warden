# WARDEN 0.26.0: MOMUS release gate — passed, production on the evaluated image

**Done 2026-11-11 (owner: «Yes, switch»):**
- `switch.sh` ran on histor-host: healthy on `sha256:a1a3ab93…` (`switch.log`);
- `skopos-warden-quality live sha256:a1a3ab93…` → LIVE_OK. `live-image.json` binds build `de9f98d6…`;
- the public `latest.json` is run `20261111T110826`, phase live, source 52fffde67, full evidence until
  2026-11-13 10:37:26Z (`latest-signed-after.json`);
- WARDEN's own `scripts/check-quality-gate.mjs` on the release archive prints `MOMUS release gate passed:
  20261111T110826, de9f98d6…` (`check-quality-after.log`).

Only the npm publish is left (colleague-tasks §96). The gate needs `evaluatedAt` within 48 hours, so publish
before 2026-11-13 11:08Z or ask for a new run.

The record below is from before the switch.


2026-11-11. The release archive is `../aimarket-warden-0.26.0.tgz` from 52fffde67:
- SHA-256 `ff8e9fc959caf1ec…`;
- MOMUS build digest `de9f98d627832446e0433cd112898d1106758f89f31506feeed71a7903530ec8`.

## Where things run now

- **HISTOR production** runs on histor-host, `/opt/histor`, compose project `histor`. The image is chosen by
  `docker-compose.warden-image.yml`. It runs `histor-histor:pre-wd-20261111` = `sha256:da716f98…` with WARDEN 0.25.0.
- **MOMUS** stays on admin-vps:
  - `/usr/local/sbin/skopos-warden-quality`, state in `/var/lib/momus-quality`;
  - it reads the live image from the HISTOR host through `/.well-known/aicom-histor-runtime.json` (allowed only for
    admin-vps);
  - it reads sandbox credentials from the stopped old `histor-histor-1` on admin-vps, which must stay stopped. The
    daily `momus-quality.service` failed at 03:25Z today for this reason. The container was running again from
    11-10 14:47Z to 11-11 10:37Z.

## What was wrong with the first candidate

The earlier candidate `ee4f043c0c57` (run `20261111T103726`, passed) was built FROM
`aicom-security:histor-histor-1-badge-20261109`, which carries HISTOR 0.6.2:
- `compare_images.py`: 1,002 files of production are missing from it, among them `histor/revision.py`,
  `signed_revisions.py` and `peers.py`, and 39 more differ;
- moving production onto it would have rolled HISTOR back.

## This candidate

`Dockerfile.candidate` builds FROM the running production image. It replaces only
`/app/scanner/node_modules/@aimarket/warden` (the archive above) and `/opt/warden-source/src` (`git archive
52fffde67 warden/src`), with the label `skopos.source.commit=52fffde67532419fa86582c26cff91ce648a595f`.

- Image `histor-histor:warden-0.26.0-prod` = `sha256:a1a3ab932a6b4adfa8b1e85334824947a61d7d46078d08421535d390f4f93b0a`.
  It was built on the HISTOR host, then `docker save | docker load` to admin-vps; the ID is the same.
- `verify_candidate.py`: every file of the two filesystems compared, 10,899 against 10,978. Outside the two WARDEN
  folders nothing is missing, added or different. WARDEN 0.26.0, 68 dist files, build digest `de9f98d6…`. The package
  imports.
- MOMUS candidate run `20261111T110826`, unit `warden-release-quality-0260-prod-20261111`, 11:08:23–11:11:06Z, exit 0.
  The signed receipt is `candidate-signed.json`:
  - status passed;
  - development 8,244 attacks and 362 benign: 0 missed, 0 false positives, 0 incomplete;
  - held-out passed;
  - 18 discovery candidates;
  - behaviour 72 of 72 executed, smoke passed.

  It reused the same-day full measurement of the identical build, so its full evidence expires
  **2026-11-13 10:37:26Z**.
- `skopos-warden-quality authorize sha256:a1a3ab93…` accepts the image.

## The public receipt

`check-quality-gate.mjs` reads `https://histor.modelmarket.dev/security-quality/latest.json`.
- The HISTOR host served those two paths from local files, which were copied by hand at 10:31Z and go stale with
  every new signature.
- Since 2026-11-11 ~11:10Z its nginx proxies `/security-quality/{latest,candidate}.json` to admin-vps (
  SNI and Host `histor.modelmarket.dev`), where MOMUS writes them. The receipt is Ed25519-signed, so the transport adds
  no trust. The public file was checked byte-identical to admin-vps's.
- The same change is in `histor/deploy/nginx/histor.modelmarket.dev.conf`. Backup on the host:
  `/root/wd026-prod-20261111/nginx-histor.pre-receipt-proxy`.
- **admin-vps must keep its nginx vhost for histor.modelmarket.dev** (it now serves only these receipts).
- `latest-signed-before.json` is the live receipt before promotion: WARDEN 0.25.0, run `20261110T142549`.

## Left, in order (before 2026-11-13 10:37Z)

1. **Production switch** on histor-host: `bash /root/wd026-prod-20261111/switch.sh` (`switch.sh` here). It
   changes only the image line of `docker-compose.warden-image.yml`, recreates `histor`, waits until it is healthy and
   checks the image ID. The rollback is in its header.
2. **Live promotion** on admin-vps: `/usr/local/sbin/skopos-warden-quality live
   sha256:a1a3ab932a6b4adfa8b1e85334824947a61d7d46078d08421535d390f4f93b0a`. It publishes `latest.json` for build
   `de9f98d6…`.
3. `cd warden && npm run check:quality` prints `MOMUS release gate passed: … de9f98d6…`.
4. npm publish by the colleague (colleague-tasks §96).
