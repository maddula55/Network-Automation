# collect\_data\_rsi\_var\_log

A resilient Junos® data collector that logs in over SSH, generates **RSI** and **/var/log** archives on the device, pulls them back (SFTP → SCP → shell-stream), optionally **bundles** them locally, and can **upload** the results (SFTP or S3). Works directly or through a **jump host**. Designed for incident response and routine support captures.

---

## Highlights

* **End-to-end orchestration:** hostname → generate RSI → archive `/var/log` → verify → download → (optional) bundle → (optional) upload → cleanup.
* **Robust transfers:** tries **SFTP** first, then **SCP**, then **shell streaming** as a last resort.
* **Creation fallback:** if `request support information | save <file>` doesn’t produce a file, uses a **shell redirect** fallback to write RSI output.
* **Jump host (bastion) support** out of the box.
* **Strict host-key** mode with optional `known_hosts`.
* **Concurrency** for many devices; **timeouts** for commands and connections.
* **Deterministic names:** UTC-stamped filenames safe for automation.
* **Uploads:** push artifacts to a remote SFTP path or to **Amazon S3** (with optional SSE/SSE-KMS).

---

## Requirements

* **Python:** 3.8+ (tested with 3.10–3.12).
* **Packages:**

  * `paramiko` (required)
  * `scp` (recommended; enables SCP fallback)
  * `boto3` (optional; only if using `--upload-s3`)
* **Junos device access:** SSH op-mode privileges; shell access only needed for last-resort fallbacks.

Install:

```bash
python3 -m pip install paramiko scp boto3
```

> If you won’t use S3 uploads, `boto3` is not required.

---

## Quick Start

```bash
python3 collect_data_rsi_var_log.py \
  --host blaze-re0.ultralab.juniper.net \
  --user labroot \
  --bundle \
  --verbose
```

* Prompts for the device password if `--password`/`--key-file` are not provided.
* Creates `./junos_support/<hostname>/` containing:

  * `<hostname>_RSI_<UTC>.txt`
  * `<hostname>_VARLOG_<UTC>.tgz`
  * (optional) `<hostname>_SUPPORT_<UTC>.tgz` (bundle of the two)

---

## Usage

```bash
python3 collect_data_rsi_var_log.py [TARGETS] [AUTH] [JUMP] [BEHAVIOR] [UPLOAD] [SSH] [LOGGING]
```

### Targets

* `--host` — One host or a comma-separated list
  e.g. `--host mx1,10.0.0.2`
* `--hosts-file` — File with one host per line (ignores empty lines and `#` comments)

### Authentication

* `--user` **(required)** — SSH username
* `--password` — SSH password (or it will prompt)
* `--key-file` — Private key for device (RSA/ECDSA/Ed25519/DSS)
* `--key-passphrase` — Passphrase for `--key-file`
* `--port` — Device SSH port (default: `22`)

> If both `--key-file` and `--password` are given, the script tries the key first, then password.

### Jump/Bastion Host (optional)

* `--jump-host` — Bastion hostname
* `--jump-port` — Bastion SSH port (default: `22`)
* `--jump-user` — Bastion username (defaults to `--user`)
* `--jump-password` — Bastion password
* `--jump-key-file`, `--jump-key-passphrase` — Bastion private key + passphrase

### Behavior

* `--output-dir` — Local output root (default: `./junos_support`)
* `--bundle` — Create a local `tar.gz` bundle of RSI + VARLOG
* `--keep-remote` — Do **not** delete files from device after download
* `--dry-run` — Print operations without making changes
* `--no-shell-fallback` — Disable last-resort shell streaming download
* `--connect-timeout` — SSH connect timeout seconds (default: `30`)
* `--cmd-timeout` — Command timeout seconds for long ops (default: `1800`)

### Uploads (optional)

**SFTP upload (to a non-Junos server):**

* `--upload-scp-host` — Upload to this SFTP/SCP-capable host
* `--upload-scp-port` — Port (default: `22`)
* `--upload-scp-user` — Username (defaults to `--user`)
* `--upload-scp-password` — Password
* `--upload-scp-key-file`, `--upload-scp-key-passphrase` — Private key + passphrase
* `--upload-scp-path` — Remote directory (default: `/tmp`)
* `--upload-bundle-only` — Upload only the local bundle (requires `--bundle`)
* `--upload-scp-strict-host-key` — Enforce strict host key check for upload target
* `--upload-scp-known-hosts` — Path to a known\_hosts file for upload target

**S3 upload:**

* `--upload-s3` — S3 URI like `s3://bucket/prefix`
* `--aws-profile` — AWS profile for `boto3` session
* `--s3-sse` — `AES256` or `aws:kms` (optional)
* `--s3-kms-key-id` — KMS key ID if using `aws:kms`

### SSH / Host Key Behavior

* `--strict-host-key` — Reject unknown device/jump host keys
* `--known-hosts` — File containing known host keys (used when strict mode set)

### Concurrency & Logging

* `--threads` — Parallel threads for multiple hosts (default: `4`)
* `--verbose` — More logging
* `--log-file` — Also write logs to given file

---

## What It Does (Flow)

1. **Connect** to device (optionally via jump host).
2. Detect **hostname** (CLI → config → shell).
3. Create well-known filenames in `/var/tmp`:

   * `<hostname>_RSI_<UTC>.txt`
   * `<hostname>_VARLOG_<UTC>.tgz`
4. Generate **RSI** using:

   * Primary: `cli -c 'request support information | save <file>'`
   * Fallback: **shell redirect** → `cli -c "request support information" | no-more` **to file**
     (fallback used when the saved file doesn’t appear or CLI indicates an error)
5. Create **/var/log** archive:
   `cli -c 'file archive compress source /var/log destination <file>'`
6. **Verify** (CLI-first) that remote files exist and are non-empty.
7. **Download** with **SFTP → SCP → shell streaming** (last resort).
8. **Bundle** locally (optional).
9. **Upload** to SFTP or S3 (optional).
10. **Cleanup** remote files (unless `--keep-remote`).

---

## Output Layout & Naming

Local files go to:

```
<output-dir>/<hostname>/
  <hostname>_RSI_<UTC>.txt
  <hostname>_VARLOG_<UTC>.tgz
  <hostname>_SUPPORT_<UTC>.tgz   # when --bundle is used
```

* `<UTC>` is `YYYYMMDDTHHMMSSZ` (e.g., `20250911T214306Z`)
* Hostname is sanitized to be filename-safe.

---

## Examples

**Multiple hosts, key auth, bundle, verbose:**

```bash
python3 collect_data_rsi_var_log.py \
  --hosts-file devices.txt \
  --user labops \
  --key-file ~/.ssh/id_ed25519 \
  --bundle --threads 8 --verbose
```

**Jump host & S3 upload (KMS encryption):**

```bash
python3 collect_data_rsi_var_log.py \
  --host qfx1,ptx2 \
  --user labroot --password '...' \
  --jump-host bastion.example.net --jump-user jumplab \
  --bundle --upload-bundle-only \
  --upload-s3 s3://jtac-support/msft/ \
  --s3-sse aws:kms --s3-kms-key-id arn:aws:kms:us-east-1:123456789012:key/abcd-... \
  --strict-host-key --verbose
```

**Upload to SFTP share:**

```bash
python3 collect_data_rsi_var_log.py \
  --host mx1 \
  --user labroot --password '...' \
  --bundle \
  --upload-scp-host files.example.com \
  --upload-scp-user ops \
  --upload-scp-path /srv/support/incoming \
  --upload-scp-strict-host-key --upload-scp-known-hosts ~/.ssh/known_hosts \
  --verbose
```

`devices.txt` example:

```text
# lab core devices
mx1.dc.example.com
ptx1.dc.example.com
qfx22.dc.example.com
```

---

## Exit Codes

* `0` — All targets succeeded
* `1` — One or more targets failed
* `2` — Input/argument/setup error (e.g., missing dependency, invalid path)

---

## Logging

Default console output is UTC-stamped. Use `--verbose` for debug-level details and `--log-file` to tee logs to a file.

Typical lines:

```
2025-09-11 21:43:06,242Z | INFO    | collector_0 | [host] Generating RSI -> /var/tmp/host_RSI_20250911T214306Z.txt
2025-09-11 21:43:06,820Z | WARNING | collector_0 | [host] SFTP not available (will fall back to SCP/CLI): Channel closed.
2025-09-11 21:43:10,000Z | INFO    | collector_0 | [host] RSI generated at /var/tmp/...
```

---

## Security Considerations

* Prefer **key-based** auth when possible.
* Use `--strict-host-key` with `--known-hosts` to prevent MITM risks.
* Avoid shell history leaks: pass secrets via environment or prompt rather than embedding in commands.
* The script writes to `/var/tmp` on devices; ensure sufficient space or specify maintenance windows accordingly.

---

## Troubleshooting

**“SFTP not available…” repeats**
The script detects once and falls back; subsequent polls are quiet (debug-level). This is normal when the device disables SFTP. Transfers will use SCP or shell streaming.

**RSI file never appears**
The script detects this and uses a **shell-redirect fallback** to force RSI content into the file. If both fail:

* Check device space (`show system storage`)
* Check permissions on `/var/tmp`
* Ensure shell access isn’t restricted by security policy
* Increase `--cmd-timeout` for large/slow RSI generation

**Archive step fails**
You’ll see: `Log archive failed …`
Check `/var/log` size/permissions, free space in `/var/tmp`, and device load. Increase `--cmd-timeout`.

**Downloads fail (SFTP/SCP/shell)**

* SCP requires the `scp` Python package (install `scp`).
* Shell streaming needs `start shell` permission.
* Network middleboxes (firewalls/ALG) may kill large channels; try again or use a jump host close to the device.

**Strict host key issues**

* Use `ssh-keyscan` (outside this script) to populate `--known-hosts` with the device and jump host keys.

---

## Design Notes

* **Verification-first philosophy:** we don’t assume success; we check file existence/size via CLI parsing (`file list detail … | no-more`).
* **Resilient fallbacks:** multiple independent ways to generate and retrieve data reduce on-call surprises.
* **Polite polling:** exponential backoff while waiting for long-running operations; capped sleep to keep the UI responsive.

---

## FAQ

**Q: Can I collect only RSI or only logs?**
A: Not in this version. If you want that, we can add `--skip-rsi` and `--skip-logs` flags easily.

**Q: How big can RSI get?**
A: Depends on platform and active features; tens to hundreds of MB in some cases. Use a larger `--cmd-timeout` if needed.

**Q: Do I need shell access?**
A: Only for last-resort fallback paths (RSI redirect and shell-stream download). If shell is disabled, SFTP/SCP paths still work when available.

**Q: What about dual-RE devices?**
A: RSI collection runs where the CLI command executes. If you need RE-specific captures, run per-RE or extend the script to target REs explicitly.

---

## Changelog (behavioral highlights)

* Robust CLI parsing for remote file sizes.
* One-time SFTP unavailability warning (no spam).
* RSI **shell-redirect fallback** when `| save` doesn’t materialize a file.
* Jump host honors `known_hosts` under strict mode.
* Gentle polling with exponential backoff while files are being created.

---

## Contributing

* Open issues with logs (use `--verbose`) and your exact command line (scrub secrets).
* PRs welcome for:

  * `--skip-rsi` / `--skip-logs`
  * Per-artifact timeouts (`--rsi-timeout`, `--logs-timeout`)
  * Disk space preflight checks on `/var/tmp`
  * RE-aware RSI collection

---

## License
#No warranties or enhancements
#Not liable for any damages as a result of using the program
#Adapt or add a LICENSE file as appropriate for your org.
