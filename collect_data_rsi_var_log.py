#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
collect_data_rsi_var_log.py

Collects RSI and /var/log archive from Juniper (Junos) devices over SSH, with:
- Jump host support
- SFTP optional; automatic SCP fallback
- Robust CLI fallback for remote file verification (regex parsing)
- Optional shell-stream fallback to retrieve files if SFTP/SCP are unavailable
- Well-known UTC-stamped filenames
- Optional local bundling and optional uploads (SFTP/SCP or S3)
- Concurrency, timeouts, dry-run, keep-remote, strict host key checking
- Built-in wait/poll for slow RSI/log archive creation
"""

import argparse
import concurrent.futures as cf
import getpass
import logging
import os
import re
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict

# Third-party
try:
    import paramiko
except ImportError:
    print("ERROR: This script requires 'paramiko'. Install with: pip install paramiko", file=sys.stderr)
    sys.exit(2)

try:
    from scp import SCPClient
    _SCP_AVAILABLE = True
except Exception:
    _SCP_AVAILABLE = False

# boto3 is optional; only required if using --upload-s3
try:
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
    _BOTO3_AVAILABLE = True
except Exception:
    _BOTO3_AVAILABLE = False


# ----------------------------
# Constants & Defaults
# ----------------------------

DEFAULT_SSH_PORT = 22
DEFAULT_CMD_TIMEOUT = 1800  # 30 minutes
DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_THREADS = 4
LOG_FORMAT = "%(asctime)sZ | %(levelname)-7s | %(threadName)s | %(message)s"


# ----------------------------
# Utilities
# ----------------------------

def utc_now_iso_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def setup_logging(verbose: bool, log_file: Optional[Path]) -> None:
    logging.captureWarnings(True)
    formatter = logging.Formatter(LOG_FORMAT)
    formatter.converter = time.gmtime  # UTC timestamps

    handlers: List[logging.Handler] = []
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    handlers.append(sh)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(formatter)
        handlers.append(fh)

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, handlers=handlers)


def load_private_key(key_file: Path, passphrase: Optional[str]) -> Optional[paramiko.PKey]:
    if not key_file.exists():
        raise FileNotFoundError(f"Key file not found: {key_file}")
    exceptions = []
    for cls in (paramiko.RSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.DSSKey):
        try:
            return cls.from_private_key_file(str(key_file), password=passphrase)
        except Exception as e:
            exceptions.append(e)
    raise ValueError(f"Unable to load private key {key_file}. Errors: {exceptions}")


def parse_host_list(host: Optional[str], hosts_file: Optional[Path]) -> List[str]:
    targets: List[str] = []
    if host:
        targets.extend([h.strip() for h in host.split(",") if h.strip()])
    if hosts_file:
        if not hosts_file.exists():
            raise FileNotFoundError(f"--hosts-file not found: {hosts_file}")
        with hosts_file.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    targets.append(s)
    if not targets:
        raise ValueError("No targets provided. Use --host or --hosts-file.")
    return targets


def human_bytes(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


def sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ----------------------------
# SSH / SFTP / SCP Management (with Jump Host)
# ----------------------------

class SSHConnection:
    """
    Paramiko wrapper with jump host support, SFTP/SCP helpers, and shell streaming.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        pkey: Optional[paramiko.PKey],
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
        strict_host_key: bool = False,
        known_hosts: Optional[Path] = None,
        jump_host: Optional[str] = None,
        jump_port: int = DEFAULT_SSH_PORT,
        jump_username: Optional[str] = None,
        jump_password: Optional[str] = None,
        jump_pkey: Optional[paramiko.PKey] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.pkey = pkey
        self.connect_timeout = connect_timeout
        self.strict_host_key = strict_host_key
        self.known_hosts = known_hosts

        self.jump_host = jump_host
        self.jump_port = jump_port
        self.jump_username = jump_username
        self.jump_password = jump_password
        self.jump_pkey = jump_pkey

        self._client = paramiko.SSHClient()
        if strict_host_key:
            if known_hosts:
                self._client.load_host_keys(str(known_hosts))
            self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self._jump_client: Optional[paramiko.SSHClient] = None
        self._sftp_known_unavailable = False  # to suppress repeated warnings

    def connect(self) -> paramiko.SSHClient:
        sock = None
        try:
            if self.jump_host:
                logging.debug(f"[{self.host}] Connecting to jump host {self.jump_host}:{self.jump_port}")
                self._jump_client = paramiko.SSHClient()
                if self.strict_host_key:
                    if self.known_hosts:
                        self._jump_client.load_host_keys(str(self.known_hosts))
                    self._jump_client.set_missing_host_key_policy(paramiko.RejectPolicy())
                else:
                    self._jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                self._jump_client.connect(
                    hostname=self.jump_host,
                    port=self.jump_port,
                    username=self.jump_username or self.username,
                    password=self.jump_password,
                    pkey=self.jump_pkey,
                    timeout=self.connect_timeout,
                    banner_timeout=self.connect_timeout,
                    auth_timeout=self.connect_timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                jt = self._jump_client.get_transport()
                if not jt or not jt.is_active():
                    raise ConnectionError("Jump host transport not active after connect.")
                sock = jt.open_channel("direct-tcpip", (self.host, self.port), ("127.0.0.1", 0))
                logging.debug(f"[{self.host}] Jump channel established via {self.jump_host}")

            logging.info(f"[{self.host}] Establishing SSH session...")
            self._client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                pkey=self.pkey,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                look_for_keys=False,
                allow_agent=False,
                sock=sock,
            )
            logging.info(f"[{self.host}] SSH connected.")
            return self._client
        except Exception:
            self.close()
            raise

    def exec(self, command: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> Tuple[int, str, str]:
        if not self._client:
            raise RuntimeError("SSH client not connected.")
        logging.debug(f"[{self.host}] exec: {command}")
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            exit_status = stdout.channel.recv_exit_status()
            logging.debug(f"[{self.host}] exit={exit_status}, out_len={len(out)}, err_len={len(err)}")
            return exit_status, out, err
        except Exception:
            logging.exception(f"[{self.host}] Command failed: {command}")
            raise

    def exec_cat_to_file(self, command: str, local_path: Path, timeout: int = DEFAULT_CMD_TIMEOUT) -> int:
        if not self._client:
            raise RuntimeError("SSH client not connected.")
        logging.debug(f"[{self.host}] exec(stream): {command}")
        chan = None
        try:
            t = self._client.get_transport()
            if not t or not t.is_active():
                raise RuntimeError("SSH transport not active.")
            chan = t.open_session(timeout=timeout)
            chan.exec_command(command)

            last_data_time = time.time()
            with local_path.open("wb") as f:
                while True:
                    if chan.recv_ready():
                        data = chan.recv(65536)
                        if not data:
                            break
                        f.write(data)
                        last_data_time = time.time()
                    elif chan.exit_status_ready():
                        while chan.recv_ready():
                            f.write(chan.recv(65536))
                        break
                    else:
                        if time.time() - last_data_time > 30:
                            chan.close()
                            return 124
                        time.sleep(0.05)
            return chan.recv_exit_status()
        except Exception:
            logging.exception(f"[{self.host}] Streaming command failed: {command}")
            raise
        finally:
            try:
                if chan:
                    chan.close()
            except Exception:
                pass

    def sftp(self) -> Optional[paramiko.SFTPClient]:
        """
        Try to open SFTP. Returns None if the subsystem is not available.
        Suppresses repeated WARN logs once unavailability is detected.
        """
        if not self._client:
            raise RuntimeError("SSH client not connected.")
        try:
            return self._client.open_sftp()
        except paramiko.SSHException as e:
            if not self._sftp_known_unavailable:
                logging.warning(f"[{self.host}] SFTP not available (will fall back to SCP/CLI): {e}")
                self._sftp_known_unavailable = True
            else:
                logging.debug(f"[{self.host}] SFTP not available.")
            return None

    def _scp_progress(self, label: str):
        last_pct = -1
        def _cb(filename, size, sent):
            nonlocal last_pct
            total = size or 1
            pct = int((sent / total) * 100)
            if pct != last_pct and pct % 10 == 0:
                logging.debug(f"[{self.host}] {label}: {pct}%")
                last_pct = pct
        return _cb

    def scp_get(self, remote_path: str, local_path: str) -> None:
        if not _SCP_AVAILABLE:
            raise RuntimeError("scp package is not installed. Install with: pip install scp")
        t = self._client.get_transport()
        if not t or not t.is_active():
            raise RuntimeError("SSH transport not active for SCP download.")
        with SCPClient(t, progress=self._scp_progress(Path(remote_path).name)) as scp:
            scp.get(remote_path, local_path)

    def close(self) -> None:
        try:
            if self._client:
                self._client.close()
        except Exception:
            pass
        try:
            if self._jump_client:
                self._jump_client.close()
        except Exception:
            pass


# ----------------------------
# Junos Collector
# ----------------------------

class JunosCollector:
    """
    Orchestrates RSI/log collection from a Junos device.
    """

    def __init__(self, ssh: SSHConnection, dry_run: bool = False, keep_remote: bool = False, cmd_timeout: int = DEFAULT_CMD_TIMEOUT, shell_fallback: bool = True) -> None:
        self.ssh = ssh
        self.dry_run = dry_run
        self.keep_remote = keep_remote
        self.cmd_timeout = cmd_timeout
        self.shell_fallback = shell_fallback
        self.hostname: Optional[str] = None

    # -------- Hostname

    def _sanitize_hostname(self, candidate: str, default_value: str) -> str:
        c = candidate.strip()
        if not c or c.lower().startswith("error"):
            c = ""
        c = c.split()[0] if c else ""
        c = re.sub(r"[^A-Za-z0-9._-]", "_", c)
        return c or default_value

    def get_hostname(self) -> str:
        code, out, _ = self.ssh.exec("cli -c 'show system hostname | no-more'", timeout=60)
        if code == 0:
            for line in out.splitlines():
                name = self._sanitize_hostname(line, "")
                if name:
                    self.hostname = name
                    logging.info(f"[{self.ssh.host}] Detected hostname: {self.hostname}")
                    return self.hostname
        code2, out2, _ = self.ssh.exec('cli -c "show configuration system host-name | display set | no-more"', timeout=60)
        if code2 == 0:
            for line in out2.splitlines():
                if "set system host-name" in line:
                    name = self._sanitize_hostname(line.rsplit(" ", 1)[-1], "")
                    if name:
                        self.hostname = name
                        logging.info(f"[{self.ssh.host}] Detected hostname (config): {self.hostname}")
                        return self.hostname
        code3, out3, _ = self.ssh.exec("hostname", timeout=30)
        if code3 == 0 and out3.strip():
            self.hostname = self._sanitize_hostname(out3.strip(), self.ssh.host.replace(".", "-"))
            logging.info(f"[{self.ssh.host}] Detected hostname (shell): {self.hostname}")
            return self.hostname
        self.hostname = self._sanitize_hostname(self.ssh.host, self.ssh.host.replace(".", "-"))
        logging.warning(f"[{self.ssh.host}] Falling back to {self.hostname} as hostname.")
        return self.hostname

    # -------- Naming

    def _mk_names(self) -> Tuple[str, str]:
        if not self.hostname:
            self.get_hostname()
        ts = utc_now_iso_compact()
        return (f"/var/tmp/{self.hostname}_RSI_{ts}.txt",
                f"/var/tmp/{self.hostname}_VARLOG_{ts}.tgz")

    # -------- Remote file size helpers (robust)

    def _parse_size_from_cli(self, text: str, filename: str) -> int:
        m = re.search(r"\bsize\s+(\d+)\s+bytes\b", text, re.IGNORECASE)
        if m:
            return int(m.group(1))
        m = re.search(r"^[\-dlcbpsrwx]+\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+\s+\d+\s+[\d:]+\s+.*{}".format(
            re.escape(Path(filename).name)), text, re.MULTILINE)
        if m:
            return int(m.group(1))
        m = re.search(r"^\s*(\d+)\s+{}$".format(re.escape(Path(filename).name)), text, re.MULTILINE)
        if m:
            return int(m.group(1))
        return -1

    def _stat_remote_size_cli_only(self, remote_path: str) -> int:
        cmd = f"cli -c 'file list detail {remote_path} | no-more'"
        code, out, err = self.ssh.exec(cmd, timeout=60)
        if code != 0 or not out.strip():
            return -1
        return self._parse_size_from_cli(out, remote_path)

    def _stat_remote_size(self, remote_path: str) -> int:
        # Try SFTP once (if available). If not, CLI only.
        try:
            sftp = self.ssh.sftp()
            if sftp:
                try:
                    size = int(sftp.stat(remote_path).st_size)
                    try:
                        sftp.close()
                    except Exception:
                        pass
                    return size
                except FileNotFoundError:
                    try:
                        sftp.close()
                    except Exception:
                        pass
                    return -1
                except Exception:
                    try:
                        sftp.close()
                    except Exception:
                        pass
                    # Fall through to CLI
        except Exception:
            pass
        return self._stat_remote_size_cli_only(remote_path)

    def _wait_for_remote_file(self, remote_path: str, min_size: int = 1, timeout: int = DEFAULT_CMD_TIMEOUT, poll_initial: float = 1.0) -> int:
        deadline = time.time() + timeout
        delay = poll_initial
        last_size = -1
        while time.time() < deadline:
            size = self._stat_remote_size(remote_path)
            if size >= min_size:
                if last_size != size:
                    logging.debug(f"[{self.ssh.host}] Remote file {remote_path} size={size} bytes")
                return size
            last_size = size
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)
        raise RuntimeError(f"Remote file not ready or too small after wait: {remote_path} (size={last_size})")

    # -------- RSI generation (with fallback)

    def _looks_like_cli_error(self, out: str, err: str) -> bool:
        blob = f"{out}\n{err}".lower()
        return any(k in blob for k in [
            "error:", "permission denied", "no space", "no such file", "not found", "invalid", "failed"
        ])

    def _generate_rsi_via_cli_save(self, rsi_file: str) -> bool:
        cmd = f"cli -c 'request support information | save {rsi_file}'"
        logging.info(f"[{self.ssh.host}] Generating RSI -> {rsi_file}")
        code, out, err = self.ssh.exec(cmd, timeout=self.cmd_timeout)
        if code != 0 or self._looks_like_cli_error(out, err):
            logging.warning(f"[{self.ssh.host}] RSI save reported issue (exit {code}). Will try fallback. out_len={len(out)}, err_len={len(err)}")
            return False
        return True

    def _generate_rsi_via_shell_redirect(self, rsi_file: str) -> None:
        # Directly dump the CLI output into the file via the shell (bypasses 'save')
        cmd = f"start shell sh -lc 'cli -c \"request support information | no-more\" > {sh_quote(rsi_file)} 2>/var/tmp/rsi_err.log'"
        logging.info(f"[{self.ssh.host}] RSI fallback: redirecting CLI output to {rsi_file}")
        code, out, err = self.ssh.exec(cmd, timeout=self.cmd_timeout)
        if code != 0:
            raise RuntimeError(f"RSI shell-redirect failed (exit {code}): {err.strip() or out.strip()}")

    def generate_rsi(self) -> str:
        rsi_file, _ = self._mk_names()
        if self.dry_run:
            logging.info(f"[{self.ssh.host}] DRY-RUN: would run RSI to {rsi_file}")
            return rsi_file

        ok = self._generate_rsi_via_cli_save(rsi_file)
        # Wait briefly for file; if not present, do fallback
        try:
            if ok:
                self._wait_for_remote_file(rsi_file, min_size=1, timeout=min(self.cmd_timeout, 900))
                logging.info(f"[{self.ssh.host}] RSI generated at {rsi_file}")
                return rsi_file
        except RuntimeError:
            logging.warning(f"[{self.ssh.host}] RSI not visible after save; attempting fallback redirect.")

        # Fallback path
        self._generate_rsi_via_shell_redirect(rsi_file)
        self._wait_for_remote_file(rsi_file, min_size=1, timeout=min(self.cmd_timeout, 900))
        logging.info(f"[{self.ssh.host}] RSI generated (fallback) at {rsi_file}")
        return rsi_file

    # -------- /var/log archive

    def generate_logs_archive(self) -> str:
        _, logs_file = self._mk_names()
        if self.dry_run:
            logging.info(f"[{self.ssh.host}] DRY-RUN: would archive /var/log to {logs_file}")
            return logs_file

        cmd = f"cli -c 'file archive compress source /var/log destination {logs_file}'"
        logging.info(f"[{self.ssh.host}] Archiving /var/log -> {logs_file}")
        code, out, err = self.ssh.exec(cmd, timeout=self.cmd_timeout)
        if code != 0 or self._looks_like_cli_error(out, err):
            raise RuntimeError(f"Log archive failed (exit {code}): {err.strip() or out.strip()}")

        self._wait_for_remote_file(logs_file, min_size=1, timeout=min(self.cmd_timeout, 900))
        logging.info(f"[{self.ssh.host}] /var/log archived at {logs_file}")
        return logs_file

    # -------- Downloads

    def download(self, remote_path: str, local_dir: Path) -> Path:
        ensure_dir(local_dir)
        filename = Path(remote_path).name
        local_path = local_dir / filename

        logging.info(f"[{self.ssh.host}] Downloading {remote_path} -> {local_path}")
        if self.dry_run:
            logging.info(f"[{self.ssh.host}] DRY-RUN: GET {remote_path} to {local_path}")
            return local_path

        # SFTP first (once)
        sftp = None
        try:
            sftp = self.ssh.sftp()
            if sftp:
                try:
                    total = sftp.stat(remote_path).st_size or 1
                except Exception:
                    total = 0
                last_pct = -1
                def _cb(transferred: int, t: int):
                    nonlocal last_pct
                    denom = t or total or 1
                    pct = int((transferred / denom) * 100)
                    if pct != last_pct and pct % 10 == 0:
                        logging.debug(f"[{self.ssh.host}] {filename}: {pct}%")
                        last_pct = pct
                sftp.get(remote_path, str(local_path), callback=_cb)
                logging.info(f"[{self.ssh.host}] Download complete (SFTP): {local_path} ({human_bytes(local_path.stat().st_size)})")
                return local_path
        except Exception:
            logging.exception(f"[{self.ssh.host}] SFTP download failed for {remote_path}")
        finally:
            if sftp:
                try: sftp.close()
                except Exception: pass

        # SCP fallback
        try:
            self.ssh.scp_get(remote_path, str(local_path))
            logging.info(f"[{self.ssh.host}] Download complete (SCP): {local_path} ({human_bytes(local_path.stat().st_size)})")
            return local_path
        except Exception as e:
            logging.warning(f"[{self.ssh.host}] SCP fallback failed: {e}")

        # Shell streaming fallback
        if self.shell_fallback:
            logging.info(f"[{self.ssh.host}] Falling back to shell streaming for {remote_path}")
            cmd = f"start shell sh -lc 'cat {sh_quote(remote_path)}'"
            rc = self.ssh.exec_cat_to_file(cmd, local_path, timeout=self.cmd_timeout)
            if rc != 0:
                raise RuntimeError(f"Shell streaming failed for {remote_path} (exit {rc})")
            st = local_path.stat()
            if st.st_size <= 0:
                raise RuntimeError(f"Downloaded file is empty after shell streaming: {local_path}")
            logging.info(f"[{self.ssh.host}] Download complete (shell): {local_path} ({human_bytes(st.st_size)})")
            return local_path

        raise RuntimeError(f"All download methods failed for {remote_path}")

    # -------- Cleanup & Bundle

    def delete_remote(self, remote_path: str) -> None:
        if self.dry_run or self.keep_remote:
            logging.info(f"[{self.ssh.host}] Skipping remote delete (dry-run or keep-remote): {remote_path}")
            return
        cmd = f"cli -c 'file delete {remote_path}'"
        code, out, err = self.ssh.exec(cmd, timeout=60)
        if code != 0:
            logging.warning(f"[{self.ssh.host}] Failed to delete remote {remote_path}: {err.strip() or out.strip()}")
        else:
            logging.debug(f"[{self.ssh.host}] Deleted remote {remote_path}")

    def bundle_local(self, output_dir: Path, files: List[Path]) -> Path:
        if not self.hostname:
            self.get_hostname()
        ts = utc_now_iso_compact()
        bundle_name = f"{self.hostname}_SUPPORT_{ts}.tgz"
        bundle_path = output_dir / bundle_name
        logging.info(f"[{self.ssh.host}] Creating bundle: {bundle_path}")
        with tarfile.open(bundle_path, "w:gz") as tar:
            for f in files:
                tar.add(f, arcname=f.name)
        logging.info(f"[{self.ssh.host}] Bundle created: {bundle_path} ({human_bytes(bundle_path.stat().st_size)})")
        return bundle_path


# ----------------------------
# Uploaders
# ----------------------------

class BaseUploader:
    def upload(self, path: Path) -> str:
        raise NotImplementedError


class ScpUploader(BaseUploader):
    """
    Upload via SFTP to a remote server (SCP-like over SSH).
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        pkey: Optional[paramiko.PKey],
        remote_dir: str,
        strict_host_key: bool = False,
        known_hosts: Optional[Path] = None,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.pkey = pkey
        self.remote_dir = remote_dir or "/tmp"
        self.strict_host_key = strict_host_key
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout

    def _sftp_mkdir_p(self, sftp: paramiko.SFTPClient, remote_dir: str) -> None:
        path = remote_dir.rstrip("/")
        if not path:
            return
        parts = [p for p in path.split("/") if p]
        cur = ""
        for p in parts:
            cur = f"{cur}/{p}" if cur else f"/{p}"
            try:
                sftp.stat(cur)
            except FileNotFoundError:
                sftp.mkdir(cur)

    def upload(self, path: Path) -> str:
        client = paramiko.SSHClient()
        if self.strict_host_key:
            if self.known_hosts:
                client.load_host_keys(str(self.known_hosts))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                pkey=self.pkey,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
            )
            sftp = client.open_sftp()
            try:
                self._sftp_mkdir_p(sftp, self.remote_dir)
                remote_path = f"{self.remote_dir.rstrip('/')}/{path.name}"
                logging.info(f"[UPLOAD] SFTP PUT {path} -> {remote_path}")
                sftp.put(str(path), remote_path)
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass
        finally:
            try:
                client.close()
            except Exception:
                pass
        return f"sftp://{self.username}@{self.host}:{self.port}{self.remote_dir}/{path.name}"


class S3Uploader(BaseUploader):
    def __init__(self, s3_uri: str, aws_profile: Optional[str] = None, server_side_encryption: Optional[str] = None, sse_kms_key_id: Optional[str] = None):
        if not _BOTO3_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Install with: pip install boto3")
        if not s3_uri.startswith("s3://"):
            raise ValueError("S3 URI must start with s3://")
        parts = s3_uri[5:].split("/", 1)
        self.bucket = parts[0]
        self.prefix = parts[1] if len(parts) > 1 else ""
        self.sse = server_side_encryption
        self.sse_kms_key_id = sse_kms_key_id
        session_kwargs = {}
        if aws_profile:
            session_kwargs["profile_name"] = aws_profile
        self.session = boto3.Session(**session_kwargs) if session_kwargs else boto3.Session()
        self.s3 = self.session.client("s3")

    def upload(self, path: Path) -> str:
        key = f"{self.prefix.rstrip('/')}/{path.name}" if self.prefix else path.name
        extra_args: Dict[str, str] = {}
        if self.sse:
            extra_args["ServerSideEncryption"] = self.sse
        if self.sse_kms_key_id:
            extra_args["SSEKMSKeyId"] = self.sse_kms_key_id
        logging.info(f"[UPLOAD] S3 PUT {path} -> s3://{self.bucket}/{key}")
        try:
            self.s3.upload_file(str(path), self.bucket, key, ExtraArgs=extra_args if extra_args else None)
        except (BotoCoreError, ClientError):
            logging.exception("S3 upload failed.")
            raise
        return f"s3://{self.bucket}/{key}"


# ----------------------------
# Orchestrator per host
# ----------------------------

def run_for_host(
    target: str,
    args: argparse.Namespace,
    ssh_key: Optional[paramiko.PKey],
    jump_key: Optional[paramiko.PKey],
) -> Dict[str, str]:
    result: Dict[str, str] = {"target": target}
    ssh = SSHConnection(
        host=target,
        port=args.port,
        username=args.user,
        password=args.password,
        pkey=ssh_key,
        connect_timeout=args.connect_timeout,
        strict_host_key=args.strict_host_key,
        known_hosts=Path(args.known_hosts) if args.known_hosts else None,
        jump_host=args.jump_host,
        jump_port=args.jump_port,
        jump_username=args.jump_user,
        jump_password=args.jump_password,
        jump_pkey=jump_key,
    )

    try:
        ssh.connect()
        collector = JunosCollector(
            ssh=ssh,
            dry_run=args.dry_run,
            keep_remote=args.keep_remote,
            cmd_timeout=args.cmd_timeout,
            shell_fallback=not args.no_shell_fallback,
        )

        hostname = collector.get_hostname()
        result["hostname"] = hostname

        remote_rsi = collector.generate_rsi()
        remote_logs = collector.generate_logs_archive()

        local_dir = Path(args.output_dir) / hostname
        ensure_dir(local_dir)

        local_rsi = collector.download(remote_rsi, local_dir)
        local_logs = collector.download(remote_logs, local_dir)
        result["local_rsi"] = str(local_rsi)
        result["local_logs"] = str(local_logs)

        bundle_path: Optional[Path] = None
        if args.bundle:
            bundle_path = collector.bundle_local(local_dir, [local_rsi, local_logs])
            result["local_bundle"] = str(bundle_path)

        # Cleanup
        collector.delete_remote(remote_rsi)
        collector.delete_remote(remote_logs)

        # Optional uploads
        uploaded_urls: List[str] = []
        if args.upload_scp_host:
            scp_key = load_private_key(Path(args.upload_scp_key_file), args.upload_scp_key_passphrase) if args.upload_scp_key_file else None
            scp = ScpUploader(
                host=args.upload_scp_host,
                port=args.upload_scp_port,
                username=args.upload_scp_user or args.user,
                password=args.upload_scp_password,
                pkey=scp_key,
                remote_dir=args.upload_scp_path or "/tmp",
                strict_host_key=args.upload_scp_strict_host_key,
                known_hosts=Path(args.upload_scp_known_hosts) if args.upload_scp_known_hosts else None,
                connect_timeout=args.connect_timeout,
            )
            files_to_upload: List[Path] = []
            if args.upload_bundle_only and bundle_path:
                files_to_upload = [bundle_path]
            else:
                files_to_upload = [local_rsi, local_logs]
                if bundle_path and not args.upload_bundle_only:
                    files_to_upload.append(bundle_path)
            for f in files_to_upload:
                uploaded_urls.append(scp.upload(f))

        if args.upload_s3:
            s3 = S3Uploader(
                s3_uri=args.upload_s3,
                aws_profile=args.aws_profile,
                server_side_encryption=args.s3_sse,
                sse_kms_key_id=args.s3_kms_key_id,
            )
            files_to_upload: List[Path] = []
            if args.upload_bundle_only and bundle_path:
                files_to_upload = [bundle_path]
            else:
                files_to_upload = [local_rsi, local_logs]
                if bundle_path and not args.upload_bundle_only:
                    files_to_upload.append(bundle_path)
            for f in files_to_upload:
                uploaded_urls.append(s3.upload(f))

        if uploaded_urls:
            result["uploaded"] = ";".join(uploaded_urls)

        logging.info(f"[{target}] SUCCESS. RSI: {local_rsi}, LOGS: {local_logs}" + (f", BUNDLE: {bundle_path}" if bundle_path else ""))
        return result

    finally:
        try:
            ssh.close()
        except Exception:
            pass


# ----------------------------
# CLI
# ----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect RSI and /var/log from Junos devices with optional jump host, SFTP/SCP/Shell fallback, and uploads."
    )

    # Targets
    p.add_argument("--host", help="Target host or comma-separated list (e.g., 10.0.0.1,10.0.0.2)")
    p.add_argument("--hosts-file", type=str, help="File containing target hosts (one per line)")

    # Auth
    p.add_argument("--user", required=True, help="SSH username for device")
    p.add_argument("--password", help="SSH password for device (omit to prompt)")
    p.add_argument("--key-file", help="Path to private key for device (RSA/ECDSA/Ed25519/DSS)")
    p.add_argument("--key-passphrase", help="Passphrase for --key-file, if any")
    p.add_argument("--port", type=int, default=DEFAULT_SSH_PORT, help=f"SSH port for device (default: {DEFAULT_SSH_PORT})")

    # Jump Host
    p.add_argument("--jump-host", help="Jump/bastion host")
    p.add_argument("--jump-port", type=int, default=DEFAULT_SSH_PORT, help=f"Jump host SSH port (default: {DEFAULT_SSH_PORT})")
    p.add_argument("--jump-user", help="Jump host username (defaults to --user if omitted)")
    p.add_argument("--jump-password", help="Jump host password")
    p.add_argument("--jump-key-file", help="Jump host private key file")
    p.add_argument("--jump-key-passphrase", help="Passphrase for --jump-key-file, if any")

    # Behavior
    p.add_argument("--output-dir", default="./junos_support", help="Local output directory (default: ./junos_support)")
    p.add_argument("--bundle", action="store_true", help="Create a local tar.gz bundle containing RSI and logs")
    p.add_argument("--keep-remote", action="store_true", help="Do not delete remote files after download")
    p.add_argument("--dry-run", action="store_true", help="Validate and show operations without executing destructive actions")
    p.add_argument("--no-shell-fallback", action="store_true", help="Disable last-resort shell streaming fallback for downloads")

    # Upload (SCP/SFTP)
    p.add_argument("--upload-scp-host", help="Upload artifacts via SFTP to this host")
    p.add_argument("--upload-scp-port", type=int, default=DEFAULT_SSH_PORT, help=f"SFTP port (default: {DEFAULT_SSH_PORT})")
    p.add_argument("--upload-scp-user", help="SFTP username (defaults to --user if omitted)")
    p.add_argument("--upload-scp-password", help="SFTP password")
    p.add_argument("--upload-scp-key-file", help="SFTP private key file")
    p.add_argument("--upload-scp-key-passphrase", help="Passphrase for SFTP private key")
    p.add_argument("--upload-scp-path", help="Remote directory to upload to (default: /tmp)")
    p.add_argument("--upload-bundle-only", action="store_true", help="Upload only the local bundle (requires --bundle)")
    p.add_argument("--upload-scp-strict-host-key", action="store_true", help="Enforce strict host key for SFTP upload target")
    p.add_argument("--upload-scp-known-hosts", help="Known hosts file path for SFTP upload target")

    # Upload (S3)
    p.add_argument("--upload-s3", help="S3 URI (e.g., s3://my-bucket/support). Requires boto3.")
    p.add_argument("--aws-profile", help="AWS profile name to use for boto3 session")
    p.add_argument("--s3-sse", choices=["AES256", "aws:kms"], help="S3 server-side encryption")
    p.add_argument("--s3-kms-key-id", help="S3 SSE-KMS key ID if using aws:kms")

    # SSH/Transport behavior
    p.add_argument("--strict-host-key", action="store_true", help="Reject unknown host keys for device/jump connections")
    p.add_argument("--known-hosts", help="Known hosts file to enforce when --strict-host-key is set")
    p.add_argument("--connect-timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT, help=f"SSH connect timeout seconds (default: {DEFAULT_CONNECT_TIMEOUT})")
    p.add_argument("--cmd-timeout", type=int, default=DEFAULT_CMD_TIMEOUT, help=f"Command timeout seconds (default: {DEFAULT_CMD_TIMEOUT})")

    # Concurrency & Logging
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS, help=f"Parallel threads for multiple hosts (default: {DEFAULT_THREADS})")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--log-file", help="Log file path")

    return p


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    setup_logging(verbose=args.verbose, log_file=Path(args.log_file) if args.log_file else None)

    try:
        targets = parse_host_list(args.host, Path(args.hosts_file) if args.hosts_file else None)
    except Exception as e:
        logging.error(f"Target parsing error: {e}")
        return 2

    if not args.password and not args.key_file:
        try:
            args.password = getpass.getpass("Device SSH password (leave empty to use key): ")
        except Exception:
            pass

    if args.key_file and args.password:
        logging.info("Both --key-file and --password supplied; key-based auth will be attempted first.")

    ssh_key = None
    jump_key = None
    try:
        if args.key_file:
            ssh_key = load_private_key(Path(args.key_file), args.key_passphrase)
    except Exception as e:
        logging.error(f"Failed to load device --key-file: {e}")
        return 2
    try:
        if args.jump_key_file:
            jump_key = load_private_key(Path(args.jump_key_file), args.jump_key_passphrase)
    except Exception as e:
        logging.error(f"Failed to load --jump-key-file: {e}")
        return 2

    if args.upload_s3 and not _BOTO3_AVAILABLE:
        logging.error("boto3 is required for --upload-s3. Install with: pip install boto3")
        return 2
    if args.upload_bundle_only and not args.bundle:
        logging.error("--upload-bundle-only requires --bundle.")
        return 2

    try:
        ensure_dir(Path(args.output_dir))
    except Exception as e:
        logging.error(f"Failed to create --output-dir {args.output_dir}: {e}")
        return 2

    failures = 0
    results: List[Dict[str, str]] = []

    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads), thread_name_prefix="collector") as executor:
        fut = {executor.submit(run_for_host, target, args, ssh_key, jump_key): target for target in targets}
        for future in cf.as_completed(fut):
            target = fut[future]
            try:
                res = future.result()
                results.append(res)
            except KeyboardInterrupt:
                logging.error(f"[{target}] Interrupted.")
                failures += 1
            except Exception:
                logging.exception(f"[{target}] FAILED")
                failures += 1

    success = len(targets) - failures
    logging.info(f"Completed. Success: {success}/{len(targets)}, Failures: {failures}")
    for r in results:
        line = f"- {r.get('target')} (hostname={r.get('hostname')}): RSI={r.get('local_rsi')}, LOGS={r.get('local_logs')}"
        if r.get("local_bundle"):
            line += f", BUNDLE={r.get('local_bundle')}"
        if r.get("uploaded"):
            line += f", UPLOADED={r.get('uploaded')}"
        logging.info(line)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
