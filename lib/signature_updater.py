"""
lib.signature_updater -- Hot-update client for WAF signature packs.

Downloads signature packs from GitHub Releases (or a custom URL),
verifies SHA256 integrity, and installs to ~/.wafbypass/signatures/.

Usage:
    from lib.signature_updater import SignatureUpdater
    updater = SignatureUpdater()
    updater.check()       # check if update available
    updater.update()      # download and install latest pack
"""

import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import time

import requests

import lib.formatter

_HOME = os.path.join(os.path.expanduser("~"), ".wafbypass")
_USER_SIGNATURES_DIR = os.path.join(_HOME, "signatures")
_VERSION_FILE = os.path.join(_USER_SIGNATURES_DIR, "_version.json")

# Default signature pack source (GitHub Releases)
DEFAULT_RELEASES_URL = "https://api.github.com/repos/hnytgl/WafBypass/releases"
DEFAULT_TAG_PREFIX = "signatures-"


class SignatureUpdater:
    """
    Manages downloading and installing WAF signature packs.

    Signature packs are versioned independently from the tool itself,
    allowing frequent WAF detection updates without code releases.
    """

    def __init__(self, source_url=None, timeout=10, proxy=None):
        """
        Args:
            source_url: Base URL for signature releases API.
                        None = use default GitHub Releases.
            timeout: HTTP request timeout in seconds.
            proxy: Optional proxy URL for downloads.
        """
        self.source_url = source_url or DEFAULT_RELEASES_URL
        self.timeout = timeout
        self.proxy = proxy
        self._proxies = {"http": proxy, "https": proxy} if proxy else {}

    def get_local_version(self):
        """
        Get the currently installed signature pack version.

        Returns:
            dict with 'version', 'updated_at', 'count' or None if not installed.
        """
        if not os.path.exists(_VERSION_FILE):
            return None
        try:
            with open(_VERSION_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def check(self):
        """
        Check if a newer signature pack is available.

        Returns:
            dict with 'update_available' (bool), 'local_version', 'remote_version'
            or None on network failure.
        """
        local = self.get_local_version()
        local_version = local.get("version", "0") if local else "0"

        remote_version = self._fetch_latest_version()
        if remote_version is None:
            return None

        return {
            "update_available": remote_version > local_version,
            "local_version": local_version,
            "remote_version": remote_version,
        }

    def update(self, force=False):
        """
        Download and install the latest signature pack.

        Args:
            force: If True, reinstall even if already up-to-date.

        Returns:
            True on success, False on failure.
        """
        if not force:
            status = self.check()
            if status is None:
                lib.formatter.error("cannot check for signature updates (network unreachable)")
                return False
            if not status["update_available"]:
                lib.formatter.info(
                    "signatures are up-to-date (version {})".format(status["local_version"])
                )
                return True
            lib.formatter.info(
                "updating signatures: {} -> {}".format(
                    status["local_version"], status["remote_version"]
                )
            )

        # Download the pack
        pack_data = self._download_pack()
        if pack_data is None:
            return False

        # Verify and install
        return self._install_pack(pack_data)

    def _fetch_latest_version(self):
        """Fetch the latest signature pack version from the release API."""
        try:
            resp = requests.get(
                self.source_url,
                timeout=self.timeout,
                proxies=self._proxies,
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code != 200:
                return None
            releases = resp.json()
            for release in releases:
                tag = release.get("tag_name", "")
                if tag.startswith(DEFAULT_TAG_PREFIX):
                    return tag[len(DEFAULT_TAG_PREFIX):]
            return None
        except Exception:
            return None

    def _download_pack(self):
        """Download the latest signature pack tarball."""
        try:
            resp = requests.get(
                self.source_url,
                timeout=self.timeout,
                proxies=self._proxies,
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code != 200:
                lib.formatter.error("failed to fetch release info (HTTP {})".format(resp.status_code))
                return None

            releases = resp.json()
            download_url = None
            sha256_url = None

            for release in releases:
                tag = release.get("tag_name", "")
                if tag.startswith(DEFAULT_TAG_PREFIX):
                    for asset in release.get("assets", []):
                        name = asset.get("name", "")
                        if name.endswith(".tar.gz"):
                            download_url = asset.get("browser_download_url")
                        elif name.endswith(".sha256"):
                            sha256_url = asset.get("browser_download_url")
                    break

            if not download_url:
                lib.formatter.error("no signature pack found in latest release")
                return None

            lib.formatter.info("downloading signature pack...")
            pack_resp = requests.get(
                download_url, timeout=30, proxies=self._proxies, stream=True
            )
            if pack_resp.status_code != 200:
                lib.formatter.error("download failed (HTTP {})".format(pack_resp.status_code))
                return None

            pack_bytes = pack_resp.content

            # Fetch and verify SHA256 if available
            if sha256_url:
                sha_resp = requests.get(sha256_url, timeout=self.timeout, proxies=self._proxies)
                if sha_resp.status_code == 200:
                    expected_hash = sha_resp.text.strip().split()[0]
                    actual_hash = hashlib.sha256(pack_bytes).hexdigest()
                    if actual_hash != expected_hash:
                        lib.formatter.error(
                            "SHA256 mismatch! expected={}, got={}. "
                            "Pack may be tampered with.".format(expected_hash, actual_hash)
                        )
                        return None
                    lib.formatter.info("SHA256 verified: {}".format(actual_hash[:16] + "..."))

            return pack_bytes

        except requests.exceptions.RequestException as e:
            lib.formatter.error("download failed: {}".format(e))
            return None

    def _install_pack(self, pack_bytes):
        """Extract and install a signature pack tarball."""
        try:
            os.makedirs(_USER_SIGNATURES_DIR, exist_ok=True)

            # Extract to temp dir first, then move
            with tempfile.TemporaryDirectory() as tmpdir:
                tar_path = os.path.join(tmpdir, "pack.tar.gz")
                with open(tar_path, "wb") as f:
                    f.write(pack_bytes)

                with tarfile.open(tar_path, "r:gz") as tar:
                    # Security: only extract .yaml/.yml/.json files
                    safe_members = []
                    for member in tar.getmembers():
                        if member.isfile() and member.name.endswith((".yaml", ".yml", ".json")):
                            # Prevent path traversal
                            if not os.path.isabs(member.name) and ".." not in member.name:
                                safe_members.append(member)
                    tar.extractall(tmpdir, members=safe_members)

                # Count and move YAML files
                count = 0
                for root, dirs, files in os.walk(tmpdir):
                    for fname in files:
                        if fname.endswith((".yaml", ".yml")) and not fname.startswith("_"):
                            src = os.path.join(root, fname)
                            dst = os.path.join(_USER_SIGNATURES_DIR, fname)
                            shutil.copy2(src, dst)
                            count += 1

            # Write version metadata
            version_info = {
                "version": time.strftime("%Y.%m.%d"),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "count": count,
                "source": self.source_url,
            }
            with open(_VERSION_FILE, "w") as f:
                json.dump(version_info, f, indent=2)

            lib.formatter.success(
                "installed {} signatures to '{}'".format(count, _USER_SIGNATURES_DIR)
            )
            return True

        except (tarfile.TarError, IOError, OSError) as e:
            lib.formatter.error("failed to install signature pack: {}".format(e))
            return False
