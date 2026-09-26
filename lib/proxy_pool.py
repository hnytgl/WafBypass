"""
lib.proxy_pool -- Proxy rotation and Tor circuit management.

Provides:
  - ProxyPool: round-robin or random proxy rotation with health tracking
  - tor_newnym(): signal Tor to switch to a new circuit (new exit IP)
  - Auto-rotation on consecutive blocks/rate-limits
"""

import random
import socket
import time

import lib.formatter


class ProxyPool:
    """
    Manages a pool of proxies with health tracking and rotation.

    Usage:
        pool = ProxyPool.from_file("proxies.txt")
        proxy = pool.next()  # get next healthy proxy
        pool.mark_failed(proxy)  # mark proxy as failed
        pool.mark_success(proxy)  # reset failure count
    """

    def __init__(self, proxies=None, strategy="round-robin", max_failures=3):
        """
        Args:
            proxies: list of proxy URL strings
            strategy: "round-robin" or "random"
            max_failures: consecutive failures before removing proxy from pool
        """
        self._proxies = list(proxies or [])
        self._strategy = strategy
        self._max_failures = max_failures
        self._index = 0
        self._failures = {}  # proxy -> consecutive failure count
        self._healthy = list(self._proxies)  # currently healthy proxies

    @classmethod
    def from_file(cls, path, strategy="round-robin", max_failures=3):
        """Load proxies from a text file (one proxy URL per line)."""
        proxies = []
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxies.append(line)
        if not proxies:
            raise ValueError("No proxies found in '{}'".format(path))
        return cls(proxies=proxies, strategy=strategy, max_failures=max_failures)

    @property
    def size(self):
        """Total proxies (including unhealthy)."""
        return len(self._proxies)

    @property
    def healthy_count(self):
        """Currently healthy proxies."""
        return len(self._healthy)

    def next(self):
        """Get the next proxy from the pool. Returns None if pool is empty."""
        if not self._healthy:
            # All proxies failed; reset and try again
            lib.formatter.warn("all proxies exhausted, resetting pool")
            self._healthy = list(self._proxies)
            self._failures.clear()
            self._index = 0
            if not self._healthy:
                return None

        if self._strategy == "random":
            return random.choice(self._healthy)

        # round-robin
        proxy = self._healthy[self._index % len(self._healthy)]
        self._index += 1
        return proxy

    def mark_failed(self, proxy):
        """Mark a proxy as failed. Removes from pool after max_failures."""
        self._failures[proxy] = self._failures.get(proxy, 0) + 1
        if self._failures[proxy] >= self._max_failures:
            if proxy in self._healthy:
                self._healthy.remove(proxy)
                lib.formatter.warn(
                    "proxy '{}' removed from pool ({} consecutive failures), {} remaining".format(
                        proxy, self._max_failures, len(self._healthy)
                    ), minor=True
                )

    def mark_success(self, proxy):
        """Reset failure count for a proxy on success."""
        self._failures.pop(proxy, None)

    def rotate(self):
        """Force rotation to next proxy (e.g. after WAF block)."""
        if self._healthy and self._strategy == "round-robin":
            self._index = (self._index + 1) % len(self._healthy)
        return self.next()


def tor_newnym(control_port=9051, password="", timeout=5):
    """
    Signal Tor to switch to a new circuit (new exit IP).

    Args:
        control_port: Tor ControlPort (default 9051)
        password: Tor control password (empty = no auth)
        timeout: socket timeout in seconds

    Returns:
        True if newnym signal was accepted, False otherwise.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("127.0.0.1", control_port))

        # Authenticate
        if password:
            s.sendall('AUTHENTICATE "{}"\r\n'.format(password).encode())
        else:
            s.sendall(b"AUTHENTICATE\r\n")
        auth_resp = s.recv(1024).decode("utf-8", errors="replace")
        if not auth_resp.startswith("250"):
            s.close()
            return False

        # Send NEWNYM signal
        s.sendall(b"SIGNAL NEWNYM\r\n")
        nym_resp = s.recv(1024).decode("utf-8", errors="replace")
        s.close()

        if nym_resp.startswith("250"):
            # Tor recommends waiting 10s for the new circuit to establish
            time.sleep(2)
            return True
        return False
    except (socket.error, socket.timeout, OSError):
        return False


class TorManager:
    """
    Manages Tor circuit rotation with automatic newnym on consecutive blocks.
    """

    def __init__(self, control_port=9051, password="", blocks_before_rotate=3):
        self.control_port = control_port
        self.password = password
        self.blocks_before_rotate = blocks_before_rotate
        self._consecutive_blocks = 0
        self._rotations = 0

    def record_block(self):
        """Record a block event. Returns True if circuit was rotated."""
        self._consecutive_blocks += 1
        if self._consecutive_blocks >= self.blocks_before_rotate:
            return self.rotate()
        return False

    def record_success(self):
        """Reset consecutive block counter on successful request."""
        self._consecutive_blocks = 0

    def rotate(self):
        """Force Tor circuit rotation."""
        self._consecutive_blocks = 0
        success = tor_newnym(self.control_port, self.password)
        if success:
            self._rotations += 1
            lib.formatter.info(
                "Tor circuit rotated (newnym #{})".format(self._rotations)
            )
        else:
            lib.formatter.warn(
                "Tor newnym failed (ControlPort {} unreachable or auth failed)".format(
                    self.control_port
                ), minor=True
            )
        return success

    @property
    def rotations(self):
        return self._rotations
