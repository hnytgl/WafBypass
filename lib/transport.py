"""
lib.transport -- HTTP transport abstraction layer.

Provides a unified interface over two backends:
  1. curl_cffi (preferred) -- TLS fingerprint impersonation (Chrome/Safari/Firefox)
  2. requests (fallback)   -- standard Python TLS, no impersonation

The backend is selected at session creation time based on:
  - Whether curl_cffi is installed
  - Whether the user passed --impersonate

Usage:
    from lib.transport import create_session, get_backend_info
    session = create_session(impersonate="chrome120")
    resp = session.get(url, timeout=15)
"""

import importlib.util
import http.cookiejar
import os

import requests
import requests.adapters

# Detect curl_cffi availability at import time (cheap find_spec, no actual import)
_HAS_CURL_CFFI = importlib.util.find_spec("curl_cffi") is not None

# Supported impersonation targets (curl_cffi >= 0.7)
IMPERSONATE_TARGETS = (
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
    "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
    "chrome124", "chrome131", "chrome136",
    "safari15_3", "safari15_5", "safari17_0", "safari17_2_ios",
    "safari18_0", "safari18_2_ios",
    "firefox133", "firefox135",
    "edge99", "edge101",
    "tor_145",
)

# Default impersonation target when user passes --impersonate without a value
DEFAULT_IMPERSONATE = "chrome120"


class TransportSession:
    """
    Unified session wrapper that works with both curl_cffi and requests backends.
    Exposes .get(), .post(), .close(), .cookies for the caller.
    """

    def __init__(self, backend, session, impersonate=None):
        self._backend = backend  # "curl_cffi" or "requests"
        self._session = session
        self._impersonate = impersonate

    @property
    def backend(self):
        return self._backend

    @property
    def impersonate(self):
        return self._impersonate

    @property
    def cookies(self):
        return self._session.cookies

    @cookies.setter
    def cookies(self, value):
        self._session.cookies = value

    @property
    def headers(self):
        return self._session.headers

    def get(self, url, **kwargs):
        return self._session.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self._session.post(url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._session.request(method, url, **kwargs)

    def close(self):
        self._session.close()

    def load_cookie_jar(self, path):
        """Load cookies from a Netscape/Mozilla format cookie file."""
        jar = http.cookiejar.MozillaCookieJar(path)
        jar.load(ignore_discard=True, ignore_expires=True)
        for cookie in jar:
            self._session.cookies.set_cookie(cookie)
        return len(jar)

    def export_cookie_jar(self, path):
        """Export current session cookies to Netscape/Mozilla format file."""
        jar = http.cookiejar.MozillaCookieJar(path)
        for cookie in self._session.cookies:
            jar.set_cookie(cookie)
        jar.save(ignore_discard=True, ignore_expires=True)
        return len(jar)


def create_session(impersonate=None, proxy=None, verify=True, timeout=15,
                   pool_connections=10, pool_maxsize=20):
    """
    Factory: create a TransportSession with the best available backend.

    Args:
        impersonate: TLS fingerprint target (e.g. "chrome120"). None = no impersonation.
        proxy: proxy URL string or None.
        verify: TLS certificate verification.
        timeout: default request timeout in seconds.
        pool_connections: connection pool size (requests backend only).
        pool_maxsize: max pool size (requests backend only).

    Returns:
        TransportSession instance.
    """
    if impersonate and _HAS_CURL_CFFI:
        return _create_curl_cffi_session(impersonate, proxy, verify, timeout)
    if impersonate and not _HAS_CURL_CFFI:
        import lib.formatter
        lib.formatter.warn(
            "--impersonate requires curl_cffi. Install with: pip install wafbypass[impersonate]. "
            "Falling back to standard requests (no TLS impersonation)."
        )
    return _create_requests_session(proxy, verify, timeout, pool_connections, pool_maxsize)


def _create_curl_cffi_session(impersonate, proxy, verify, timeout):
    """Create a curl_cffi session with TLS fingerprint impersonation."""
    from curl_cffi.requests import Session

    kwargs = {
        "impersonate": impersonate,
        "verify": verify,
        "timeout": timeout,
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}

    session = Session(**kwargs)
    return TransportSession(backend="curl_cffi", session=session, impersonate=impersonate)


def _create_requests_session(proxy, verify, timeout, pool_connections=10, pool_maxsize=20):
    """Create a standard requests session with connection pooling."""
    session = requests.Session()
    session.verify = verify

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    adapter = requests.adapters.HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=0,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return TransportSession(backend="requests", session=session, impersonate=None)


def get_backend_info():
    """
    Return a dict describing the current transport capabilities.
    Useful for --fingerprint and report generation.
    """
    info = {
        "curl_cffi_available": _HAS_CURL_CFFI,
        "supported_targets": list(IMPERSONATE_TARGETS) if _HAS_CURL_CFFI else [],
        "default_backend": "curl_cffi" if _HAS_CURL_CFFI else "requests",
    }
    if _HAS_CURL_CFFI:
        try:
            import curl_cffi
            info["curl_cffi_version"] = curl_cffi.__version__
        except (ImportError, AttributeError):
            info["curl_cffi_version"] = "unknown"
    return info


def fetch_client_fingerprint(proxy=None, verify=True, timeout=10):
    """
    Fetch the client's TLS/HTTP fingerprint from tls.peet.ws/api/all.
    Returns a dict with ja3, ja4, http2 fingerprint, user_agent, etc.
    Returns None on failure.
    """
    try:
        session = create_session(impersonate=None, proxy=proxy, verify=verify, timeout=timeout)
        resp = session.get("https://tls.peet.ws/api/all")
        session.close()
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass

    # Fallback: try with curl_cffi if available to show impersonated fingerprint
    if _HAS_CURL_CFFI:
        try:
            session = create_session(impersonate=DEFAULT_IMPERSONATE, proxy=proxy, verify=verify, timeout=timeout)
            resp = session.get("https://tls.peet.ws/api/all")
            session.close()
            if resp.status_code == 200:
                data = resp.json()
                data["_note"] = "fingerprint shown is for impersonate={}".format(DEFAULT_IMPERSONATE)
                return data
        except Exception:
            pass

    return None
