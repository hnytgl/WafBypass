import os
import re
import sys
import json
import time
import random
import string
import platform
import urllib.parse as urlparse

import requests
from bs4 import BeautifulSoup

import lib.formatter
import lib.database

try:
    import yaml
except ImportError:
    yaml = None

# version number <major>.<minor>.<patch>
VERSION = "4.0.0"
TLS_VERIFY = True

# version string
VERSION_TYPE = "($dev)" if VERSION.count(".") > 1 else "($stable)"

# the saying that will go inside of the banner
SAYING = "/><script>alert();</script>"
INSIDE_SAYING = '"\033[94mWAFBypass\033[0m\033[1m<|>v{}{}\033[1m"'.format(VERSION, VERSION_TYPE)

# cool looking banner
BANNER = """\b\033[1m
\t                          ,------.
\t                         '  .--.  '
\t,--.   .--.   ,--.   .--.|  |  |  |
\t|  |   |  |   |  |   |  |'--'  |  |
\t|  |   |  |   |  |   |  |    __.  |
\t|  |.'.|  |   |  |.'.|  |   |   .'
\t|         |   |         |   |___|
\t|   ,'.   |af|   ,'.   |ypass .---.
\t'--'   '--'   '--'   '--'   '---'
{}
\033[0m"""

# template for the results if needed
RESULTS_TEMPLATE = "{}\nSite: {}\nIdentified Protections: {}\nIdentified Tampers: {}\nIdentified Webserver: {}\n{}"

# directory to do the importing for the WAF scripts
PLUGINS_IMPORT_TEMPLATE = "content.plugins.{}"

# directory to do the importing for the tamper scripts
TAMPERS_IMPORT_TEMPLATE = "content.tampers.{}"

# link to the create a new issue page
ISSUES_LINK = "https://github.com/hnytgl/wafbypass/issues/new"

# regex to detect the URL protocol (http or https)
PROTOCOL_DETECTION = re.compile("http(s)?")

# check if a query is in a URL or not
URL_QUERY_REGEX = re.compile(r"(.*)[?|#](.*){1}\=(.*)")

# Project/package root. Resource discovery must not depend on the directory from
# which the CLI was launched.
CUR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# path to our home directory
HOME = "{}/.wafbypass".format(os.path.expanduser("~"))

# plugins (waf scripts) path
try:
    PLUGINS_DIRECTORY = "{}/content/plugins".format(CUR_DIR)
    os.listdir(PLUGINS_DIRECTORY)
except OSError:
    PLUGINS_DIRECTORY = "{}/plugins".format(HOME)

# tampers (tamper scripts) path
try:
    TAMPERS_DIRECTORY = "{}/content/tampers".format(CUR_DIR)
    os.listdir(TAMPERS_DIRECTORY)
except OSError:
    TAMPERS_DIRECTORY = "{}/tampers".format(HOME)

# flag: True when tamper/plugin directory fell back to user-writable ~/.wafbypass/
_USING_FALLBACK_TAMPERS = TAMPERS_DIRECTORY.startswith(HOME)
_USING_FALLBACK_PLUGINS = PLUGINS_DIRECTORY.startswith(HOME)

# name provided to unknown firewalls
UNKNOWN_FIREWALL_NAME = "Unknown Firewall"

# fingerprint path for unknown firewalls
UNKNOWN_PROTECTION_FINGERPRINT_PATH = "{}/fingerprints".format(HOME)

# JSON data file path
JSON_FILE_PATH = "{}/json_output".format(HOME)

# YAML data file path
YAML_FILE_PATH = "{}/yaml_output".format(HOME)

# CSV data file path
CSV_FILE_PATH = "{}/csv_output".format(HOME)

# for when an issue occurs but is not processed due to an error
UNPROCESSED_ISSUES_PATH = "{}/unprocessed_issues".format(HOME)

# known POST strings (I'll probably think of more later)
try:
    POST_STRING_NAMES_PATH = "{}/content/files/post_strings.lst".format(CUR_DIR)
    open(POST_STRING_NAMES_PATH).close()
except IOError:
    POST_STRING_NAMES_PATH = "{}/files/post_strings.lst".format(HOME)

# path to the database file
DATABASE_FILENAME = "{}/wafbypass.sqlite".format(HOME)

# payloads that have been exported from database cache
EXPORTED_PAYLOADS_PATH = "{}/payload_exports".format(HOME)

# default payloads path
try:
    DEFAULT_PAYLOAD_PATH = "{}/content/files/default_payloads.lst".format(CUR_DIR)
    open(DEFAULT_PAYLOAD_PATH).close()
except IOError:
    DEFAULT_PAYLOAD_PATH = "{}/files/default_payloads.lst".format(HOME)

# default user-agent
DEFAULT_USER_AGENT = "wafbypass/{} (Language={}; Platform={})".format(
    VERSION, sys.version.split(" ")[0], platform.platform().split("-")[0]
)

# module-level cache for user agents (loaded once on first use)
_AGENT_CACHE = None

# module-level shared HTTP session (connection pooling + cookie jar)
_SESSION = None

# TLS fingerprint impersonation target (set via configure_transport)
_IMPERSONATE = None

# Last request elapsed time in milliseconds (for blind/timing analysis)
_LAST_ELAPSED_MS = 0

# arguments that need to be blocked from issue creations and waf creations
SENSITIVE_ARGUMENTS = ("--proxy", "-u", "--url", "-D", "--data", "--pa", "-b", "--burp")

# payloads for detecting the WAF, at least one of
# these payloads `should` trigger the WAF and provide
# us with the information we need to identify what
# the WAF is, along with the information we will need
# to identify what tampering method we should use
# they are located in ./content/files/default_payloads.lst
with open(DEFAULT_PAYLOAD_PATH) as _f:
    WAF_REQUEST_DETECTION_PAYLOADS = [p.strip() for p in _f.readlines() if p.strip()]

# random home pages to try and get cookies
RAND_HOMEPAGES = (
    "index.php", "index.exe", "index.html", "index.py", "index.pl", "index.exe",
    "phpadmin.php", "home.php", "home.html", "home.py", "home.pl", "home.exe",
    "phpcmd.exe", "index.phpcmd.exe", "index.html", "index.htm", "index.shtml",
    "index.php", "index.php5", "index.php5.exe", "index.php4.exe", "index.php4",
    "index.php3", "index.cgi", "default.html", "default.htm", "home.html", "home.htm",
    "Index.html", "Index.htm", "Index.shtml", "Index.php", "Index.cgi", "Default.html",
    "Default.htm", "Home.html", "Home.htm", "placeholder.html"
)

# this is a regex to validate a URL. It was taken from Django's URL validation technique
# reference can be found here:
# `https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not/7160778#7160778`
URL_VALIDATION = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)


class InvalidURLProvided(Exception):
    pass


class _JsonResponseWrapper:
    """
    Lightweight wrapper for JSON/API responses that preserves the raw text
    for str() calls (used by block detection) while also providing .json()
    for structured access. Avoids BeautifulSoup HTML parsing which would
    destroy JSON structure.
    """

    def __init__(self, text):
        self._text = text
        self._parsed = None

    def __str__(self):
        return self._text

    def __len__(self):
        return len(self._text)

    def __bool__(self):
        return bool(self._text)

    def json(self):
        """Parse and return the JSON data (cached)."""
        if self._parsed is None:
            try:
                self._parsed = json.loads(self._text)
            except (json.JSONDecodeError, ValueError):
                self._parsed = {}
        return self._parsed

    def get_text(self):
        return self._text


# JSON block markers: keys/values in JSON responses that indicate a WAF block
_JSON_BLOCK_KEYS = ("error", "message", "detail", "reason", "description")
_JSON_BLOCK_PATTERNS = (
    re.compile(r"\bblocked\b", re.I),
    re.compile(r"\bforbidden\b", re.I),
    re.compile(r"\bdenied\b", re.I),
    re.compile(r"access.denied", re.I),
    re.compile(r"\bwaf\b", re.I),
    re.compile(r"firewall", re.I),
    re.compile(r"not.acceptable", re.I),
    re.compile(r"request.rejected", re.I),
    re.compile(r"illegal", re.I),
    re.compile(r"malicious", re.I),
)


def is_json_block(response_text):
    """
    Check if a JSON response body indicates a WAF block.
    Returns True if block markers are found in common error fields.
    """
    if not response_text:
        return False
    try:
        data = json.loads(response_text) if isinstance(response_text, str) else response_text
    except (json.JSONDecodeError, ValueError, TypeError):
        return False

    if not isinstance(data, dict):
        return False

    # Check common error/message fields
    for key in _JSON_BLOCK_KEYS:
        value = data.get(key)
        if isinstance(value, str):
            for pattern in _JSON_BLOCK_PATTERNS:
                if pattern.search(value):
                    return True
        elif isinstance(value, dict):
            # Nested error objects: {"error": {"message": "blocked by WAF"}}
            for nested_key in ("message", "detail", "reason", "text"):
                nested = value.get(nested_key)
                if isinstance(nested, str):
                    for pattern in _JSON_BLOCK_PATTERNS:
                        if pattern.search(nested):
                            return True
    return False


class HTTP_HEADER:
    """
    HTTP request headers list, putting it in a class because
    it's just easier to grab them then to retype them over
    and over again
    """
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    AESECURE_CODE = "aeSecure-code"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    CONTENT_SECURITY = "Content-Security-Policy"
    COOKIE = "Cookie"
    CF_RAY = "CF-RAY"
    EXPIRES = "Expires"
    EXPECT_CT = "Expect-CT"
    GW_SERVER = "GW-Server"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    STRICT_TRANSPORT = "Strict-Transport-Security"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_CACHE = "X-Cache"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"
    X_FRAME_OPT = "X-Frame-Options"
    X_FORWARDED_FOR = "X-Forwarded-For"
    X_SERVER = "X-Server"
    X_BACKSIDE_TRANS = "X-Backside-Transport"


def validate_url(url):
    """
    validate a provided URL
    """
    return URL_VALIDATION.match(url)


def configure_tls_verification(verify=True):
    global TLS_VERIFY
    TLS_VERIFY = bool(verify)


def get_query(url):
    """
    get the query parameter out of a URL
    """
    data = urlparse.urlparse(url)
    query = "{}?{}".format(data.path, data.query)
    return query


def _get_session():
    """
    Return the module-level TransportSession for connection pooling,
    keep-alive, cookie persistence and optional TLS impersonation.
    Created lazily on first use via lib.transport.
    """
    global _SESSION
    if _SESSION is None:
        import lib.transport
        _SESSION = lib.transport.create_session(
            impersonate=_IMPERSONATE,
            verify=TLS_VERIFY,
            timeout=15,
        )
    return _SESSION


def configure_transport(impersonate=None, cookie_jar=None):
    """
    Configure the transport layer before first request.
    Called from main() after CLI parsing.

    Args:
        impersonate: TLS fingerprint target (e.g. "chrome120") or None.
        cookie_jar: path to Netscape cookie file to preload, or None.
    """
    global _IMPERSONATE, _SESSION
    _IMPERSONATE = impersonate
    # Reset session so it gets recreated with new settings
    if _SESSION is not None:
        _SESSION.close()
        _SESSION = None
    # Pre-create session if cookie jar provided
    if cookie_jar:
        session = _get_session()
        try:
            count = session.load_cookie_jar(cookie_jar)
            lib.formatter.info("loaded {} cookies from '{}'".format(count, cookie_jar))
        except Exception as e:
            lib.formatter.warn("failed to load cookie jar '{}': {}".format(cookie_jar, e))


def close_session():
    """explicitly close the shared session (useful for tests / cleanup)"""
    global _SESSION
    if _SESSION is not None:
        _SESSION.close()
        _SESSION = None


def get_last_elapsed_ms():
    """Return the elapsed time (ms) of the most recent get_page() call.
    Used for blind/timing-based detection."""
    return _LAST_ELAPSED_MS


def get_page(url, **kwargs):
    """
    get the website page, this will return a `tuple`
    containing the status code, HTML and headers of the
    requests page. Uses a shared Session for connection
    pooling and cookie persistence.
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", DEFAULT_USER_AGENT)
    provided_headers = kwargs.get("provided_headers", None)
    throttle = kwargs.get("throttle", 0)
    req_timeout = kwargs.get("timeout", 15)
    request_method = str(kwargs.get("request_method", "GET")).upper()
    post_data = kwargs.get("post_data", " ") or ""
    verify_tls = kwargs.get("verify_tls", TLS_VERIFY)

    if post_data.isspace():
        items = list(post_data)
        for i, item in enumerate(items):
            if item == "=":
                items[i] = "{}{}{}".format(items[i - 1], items[i], random_string(length=7))

        post_data = ''.join(items)

    if provided_headers is None:
        headers = {"User-Agent": agent}
    else:
        headers = {}
        if isinstance(provided_headers, dict):
            for key, value in provided_headers.items():
                headers[key] = value
            headers["User-Agent"] = agent
        else:
            headers = dict(provided_headers)
            headers["User-Agent"] = agent
    proxies = {} if proxy is None else {"http": proxy, "https": proxy}
    error_retval = ("", 0, "", {})

    # throttle the requests from here
    if throttle:
        time.sleep(throttle)

    session = _get_session()
    resp = None
    try:
        request_kwargs = {
            "headers": headers,
            "timeout": req_timeout,
        }
        # Only pass proxies/verify per-request for requests backend;
        # curl_cffi sessions have these configured at creation time.
        if session.backend == "requests":
            request_kwargs["proxies"] = proxies
            request_kwargs["verify"] = verify_tls
        if request_method == "POST":
            resp = session.post(url, data=post_data, **request_kwargs)
        else:
            resp = session.get(url, **request_kwargs)
        # Record elapsed time for blind/timing analysis
        global _LAST_ELAPSED_MS
        try:
            elapsed = getattr(resp, "elapsed", None)
            _LAST_ELAPSED_MS = int(elapsed.total_seconds() * 1000) if elapsed and hasattr(elapsed, "total_seconds") else 0
        except (TypeError, AttributeError):
            _LAST_ELAPSED_MS = 0

        # Content-Type sniffing: JSON/API responses get raw text instead of
        # BeautifulSoup HTML parsing, which would destroy structure.
        content_type = ""
        if hasattr(resp, "headers") and resp.headers:
            content_type = str(resp.headers.get("Content-Type", "") or "").lower()

        if "json" in content_type or "graphql" in content_type:
            # For JSON responses, return raw text as a lightweight wrapper
            # that str() will produce the original JSON string.
            parsed = _JsonResponseWrapper(resp.text)
        else:
            parsed = BeautifulSoup(resp.content, "html.parser")

        return "{} {}".format(request_method, get_query(url)), resp.status_code, parsed, resp.headers
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
            requests.exceptions.TooManyRedirects, requests.exceptions.SSLError,
            requests.exceptions.ChunkedEncodingError):
        return error_retval
    except requests.exceptions.RequestException:
        return error_retval
    except Exception as e:
        # curl_cffi raises its own exception types; catch broadly
        err_str = str(e).lower()
        if "timed out" in err_str or "timeout" in err_str:
            return error_retval
        if "connection" in err_str or "ssl" in err_str or "curl" in err_str:
            return error_retval
        raise
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass


def get_random_agent(path="{}/files/user_agents.txt"):
    """
    grab a random user-agent from the file to pass as
    the HTTP User-Agent header. The agent list is cached
    at module level after first load to avoid repeated
    ~392KB disk reads on every request.
    """
    global _AGENT_CACHE
    if _AGENT_CACHE is None:
        try:
            with open(path.format(HOME)) as agents:
                _AGENT_CACHE = [agent.strip() for agent in agents.readlines() if agent.strip()]
        except IOError:
            try:
                with open("{}/content/files/user_agents.txt".format(CUR_DIR)) as agents:
                    _AGENT_CACHE = [agent.strip() for agent in agents.readlines() if agent.strip()]
            except IOError:
                _AGENT_CACHE = [DEFAULT_USER_AGENT]
    return random.choice(_AGENT_CACHE)


class SessionManager(object):
    """
    session-based HTTP manager with connection pooling and retry support.
    Respects the global TLS_VERIFY setting instead of hardcoding verify=False.
    """
    def __init__(self, proxy=None, agent=None, timeout=15, max_retries=3):
        self.session = requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if agent:
            self.session.headers.update({"User-Agent": agent})
        self.session.headers.update({"Connection": "keep-alive"})
        self.session.verify = TLS_VERIFY
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=max_retries,
            pool_block=False
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url, **kwargs):
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(url, timeout=self.timeout, **kwargs)

    def close(self):
        self.session.close()


def configure_request_headers(**kwargs):
    """
    configure the HTTP request headers with a user defined
    proxy, Tor, or a random User-Agent from the user-agent
    file
    """
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    tor = kwargs.get("tor", False)
    use_random_agent = kwargs.get("random_agent", False)
    tor_port = kwargs.get("tor_port", 9050)

    supported_proxies = ("socks5", "socks4", "http", "https")

    invalid_msg = "invalid switches detected, switch {} cannot be used in conjunction with switch {}"
    proxy_msg = "running behind proxy '{}'"

    if proxy is not None and tor:
        lib.formatter.error(invalid_msg.format("--tor", "--proxy"))
        exit(1)
    if agent is not None and use_random_agent:
        lib.formatter.error(invalid_msg.format("--ra", "--pa"))
        exit(1)
    if tor:
        proxy = "socks5://127.0.0.1:{}".format(tor_port)
    if agent is None:
        agent = DEFAULT_USER_AGENT
    if use_random_agent:
        agent = get_random_agent()
    if proxy is not None:
        if any(item in proxy for item in supported_proxies):
            lib.formatter.info(proxy_msg.format(proxy))
        else:
            lib.formatter.error(
                "you did not provide a supported proxy protocol, "
                "supported protocols are '{}'. check your proxy and try again".format(
                    ", ".join([p for p in supported_proxies])
                )
            )
            exit(1)
    else:
        lib.formatter.warn(
            "it is highly advised to use a proxy when using WAFBypass. do so by passing the proxy flag "
            "(IE `--proxy http://127.0.0.1:9050`) or by passing the Tor flag (IE `--tor`)", minor=True
        )
    if agent is not None:
        lib.formatter.info("using User-Agent '{}'".format(agent))
    return proxy, agent


def produce_results(found_tampers):
    """
    produce the results of the tamper scripts, if any this
    """
    spacer = "-" * 30
    if len(found_tampers) > 0:
        lib.formatter.success("apparent working tampers for target:")
        print(spacer)
        for i, tamper in enumerate(found_tampers, start=1):
            description, example, load = tamper
            try:
                load = str(load).split(" ")[1].split("'")[1]
            except IndexError:
                pass
            print("(#{}) description: tamper payload by {}\nexample: '{}'\nload path: {}".format(
                i, description, example, load
            ))
            if i != len(found_tampers):
                print("\n")
        print(spacer)
    else:
        lib.formatter.warn("no valid bypasses discovered with provided payloads")


def random_string(acceptable=string.ascii_letters, length=5, use_json=False, use_yaml=False, use_csv=False):
    """
    create a random string for some of the tamper scripts that
    need a random string in order to work properly
    """
    random_chars = [random.choice(acceptable) for _ in range(length)]
    if use_json:
        return "{}.json".format(''.join(random_chars))
    elif use_yaml:
        return "{}.yaml".format(''.join(random_chars))
    elif use_csv:
        return "{}.csv".format(''.join(random_chars))
    else:
        return ''.join(random_chars)


def generate_random_post_string(amount=2):
    """
    generate a random POST string from a list of provided keywords
    """
    send_string_retval = []
    post_name_retval = set()
    for _ in range(amount):
        send_string_retval.append(
            random_string(
                acceptable=string.ascii_letters + string.digits,
                length=random.choice(range(4, 18))
            )
        )
    with open(POST_STRING_NAMES_PATH, "r") as data:
        line_data = [c.strip() for c in data.readlines()]
        while len(post_name_retval) != 2:
            post_name_retval.add(random.choice(line_data))
    post_name_retval = list(post_name_retval)
    post_string_retval_data = (post_name_retval[0], send_string_retval[0], post_name_retval[1], send_string_retval[1])
    return "{}={}&{}={}".format(*post_string_retval_data)


def auto_assign(url, ssl=False):
    """
    check if a protocol is given in the URL if it isn't we'll auto assign it
    """
    if PROTOCOL_DETECTION.search(url) is None:
        if ssl:
            lib.formatter.warn("no protocol discovered, assigning HTTPS (SSL)")
            return "https://{}".format(url.strip())
        else:
            lib.formatter.warn("no protocol discovered assigning HTTP")
            return "http://{}".format(url.strip())
    else:
        if ssl:
            lib.formatter.info("forcing HTTPS (SSL) connection")
            items = PROTOCOL_DETECTION.split(url)
            item = items[-1].split("://")
            item[0] = "https://"
            return ''.join(item)
        else:
            return url.strip()


def create_fingerprint(url, content, status, headers, req_data=None, speak=False):
    """
    create the unknown firewall fingerprint file
    """
    if not os.path.exists(UNKNOWN_PROTECTION_FINGERPRINT_PATH):
        os.makedirs(UNKNOWN_PROTECTION_FINGERPRINT_PATH)

    __replace_http = lambda x: x.split("/")
    __replace_specifics = lambda u: "http://{}".format(u.split("/")[2])

    try:
        url = __replace_specifics(url)
    except Exception:
        lib.formatter.warn("full URL will be displayed to the public if an issue is created")
        url = url

    fingerprint = "<!--\n{}\nStatus code: {}\n{}\n-->\n{}".format(
        "GET {} HTTP/1.1".format(url) if req_data is None else "{} HTTP/1.1".format(req_data),
        str(status),
        '\n'.join("{}: {}".format(h, k) for h, k in headers.items()),
        str(content)
    )

    filename = __replace_http(url)[2]
    if "www" not in filename:
        filename = "www.{}".format(filename)
    full_file_path = "{}/{}".format(UNKNOWN_PROTECTION_FINGERPRINT_PATH, filename)
    if not os.path.exists(full_file_path):
        with open(full_file_path, "a+") as log:
            log.write(fingerprint)
        if speak:
            lib.formatter.success("fingerprint saved to '{}'".format(full_file_path))
    return full_file_path


def write_to_file(filename, path, data, **kwargs):
    """
    write the data to a file
    """
    write_yaml = kwargs.get("write_yaml", False)
    write_json = kwargs.get("write_json", False)
    write_csv = kwargs.get("write_csv", False)
    save_copy = kwargs.get("save_copy_to", None)

    full_path = "{}/{}".format(path, filename)

    if not os.path.exists(path):
        os.makedirs(path)
    if write_json and not write_yaml and not write_csv:
        with open(full_path, "a+") as _json:
            _json_data = json.loads(data)
            json.dump(_json_data, _json, sort_keys=True, indent=4)
    elif write_yaml and not write_json and not write_csv:
        try:
            # there is an extra dependency that needs to be installed for you to save to YAML
            # we'll check if you have it or not
            import yaml

            with open(full_path, "a+") as _yaml:
                # safe_load prevents arbitrary object construction from YAML tags
                # (e.g. !!python/object/apply) which would be an RCE vector if the
                # data ever originates from an untrusted scan result.
                _yaml_data = yaml.safe_load(data)
                yaml.dump(_yaml_data, _yaml, default_flow_style=False)
        except ImportError:
            # if you don't we'll just skip the saving and warn you
            lib.formatter.warn(
                "you do not have the needed dependency to save YAML files, to install the dependency run "
                "`pip install pyyaml`, skipping file writing"
            )
            return None
    elif write_csv and not write_json and not write_yaml:
        import csv

        _json_data = json.loads(data)
        try:
            csv_data = [
                ["url", "is_protected", "protection", "working_tampers"],
                [
                    _json_data["url"], _json_data["is protected"],
                    _json_data[
                        "identified firewall"
                    ] if _json_data["identified firewall"] is not None else "None",
                    _json_data[
                        "apparent working tampers"
                    ] if _json_data["apparent working tampers"] is not None else "None"
                ]
            ]
        except KeyError:
            pass
        with open(full_path, "a+") as _csv:
            writer = csv.writer(_csv)
            writer.writerows(csv_data)
    if save_copy is not None:
        import shutil
        try:
            shutil.copy(full_path, save_copy)
            lib.formatter.info("copy of file saved to {}".format(save_copy))
        except Exception:
            lib.formatter.error("failed to save copy of file, do you have permissions?")

    return full_path


def parse_burp_request(filename):
    """
    parse an XML file from Burp Suite and make a request based on what is parsed
    """
    burp_request_regex = re.compile(r"<url><\S.cdata.", re.I)
    tmp = set()
    retval = []

    with open(filename) as xml:
        for line in xml.readlines():
            line = line.strip()
            if burp_request_regex.search(line) is not None:
                tmp.add(line)
    tmp = list(tmp)
    for url in tmp:
        url = re.split("<(.)?url>", url)[2].split("CDATA")[-1].replace("[", "").replace("]]", "").replace(">", "")
        retval.append(url)
    return retval


def parse_googler_file(filepath):
    """
    parse a JSON file provided from a Googler search
    """
    retval = set()
    try:
        with open(filepath) as f:
            data = json.load(f)
            for item in data:
                retval.add(item["url"])
    except IOError:
        retval = None
    return retval


def check_version(speak=True):
    """
    check the version number for updates.
    Uses a 3s timeout and a 24h local cache to avoid blocking
    startup on slow/airgapped networks.
    Returns: True (up-to-date), False (new version available), None (check failed/skipped).
    """
    version_cache_path = "{}/.version_check".format(HOME)
    cache_ttl = 86400  # 24 hours

    # check local cache first
    try:
        if os.path.exists(version_cache_path):
            mtime = os.path.getmtime(version_cache_path)
            if time.time() - mtime < cache_ttl:
                with open(version_cache_path, "r") as f:
                    cached = f.read().strip()
                if cached and cached != VERSION:
                    if speak:
                        lib.formatter.warn("new version: {} is available (cached)".format(cached))
                    return False
                return True
    except (IOError, OSError):
        pass

    version_url = "https://raw.githubusercontent.com/hnytgl/wafbypass/master/lib/settings.py"
    try:
        req = requests.get(version_url, timeout=3)
        resp_text = req.text
        req.close()
        version_identification = resp_text.find("VERSION = ")
        if version_identification == -1:
            return None
        current_version = resp_text[version_identification:version_identification + 17]
        current_version = str(current_version.strip().split('"')[1])
        # write cache
        try:
            if not os.path.exists(HOME):
                os.makedirs(HOME)
            with open(version_cache_path, "w") as f:
                f.write(current_version)
        except (IOError, OSError):
            pass
        if current_version != VERSION:
            if speak:
                lib.formatter.warn("new version: {} is available".format(current_version))
            return False
        return True
    except Exception:
        if speak:
            lib.formatter.debug("error checking version, skipping")
        return None


def get_encoding_list(directory, is_tampers=True, is_wafs=False):
    """
    get a quick simple list of encodings
    """
    retval = set()
    items = os.listdir(directory)
    for item in items:
        if not any(skip in item for skip in ["__init__", "__pycache__"]):
            if is_tampers:
                item = TAMPERS_IMPORT_TEMPLATE.format(item.split(".")[0])
            elif is_wafs:
                if "unknown" not in item:
                    item = PLUGINS_IMPORT_TEMPLATE.format(item.split(".")[0])
            retval.add(item)
    return retval


def test_target_connection(url, proxy, agent, headers):
    """
    test connection to the target URL before doing anything else
    """
    test_times = 2
    failed = 0
    for _ in range(test_times):
        results = get_page(url, proxy=proxy, agent=agent, provided_headers=headers)
        _, status, _, _ = results
        if status is not None:
            if status == 0:
                failed += 1
        else:
            failed += 1
    if failed == 1:
        return "acceptable"
    elif failed == 2:
        return "nogo"
    else:
        return "ok"


def parse_help_menu(data, start, end):
    """
    parse the help menu from a certain string to a certain string
    and return the parsed help
    """
    try:
        # DO YOU SEE HOW MUCH EASIER IT IS WITH
        # PYTHON2 ?!
        start_index = data.index(start)
        end_index = data.index(end)
        retval = data[start_index:end_index].strip()
    except TypeError:
        # python3 is stupid and likes `bytes` because why tf not?
        plus, plus_another = 60, 8
        # so now we gotta add 60 in order to get the last line from the last command
        # out of the way
        start_index = data.decode().index(start) + plus
        end_index = data.decode().index(end)
        # and then we gotta convert back
        data = str(data)
        # and then we gotta store into a temporary list
        tmp = data[start_index:end_index + plus_another]
        # split the list into another list because of escapes
        # join that list with a new line and finally get the
        # retval out of it. Because that makes PERFECT sense
        retval = "\n".join(tmp.split("\\n")).replace("n\n", "")
    return retval


def save_temp_issue(data):
    """
    save unprocessed issues into a file so that they can be worked with later
    """
    if not os.path.exists(UNPROCESSED_ISSUES_PATH):
        os.makedirs(UNPROCESSED_ISSUES_PATH)
    file_path = "{}/{}.json".format(UNPROCESSED_ISSUES_PATH, random_string(length=32))
    with open(file_path, "a+") as outfile:
        json.dump(data, outfile)
    return file_path


def export_payloads(payloads, file_type):
    """
    export cached payloads from the database into a file for further use
    """
    if not os.path.exists(EXPORTED_PAYLOADS_PATH):
        os.makedirs(EXPORTED_PAYLOADS_PATH)
    is_json, is_csv, is_yaml = False, False, False
    if file_type.lower() == "json":
        is_json = True
    elif file_type.lower() == "csv":
        is_csv = True
    elif file_type.lower() == "yaml":
        try:
            import yaml
            is_yaml = True
        except ImportError:
            lib.formatter.fatal("you need the pyYAML library to export to yaml, get it by typing `pip install pyyaml`")
            exit(1)
    filename = random_string(use_csv=is_csv, use_json=is_json, use_yaml=is_yaml, length=15)
    file_path = "{}/whatwaf_{}_export_{}".format(EXPORTED_PAYLOADS_PATH, file_type.lower(), filename)
    with open(file_path, "a+") as dump_file:
        if is_json:
            retval = {"payloads": []}
            for item in payloads:
                retval["payloads"].append(str(item[-1]))
            json.dump(retval, dump_file)
        elif is_csv:
            import csv

            try:
                csv_data = [["payloads"], [str(p[-1]) for p in payloads]]
            except KeyError:
                pass
            writer = csv.writer(dump_file)
            writer.writerows(csv_data)
        elif is_yaml:
            import yaml

            retval = {"payloads": []}
            for item in payloads:
                retval["payloads"].append(str(item[-1]))
            yaml.dump(retval, dump_file, default_flow_style=False)
        else:
            for item in payloads:
                dump_file.write("{}\n".format(str(item[-1])))
    return file_path


def check_url_against_cached(given, cursor):
    """
    check the netlock of the provided URL against the netlock of the
    cached URL
    """
    is_cached = False
    cached_data = None
    cached = lib.database.fetch_data(cursor, is_payload=False)
    current_netlock_running = urlparse.urlparse(given).netloc
    for item in cached:
        _, cached_netlock, _, _, _ = item
        if str(cached_netlock) == str(current_netlock_running):
            is_cached = True
            cached_data = item
    if is_cached:
        display_only = lib.formatter.prompt(
            "this URL has already been ran, would you like to just display the cached data and skip",
            opts="yN",
            default="y"
        )
        if display_only.lower() == "y":
            return cached_data
        else:
            return None


def display_cached(urls, payloads):
    """
    display the database information in a neat format
    """
    if urls is not None:
        if len(urls) != 0:
            lib.formatter.info("cached URLs:")
            print("\tNetloc:{}|\t{}Web Server:\t{}|\t{}Working Tampers:{}\t|\tIdentified Protections:\n{}".format(
                " " * 13, " " * 2, " " * 5, " " * 3, " " * 10, "-" * 140
            ))
            output_template = "{0:27} | {1:22} | {2:40} | {3:50}"
            for i, cached in enumerate(urls):
                _, netlock, prots, tamps, server = cached
                if len(tamps) < 20:
                    tamps = tamps[0:15] + "..."
                print(output_template.format(netlock, server.split(" ")[0], tamps, prots))
            print(" {}".format("-" * 15))
        else:
            lib.formatter.warn("there are no cached URLs in the database")
    if payloads is not None:
        if len(payloads) != 0:
            lib.formatter.info("cached payloads:")
            print("{}".format("-" * 20))
            for i, payload in enumerate(payloads, start=1):
                print("#{} ~~> {}".format(i, payload[-1]))
            print("{}".format("-" * 20))
        else:
            lib.formatter.warn("no payloads have been cached into the database")


def shuffle_list(l):
    """
    shuffle a list in a cryptographically secure manner
    """
    random.SystemRandom().shuffle(l)
    return l


def make_saying_pretty(saying_string):
    """
    Obfuscate the banner saying string using a deterministic, safe
    transformation. Previously this randomly imported and executed a
    tamper plugin from disk, which was a local privilege escalation
    vector when the fallback directory (~/.wafbypass/tampers/) was
    writable by an attacker. Now uses a seeded shuffle of inline
    encoding transforms — no dynamic code execution.
    """
    import hashlib

    # deterministic seed from version so banner is reproducible for bug reports
    seed = int(hashlib.sha256(VERSION.encode()).hexdigest(), 16)
    rng = random.Random(seed)

    # inline safe transforms (no file I/O, no importlib)
    transforms = [
        lambda s: ''.join(c.upper() if rng.random() > 0.5 else c.lower() for c in s),
        lambda s: s.replace(' ', '\t'),
        lambda s: ''.join('&#{};'.format(ord(c)) if rng.random() > 0.7 else c for c in s),
        lambda s: s[::-1],
        lambda s: s,  # identity — sometimes no transform
    ]
    transform = rng.choice(transforms)
    new_saying_string = transform(saying_string)
    new_saying_string = new_saying_string.split("();")
    new_saying = "({});".format(INSIDE_SAYING).join(new_saying_string)
    return new_saying
