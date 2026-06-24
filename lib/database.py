import os
import sqlite3

import lib.settings
import lib.formatter


def initialize():
    """
    initialize the database and the HOME directory (~/.wafbypass)
    """
    os.makedirs(lib.settings.HOME, exist_ok=True)
    conn = sqlite3.connect(
        lib.settings.DATABASE_FILENAME,
        isolation_level=None,
        check_same_thread=False,
    )
    cursor = conn.cursor()
    cursor.execute(
        'CREATE TABLE IF NOT EXISTS "cached_payloads" ('
        '`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,'
        '`payload` TEXT NOT NULL'
        ')'
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS `cached_urls` ("
        "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "
        "`uri` TEXT NOT NULL, "
        "`working_tampers` TEXT NOT NULL DEFAULT 'N/A', "
        "`identified_protections` TEXT NOT NULL DEFAULT 'N/A',"
        "`identified_webserver`	TEXT NOT NULL DEFAULT 'N/A'"
        ")"
    )
    return cursor


def fetch_data(cursor, is_payload=True):
    """
    fetch all payloads or URLs out of the database
    """
    try:
        if is_payload:
            cached = cursor.execute("SELECT * FROM cached_payloads")
        else:
            cached = cursor.execute("SELECT * FROM cached_urls")
        retval = cached.fetchall()
    except Exception:
        retval = []
    return retval


def insert_payload(payload, cursor):
    """
    insert a payload into the database
    """
    try:
        existing = cursor.execute(
            "SELECT 1 FROM cached_payloads WHERE payload = ? LIMIT 1", (payload,)
        ).fetchone()
        if existing is None:
            cursor.execute("INSERT INTO cached_payloads (payload) VALUES (?)", (payload,))
    except Exception:
        return False
    return True


def _serialize_items(values, tamper_results=False):
    if values is None:
        return "N/A"
    if isinstance(values, str):
        values = [values]

    serialized = []
    for item in values:
        if tamper_results and isinstance(item, (tuple, list)) and len(item) >= 3:
            item = item[2]
        text = getattr(item, "__name__", str(item)).strip()
        if text and text not in serialized:
            serialized.append(text)
    return ",".join(sorted(serialized)) if serialized else "N/A"


def insert_url(netloc, working_tampers, identified_protections, cursor, webserver=None, return_found=False):
    """
    insert the URL into the database for future use, will only insert the netlock of the URL for easier
    caching and quicker checking, so multiple netlocks of the same URL can hypothetically be used IE:
     - www.foo.bar
     - ftp.foo.bar
     - ssh.foo.bar
    """
    try:
        if webserver is None:
            webserver = "N/A"
        netloc = str(netloc).strip()
        existing = cursor.execute(
            "SELECT * FROM cached_urls WHERE uri = ? LIMIT 1", (netloc,)
        ).fetchone()
        if existing is not None:
            return existing if return_found else False

        protections = [
            item for item in (identified_protections or [])
            if item != lib.settings.UNKNOWN_FIREWALL_NAME
        ] if not isinstance(identified_protections, str) else [identified_protections]
        serialized_tampers = _serialize_items(working_tampers, tamper_results=True)
        serialized_protections = _serialize_items(protections)

        cursor.execute(
            "INSERT INTO cached_urls ("
            "uri,working_tampers,identified_protections,identified_webserver"
            ") VALUES (?,?,?,?)",
            (netloc, serialized_tampers, serialized_protections, str(webserver))
        )
    except Exception:
        return False
    return True
