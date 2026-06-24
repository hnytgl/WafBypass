import hashlib
import platform
import sys

import lib.formatter
import lib.settings


def create_identifier(data):
    return hashlib.sha1(str(data).encode("utf-8")).hexdigest()[1:10]


def _redacted_command(args=None):
    args = list(sys.argv if args is None else args)
    sensitive = set(lib.settings.SENSITIVE_ARGUMENTS)
    redacted = []
    hide_next = False
    for item in args:
        if hide_next:
            redacted.append("***")
            hide_next = False
        else:
            redacted.append(item)
            hide_next = item in sensitive
    return " ".join(redacted)


def _save_issue_draft(issue_data):
    path = lib.settings.save_temp_issue(issue_data)
    lib.formatter.info(
        "an anonymized issue draft was saved to '{}'. Review it before submitting at {}".format(
            path, lib.settings.ISSUES_LINK
        )
    )
    return path


def request_issue_creation(exception_details):
    """Create a local, anonymized issue draft after an unhandled exception."""
    question = lib.formatter.prompt(
        "would you like to create an anonymized issue draft for the unhandled exception", "yN"
    )
    if not question.lower().startswith("y"):
        return None

    identifier = create_identifier(exception_details)
    python_version = "{}.{}.{}".format(
        sys.version_info.major, sys.version_info.minor, sys.version_info.micro
    )
    issue_data = {
        "title": "WAFBypass Unhandled Exception ({})".format(identifier),
        "body": (
            "WAFBypass version: `{}`\n"
            "Running context: `{}`\n"
            "Python version: `{}`\n"
            "Traceback:\n```\n{}\n```\n"
            "Running platform: `{}`"
        ).format(
            lib.settings.VERSION,
            _redacted_command(),
            python_version,
            exception_details,
            platform.platform(),
        ),
    }
    return _save_issue_draft(issue_data)


def request_firewall_issue_creation(path):
    """Create a local issue draft for an unknown firewall fingerprint."""
    question = lib.formatter.prompt(
        "would you like to create an issue draft for the discovered unknown firewall", "yN"
    )
    if question.lower().startswith("y"):
        with open(path, encoding="utf-8", errors="replace") as data:
            full_fingerprint = data.read()

        identifier = create_identifier(full_fingerprint[:4096])
        issue_data = {
            "title": "Unknown Firewall ({})".format(identifier),
            "body": (
                "WAFBypass version: `{}`\n"
                "Running context: `{}`\n"
                "Fingerprint:\n```\n{}\n```"
            ).format(
                lib.settings.VERSION,
                _redacted_command(),
                full_fingerprint,
            ),
        }
        _save_issue_draft(issue_data)

    lib.formatter.info(
        "for further analysis the WAF fingerprint can be found in: '{}'".format(path)
    )
