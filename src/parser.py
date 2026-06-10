"""Parse .eml files into a structured dict for phishing analysis.

Extracts the headers most relevant to spoofing checks (From, Reply-To,
Return-Path), the message bodies, and any URLs found in either the text
or HTML parts.
"""

import re
import sys
from email import message_from_binary_file
from email.message import Message
from email.utils import getaddresses

# Matches http/https URLs. Kept deliberately permissive: for phishing
# triage we would rather over-capture candidate links than miss one.
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)


def _decode_part(part: Message) -> str:
    """Decode a single message part's payload to text.

    Falls back through the part's declared charset, then utf-8, then a
    lossy decode so a single bad byte never aborts parsing.
    """
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _extract_bodies(msg: Message) -> tuple[str, str]:
    """Return (text_body, html_body) from a parsed message.

    Walks all parts and concatenates plain-text and HTML content
    separately, skipping attachments.
    """
    text_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        # Skip anything explicitly marked as an attachment.
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition:
            continue
        if content_type == "text/plain":
            text_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    return "\n".join(text_parts), "\n".join(html_parts)


def _extract_urls(*bodies: str) -> list[str]:
    """Extract a de-duplicated, order-preserving list of URLs.

    Scans each provided body string with the URL regex.
    """
    seen: set[str] = set()
    urls: list[str] = []
    for body in bodies:
        for match in URL_RE.findall(body or ""):
            # Trim trailing punctuation that commonly clings to URLs.
            url = match.rstrip(".,;:!?")
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def parse_eml(path: str) -> dict:
    """Parse a .eml file into a structured dict for phishing analysis.

    Args:
        path: Path to the .eml file on disk.

    Returns:
        A dict with the following keys:
            from:        Value of the From header (raw string or None).
            reply_to:    Value of the Reply-To header (or None).
            return_path: Value of the Return-Path header (or None).
            subject:     Value of the Subject header (or None).
            headers:     All headers as a plain dict (last value wins on
                         duplicate header names).
            text_body:   Concatenated text/plain content.
            html_body:   Concatenated text/html content.
            urls:        De-duplicated list of URLs from both bodies.
    """
    with open(path, "rb") as fh:
        msg = message_from_binary_file(fh)

    headers = dict(msg.items())
    text_body, html_body = _extract_bodies(msg)
    urls = _extract_urls(text_body, html_body)

    return {
        "from": msg.get("From"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "subject": msg.get("Subject"),
        "headers": headers,
        "text_body": text_body,
        "html_body": html_body,
        "urls": urls,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m src.parser <path-to-.eml>", file=sys.stderr)
        sys.exit(1)

    parsed = parse_eml(sys.argv[1])
    print(f"From:    {parsed['from']}")
    print(f"Subject: {parsed['subject']}")
    print(f"URLs:    {len(parsed['urls'])}")
