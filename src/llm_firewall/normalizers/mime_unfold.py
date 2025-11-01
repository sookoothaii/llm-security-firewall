# -*- coding: utf-8 -*-
"""
RFC 5322 Header Unfolding
Closes: MIME header folding obfuscation

Headers can be folded with CRLF + WSP (space/tab)
Example:
  Api-Key:
    sk-abc123
"""


def unfold_headers(text: str, max_headers: int = 50):
    """
    Unfold MIME/RFC 5322 style headers

    Returns:
        (headers_dict, body, metadata)
    """
    # Split into lines
    lines = text.split("\n")

    # Find header/body boundary (first empty line)
    boundary_idx = None
    for i, line in enumerate(lines):
        if line.strip() == "":
            boundary_idx = i
            break

    if boundary_idx is None:
        # No clear boundary - treat as body
        return {}, text, {"mime_unfolded": False, "header_count": 0}

    header_lines = lines[:boundary_idx]
    body_lines = lines[boundary_idx + 1 :]

    # Unfold headers (CRLF + WSP continuation)
    headers = {}
    current_header = None
    current_value = []
    count = 0

    for line in header_lines:
        # Continuation line (starts with space/tab)
        if line and line[0] in (" ", "\t"):
            if current_header:
                current_value.append(line.strip())
            continue

        # New header
        if ":" in line:
            # Save previous
            if current_header and count < max_headers:
                headers[current_header] = " ".join(current_value)
                count += 1

            # Parse new
            key, _, value = line.partition(":")
            current_header = key.strip().lower()
            current_value = [value.strip()]

    # Save last
    if current_header and count < max_headers:
        headers[current_header] = " ".join(current_value)
        count += 1

    body = "\n".join(body_lines)

    return (
        headers,
        body,
        {
            "mime_unfolded": len(headers) > 0,
            "header_count": len(headers),
            "headers_truncated": count >= max_headers,
        },
    )
