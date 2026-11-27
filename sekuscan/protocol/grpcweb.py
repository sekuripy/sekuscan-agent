# Copyright (c) 2026 Miroslav Stampar (https://sekuripy.hr)
# See the file 'LICENSE' for copying permission
"""gRPC-Web responses as readable text.

A gRPC-Web message is a length-prefixed protobuf frame; `grpc-web-text` is
that frame base64-encoded, carried by an ordinary HTTP/1.1 `POST`. The agent
only renders a response's frames and trailer as text (`render_response`) so
the probe result carries readable text instead of an opaque blob.
Compressed and streaming responses are left as they are.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from typing import Any, Optional

#: gRPC-Web content types. `+proto` is the same wire format under a spelling
#: that names the message encoding.
TEXT_CONTENT_TYPES = ("application/grpc-web-text",
                      "application/grpc-web-text+proto")
#: The binary framing of the same messages.
BINARY_CONTENT_TYPES = ("application/grpc-web", "application/grpc-web+proto")

_MAX_VARINT_BYTES = 10           # a 64-bit varint is at most 10 bytes
_MAX_FIELD_NUMBER = 0x1FFFFFFF   # protobuf maximum (2**29 - 1)
_B64_QUANTUM = re.compile(r"\A(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{2}=="
                          r"|[A-Za-z0-9+/]{3}=)\Z")

WIRE_VARINT, WIRE_64BIT, WIRE_LEN, WIRE_32BIT = 0, 1, 2, 5


def content_type_is_text(value: Optional[str]) -> bool:
    return (value or "").split(";", 1)[0].strip().lower() in TEXT_CONTENT_TYPES


def content_type_is_grpc_web(value: Optional[str]) -> bool:
    head = (value or "").split(";", 1)[0].strip().lower()
    return head in TEXT_CONTENT_TYPES or head in BINARY_CONTENT_TYPES


def _b64decode(text: str) -> bytes:
    """Strict base64, decoded one quantum at a time.

    Per-quantum rather than whole-string because a `grpc-web-text` body may
    concatenate independently padded chunks: a mid-stream `=` is legal there
    and `base64.b64decode` on the whole string would silently mis-align.
    Whitespace and any non-alphabet character are rejected outright: this
    decides whether a body is gRPC-Web at all, so guessing is worse than
    declining.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii", "strict")
    if not text or len(text) % 4:
        raise ValueError("invalid base64 length")
    out = bytearray()
    for offset in range(0, len(text), 4):
        quantum = text[offset:offset + 4]
        if not _B64_QUANTUM.match(quantum):
            raise ValueError("invalid base64")
        try:
            out += base64.b64decode(quantum)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid base64: %s" % exc)
    return bytes(out)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = result = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if result >= (1 << 64):
                raise ValueError("varint exceeds 64 bits")
            return result, pos
        shift += 7
        if pos - start >= _MAX_VARINT_BYTES:
            raise ValueError("overlong varint")


def _read_exact(buf: bytes, pos: int, length: int) -> tuple[bytes, int]:
    end = pos + length
    if length < 0 or end > len(buf):
        raise ValueError("truncated protobuf field")
    return buf[pos:end], end


def parse_message(buf: bytes) -> list[list[Any]]:
    """`[[field_number, wire_type, value], ...]` for one protobuf message."""
    pos = 0
    out: list[list[Any]] = []
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        number, wire = tag >> 3, tag & 7
        if not 0 < number <= _MAX_FIELD_NUMBER:
            raise ValueError("invalid field number %d" % number)
        if wire == WIRE_VARINT:
            value, pos = _read_varint(buf, pos)
        elif wire == WIRE_64BIT:
            value, pos = _read_exact(buf, pos, 8)
        elif wire == WIRE_LEN:
            length, pos = _read_varint(buf, pos)
            value, pos = _read_exact(buf, pos, length)
        elif wire == WIRE_32BIT:
            value, pos = _read_exact(buf, pos, 4)
        else:
            raise ValueError("unsupported wire type %d" % wire)
        out.append([number, wire, value])
    return out


def render_response(body: Optional[str | bytes], headers: Optional[dict[str, str]]
                    ) -> Optional[str]:
    """A gRPC-Web response as readable text, or None to leave it alone.

    This lets generic response analysis work over gRPC-Web. Left as base64, the
    body is an opaque blob in which no error string, reflected marker or stack
    trace could be seen. Rendering the message fields plus the trailer's
    `grpc-status`/`grpc-message` turns the transport back into readable text.

    A trailers-only error carries its status in the HTTP headers with an
    empty body, so the headers are read whether or not the body decodes.
    """
    lines: list[str] = []
    lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
    status = lowered.get("grpc-status")
    if status is not None:
        lines.append("grpc-status:%s" % status)
    message = lowered.get("grpc-message")
    if message:
        lines.append("grpc-message:%s" % _unquote(str(message)))

    if body and content_type_is_text(lowered.get("content-type")):
        try:
            lines.extend(_render_frames(_b64decode(body)))
        except (ValueError, UnicodeDecodeError):
            # Commit nothing partial: a half-parsed render would show
            # content that was not on the wire.
            lines.append(body.decode("utf-8", "replace")
                         if isinstance(body, bytes) else body)
    elif body and content_type_is_grpc_web(lowered.get("content-type")):
        try:
            raw = body if isinstance(body, bytes) else body.encode("latin-1")
            lines.extend(_render_frames(raw))
        except (ValueError, UnicodeDecodeError, UnicodeEncodeError):
            # A caller may already have decoded a binary body before it
            # reached this accessor. Keep it rather than guessing at a
            # second wire representation.
            lines.append(body.decode("utf-8", "replace")
                         if isinstance(body, bytes) else body)
    elif body:
        lines.append(body.decode("utf-8", "replace")
                     if isinstance(body, bytes) else body)

    return "\n".join(lines) if lines else None


def _render_frames(raw: bytes) -> list[str]:
    out: list[str] = []
    pos = 0
    data_frames = 0
    trailer_seen = False
    while pos + 5 <= len(raw):
        flag = raw[pos]
        length = struct.unpack(">I", raw[pos + 1:pos + 5])[0]
        payload, pos = _read_exact(raw, pos + 5, length)
        if trailer_seen:
            raise ValueError("frame after trailer")
        if flag == 0x00:
            data_frames += 1
            if data_frames > 1:
                raise ValueError("streaming response not supported")
            # Some gateways put a JSON document in the data frame even
            # though the transport advertises `+proto`; it is rendered as
            # text. Protobuf replies are rendered field by field below.
            if payload.lstrip().startswith((b"{", b"[")):
                text = payload.decode("utf-8")
                import json
                json.loads(text)
                out.append(text)
            else:
                for _number, wire, value in parse_message(payload):
                    out.append(bytes(value).decode("utf-8", "replace")
                               if wire == WIRE_LEN else str(value))
        elif flag == 0x80:
            trailer_seen = True
            out.append(_unquote(payload.decode("latin-1")))
        else:
            raise ValueError("unsupported frame flags 0x%02x" % flag)
    if pos != len(raw):
        raise ValueError("trailing bytes after the final frame")
    return out


def _unquote(text: str) -> str:
    """gRPC percent-encodes `grpc-message`; stdlib unquote is enough."""
    from urllib.parse import unquote
    return unquote(text)
