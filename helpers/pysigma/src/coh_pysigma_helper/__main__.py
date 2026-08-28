"""Single-document standard-input process entry point."""

from __future__ import annotations

import builtins
import os
import socket
import sys
from typing import NoReturn

from .compiler import compile_request
from .protocol import MAXIMUM_DOCUMENT_BYTES, ProtocolDenied, decode_request, encode, generic_denial


def _denied(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise PermissionError("capability denied")


def _close_ambient_capabilities() -> None:
    os.environ.clear()
    socket.socket = _denied  # type: ignore[assignment]
    socket.create_connection = _denied  # type: ignore[assignment]
    socket.getaddrinfo = _denied  # type: ignore[assignment]
    builtins.open = _denied  # type: ignore[assignment]


def main() -> int:
    if len(sys.argv) != 1:
        sys.stdout.buffer.write(generic_denial())
        return 2
    raw = sys.stdin.buffer.read(MAXIMUM_DOCUMENT_BYTES + 1)
    _close_ambient_capabilities()
    try:
        request = decode_request(raw)
        response = compile_request(request)
    except (ProtocolDenied, MemoryError, RecursionError):
        sys.stdout.buffer.write(generic_denial())
        return 2
    except Exception:
        sys.stdout.buffer.write(generic_denial())
        return 2
    sys.stdout.buffer.write(encode(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
