"""
TCP Connect Scan Module

Performs a full TCP three-way handshake against each port:

  connect succeeds          -> open
  connection refused (RST)  -> closed
  timeout / other error     -> filtered
"""

from __future__ import annotations

import errno
import socket
import ssl
import concurrent.futures
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class PortResult:
    port: int
    state: str  # {"open", "closed", "filtered"}
    banner: str = ""
    service: str = ""
    description: str = ""


# ECONNREFUSED on Linux/macOS, WSAECONNREFUSED (10061) on Windows
_REFUSED_ERRNOS = {errno.ECONNREFUSED, 10061}

TLS_PORTS = {443, 465, 636, 990, 993, 995, 2083, 2376, 3269, 5986, 6443, 8443}

HTTP_PORTS = {
    80, 443, 2375, 2376, 3000, 5000, 5601, 5985, 5986, 6443, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000,
}


def _check_port(target: str, port: int, timeout: float) -> PortResult:
    """
    Check if a port is open on a target using TCP connect.

    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
    except OSError:  # includes socket.timeout
        return PortResult(port=port, state="filtered")
    finally:
        sock.close()

    if result == 0:
        return PortResult(port=port, state="open")
    if result in _REFUSED_ERRNOS:
        return PortResult(port=port, state="closed")
    return PortResult(port=port, state="filtered")


def _first_line(data: bytes) -> str:
    text = data.decode(errors="ignore").strip()
    return text.splitlines()[0].strip() if text else ""


def _http_banner(sock: socket.socket, target: str) -> str:
    """Send a HEAD request and return 'status line | Server: xxx' if available."""
    request = f"HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: port-scanner\r\n\r\n"
    sock.sendall(request.encode())
    data = sock.recv(2048)
    if not data:
        return ""

    lines = data.decode(errors="ignore").splitlines()
    status = lines[0].strip() if lines else ""
    server = next(
        (l.split(":", 1)[1].strip()
         for l in lines if l.lower().startswith("server:")),
        "",
    )
    return f"{status} | Server: {server}" if server else status


def _probe(sock: socket.socket, target: str, port: int) -> str:
    """Pick a probe strategy based on the port."""
    if port in HTTP_PORTS:
        return _http_banner(sock, target)

    # Most other services (SSH, FTP, SMTP, POP3, IMAP, MySQL...) greet first
    try:
        return _first_line(sock.recv(1024))
    except socket.timeout:
        return ""


def grab_banner(target: str, port: int, timeout: float = 1.5) -> str:

    try:
        with socket.create_connection((target, port), timeout=timeout) as raw:
            if port in TLS_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE 
                with ctx.wrap_socket(raw) as tls:
                    return _probe(tls, target, port)
            return _probe(raw, target, port)
    except (OSError, ssl.SSLError):
        return ""


def tcp_connect_scan(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    max_threads: int = 100,
    grab_banners: bool = True,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> list[PortResult]:
    """
    Scan ports on target using TCP connect attempts.
    """
    results: list[PortResult] = []
    total = len(ports)
    done = 0

    # Phase 1: find open ports concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(
            _check_port, target, p, timeout): p for p in ports}

        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            done += 1
            if progress_cb:
                progress_cb(done, total)

    # Phase 2: grab banners from the open ports only
    open_results = [r for r in results if r.state == "open"]
    if grab_banners and open_results:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(open_results))) as executor:
            banner_futures = {
                executor.submit(grab_banner, target, r.port, timeout + 0.5): r for r in open_results
            }
            for future in concurrent.futures.as_completed(banner_futures):
                banner_futures[future].banner = future.result()

    results.sort(key=lambda x: x.port)
    return results
