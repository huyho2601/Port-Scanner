from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import time

from port_scanner.core.ports_data import COMMON_PORTS, TOP_1000_PORTS
from port_scanner.core.tcp_scan import tcp_connect_scan
from port_scanner.core.syn_scan import ScapyNotAvailableError, InsufficientPrivilegesError, syn_scan
from port_scanner.customization.output_customize import (
  print_result,
  print_progress,
  enrich_service_info,
  export_results,
)



def positive_int(value: str) -> int:
  try:
    n = int(value)
  except ValueError:
    raise argparse.ArgumentTypeError(f"'{value}' is not an integer")
  if n < 1:
    raise argparse.ArgumentTypeError("must be >= 1")
  return n


def positive_float(value: str) -> float:
  try:
    x = float(value)
  except ValueError:
    raise argparse.ArgumentTypeError(f"'{value}' is not a number")
  if x <= 0:
    raise argparse.ArgumentTypeError("must be > 0")
  return x


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="port-scanner",
    description="A simple TCP/SYN port scanner with service identification",
    epilog="If you have any questions or suggestions, feel free to let me know!",
  )

  parser.add_argument(
    "target",
    help="Target IP address or hostname",
  )

  parser.add_argument(
    "-p", "--ports",
    default="common",
    help=(
      "Ports to scan: a comma-separated list (22,80,443), a range (1-1024), "
      "a mix of both (22,80-443), 'common' for ~100 well-known ports, "
      "or 'top1000' for the 1000 most common ports. Default: common"
    ),
  )

  parser.add_argument(
    "-t", "--type",
    choices=["tcp", "syn"],
    default="tcp",
    help=(
      "Scan technique. 'tcp' = full connect scan (no privileges needed). "
      "'syn' = half-open scan via scapy (needs root). Default: tcp"
    ),
  )

  parser.add_argument(
    "--timeout",
    type=positive_float,
    default=1.0,
    help="Per-port timeout in seconds. Default: 1.0",
  )

  parser.add_argument(
    "-a", "--all",
    action="store_true",
    help="Also list closed and filtered ports (and include them in -o output). Default: only open ports",
  )

  parser.add_argument(
    "--threads",
    type=positive_int,
    default=200,
    help="Max concurrent probes. Default: 200 (SYN scan is capped at 50)",
  )

  parser.add_argument(
    "--no-banner",
    action="store_true",
    help="Skip banner grabbing on open ports (TCP scan only). Faster and quieter.",
  )

  parser.add_argument(
    "-o", "--output",
    metavar="FILE",
    help="Save results to FILE. Format is taken from the extension (.json/.csv) unless --format is given.",
  )

  parser.add_argument(
    "--format",
    choices=["json", "csv"],
    help="Output file format (overrides the -o file extension).",
  )

  return parser


#  port parsing 

def parse_ports(ports_str: str | None) -> list[int]:
  """Turn the -p string into a sorted list of unique port numbers."""
  if ports_str is None or ports_str.strip().lower() == "common":
    return sorted(COMMON_PORTS.keys())

  if ports_str.strip().lower() in ("top1000", "top"):
    return sorted(set(TOP_1000_PORTS))

  # Invalid input: letters or symbols
  if not re.fullmatch(r"[\d,\-\s]+", ports_str):
    raise ValueError("Invalid ports input. Ports must be numbers, ranges, 'common' or 'top1000'.")

  ports: set[int] = set()
  for part in ports_str.split(","):
    part = part.strip()
    if not part:
      continue
    if "-" in part:
      ports.update(range_helper(part))
    else:
      if not part.isdigit():
        raise ValueError(f"Invalid port: {part}. The port must be a number.")
      port_int = int(part)
      if not (1 <= port_int <= 65535):
        raise ValueError(f"Invalid port: {part}. Ports must be in the range 1-65535.")
      ports.add(port_int)

  return sorted(ports)


def range_helper(part: str) -> range:
  bounds = part.split("-")
  if len(bounds) != 2 or not all(b.strip().isdigit() for b in bounds):
    raise ValueError(f"Invalid port range: {part}.")
  start_port, end_port = (int(b.strip()) for b in bounds)
  if start_port > end_port:
    raise ValueError(f"Invalid port range: {part}. Start port must be <= end port.")
  if start_port < 1 or end_port > 65535:
    raise ValueError(f"Invalid port range: {part}. Ports must be in the range 1-65535.")
  return range(start_port, end_port + 1)


def resolve_target(target: str) -> str:
  """Resolve a hostname to an IPv4 address. Raises ValueError if it fails."""
  try:
    return socket.gethostbyname(target)
  except socket.gaierror:
    raise ValueError(f"Could not resolve the host '{target}'")


def resolve_output_format(path: str, fmt: str | None) -> str:
  if fmt:
    return fmt
  ext = os.path.splitext(path)[1].lower().lstrip(".")
  if ext in ("json", "csv"):
    return ext
  raise ValueError(f"Cannot infer format from '{path}'. Use a .json/.csv extension or --format.")


# main

def main(argv: list[str] | None = None) -> int:
  parser = build_parser()
  args = parser.parse_args(argv)

  try:
    ports = parse_ports(args.ports)
  except ValueError as e:
    print(f"Error parsing ports: {e}", file=sys.stderr)
    return 1

  if not ports:
    parser.error("No valid ports to scan")

  out_fmt = None
  if args.output:
    try:
      out_fmt = resolve_output_format(args.output, args.format)
    except ValueError as e:
      print(f"Error: {e}", file=sys.stderr)
      return 1

  try:
    ip = resolve_target(args.target)
  except ValueError as e:
    print(f"Error: {e}", file=sys.stderr)
    return 1

  display_target = args.target if args.target == ip else f"{args.target} ({ip})"

  print(f"Start scanning {display_target} - {len(ports)} ports, mode = {args.type}")
  start = time.time()

  try:
    if args.type == "tcp":
      results = tcp_connect_scan(
        ip,
        ports,
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banners=not args.no_banner,
        progress_cb=print_progress,
      )
    else:
      results = syn_scan(
        target=ip,
        ports=ports,
        timeout=args.timeout,
        max_workers=min(args.threads, 50),
        progress_cb=print_progress,
      )
  except (ScapyNotAvailableError, InsufficientPrivilegesError) as e:
    print(f"Error: {e}", file=sys.stderr)
    return 1
  except KeyboardInterrupt:
    print("\nScan interrupted by user.", file=sys.stderr)
    return 130

  enrich_service_info(results)
  elapsed = time.time() - start

  print_result(display_target, results, args.all)
  print(f"\nScan completed in {elapsed:.2f}s")

  if args.output:
    try:
      export_results(args.output, out_fmt, args.target, ip, args.type, results, args.all)
      print(f"Results saved to {args.output} ({out_fmt})")
    except OSError as e:
      print(f"Error writing output file: {e}", file=sys.stderr)
      return 1

  return 0


if __name__ == "__main__":
  sys.exit(main())