import csv
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone

from port_scanner.core.tcp_scan import PortResult
from port_scanner.core.ports_data import lookup_service
from . import colors as clr

PORT_JUST = 10
STATE_JUST = 10
SERVICE_JUST = 20


def _coloring(text: str, color: str) -> str:
  if not clr.enabled():
    return text
  return f"{color}{text}{clr.RESET}"


def enrich_service_info(results: list[PortResult]) -> None:
  for r in results:
    r.service, r.description = lookup_service(r.port)


def print_progress(done: int, total: int) -> None:
  bar_length = 30
  filled = int(bar_length * done / total) if total else bar_length
  bar = "#" * filled + "-" * (bar_length - filled)
  sys.stderr.write(f"\rScanning [{bar}] {done}/{total}")
  sys.stderr.flush()
  if done == total:
    sys.stderr.write("\n")


def print_result(target: str, results: list[PortResult], show_all: bool = False) -> None:
  open_ports = [r for r in results if r.state == "open"]
  filtered_ports = [r for r in results if r.state == "filtered"]
  closed_ports = [r for r in results if r.state == "closed"]

  print()
  print(_coloring(f"Scan report for {target}", clr.BOLD))
  print(f"=> Open ports: {len(open_ports)}")
  print(f"=> Filtered ports: {len(filtered_ports)}")
  print(f"=> Closed ports: {len(closed_ports)}")

  if open_ports:
    header = f"{'PORT':<{PORT_JUST}}{'STATE':<{STATE_JUST}}{'SERVICE':<{SERVICE_JUST}}DESCRIPTION / BANNER"
    print()
    print(_coloring(header, clr.CYAN))
    print(_coloring("-" * len(header), clr.CYAN))

    for r in open_ports:
      # Prefer the live banner; fall back to the static description
      info = r.banner or r.description
      state_padding = f"{r.state:<{STATE_JUST}}"
      print(f"{r.port:<{PORT_JUST}}{_coloring(state_padding, clr.GREEN)}{r.service:<{SERVICE_JUST}}{info}")
    print()

  if show_all:
    print(_coloring(f"{len(filtered_ports)} filtered port(s):", clr.YELLOW),
          ", ".join(str(p.port) for p in filtered_ports))
    print(_coloring(f"{len(closed_ports)} closed port(s):", clr.RED),
          ", ".join(str(p.port) for p in closed_ports))


def export_results(
    path: str,
    fmt: str,
    target: str,
    ip: str,
    scan_type: str,
    results: list[PortResult],
    show_all: bool = False,
) -> None:
  """
  Write results to a JSON or CSV file.
  """
  rows = results if show_all else [r for r in results if r.state == "open"]

  if fmt == "json":
    payload = {
      "target": target,
      "ip": ip,
      "scan_type": scan_type,
      "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
      "summary": {
        state: sum(1 for r in results if r.state == state)
        for state in ("open", "filtered", "closed")
      },
      "results": [asdict(r) for r in rows],
    }
    with open(path, "w", encoding="utf-8") as f:
      json.dump(payload, f, indent=2)

  elif fmt == "csv":
    fields = ["port", "state", "service", "description", "banner"]
    with open(path, "w", newline="", encoding="utf-8") as f:
      writer = csv.DictWriter(f, fieldnames=fields)
      writer.writeheader()
      for r in rows:
        writer.writerow({k: getattr(r, k) for k in fields})

  else:
    raise ValueError(f"Unsupported output format: {fmt}")