import csv
import io
import json
import sys
from dataclasses import asdict

from port_scanner.core.tcp_scan import PortResult
from port_scanner.core.ports_data import lookup_service
from . import colors as clr 

PORT_JUST = 10
STATE_JUST = 10
SERVICE_JUST = 20
DESCRIPTION_JUST = 20

def _coloring(text: str, color: str) -> str:
  if not clr.enabled():
    return text
  return f"{color}{text}{clr.RESET}"


def enrich_service_info(results: list[PortResult]):
  for r in results:
    service, description = lookup_service(r.port)
    r.service = service
    r.description = description

def print_progress(done: int, total: int):
  bar_length = 30
  filled = int(bar_length * done / total) if total else bar_length
  bar = "#" * filled + "-" * (bar_length - filled)
  sys.stderr.write(f"\rScanning [{bar}] {done}/{total}")
  sys.stderr.flush()
  if done == total:
    sys.stderr.write("\n")

def print_result(target: str, results: list[PortResult], show_all: bool = False):
  open_ports = [r for r in results if r.state == "open"]
  filtered_ports = [r for r in results if r.state == "filtered"]
  closed_ports = [r for r in results if r.state == "closed"]

  print()
  print(_coloring(f"Scan report for {target}", clr.BOLD))
  print(f"=> Open ports: {len(open_ports)}")
  print(f"=> Filtered ports: {len(filtered_ports)}")
  print(f"=> Closed ports: {len(closed_ports)}")

  if open_ports:
    header = f"{'PORT':<{PORT_JUST}}{'STATE':<{STATE_JUST}}{'SERVICE':<{SERVICE_JUST}}{'DESCRIPTION'}"
    print(_coloring(header, clr.CYAN))
    print(_coloring("-" * len(header), clr.CYAN))

    for r in open_ports:
      info = r.banner if r.banner else r.service
      state_padding = f"{r.state:<{STATE_JUST}}"
      print(f"{r.port:<{PORT_JUST}}{_coloring(state_padding, clr.GREEN)}{r.service:<{SERVICE_JUST}}{info}")
    print()

  if show_all:
    join_ports = ", ".join(str(p.port) for p in filtered_ports)
    print(_coloring(f"{len(filtered_ports)} filtered port(s):", clr.YELLOW),
          join_ports)

    join_ports = ", ".join(str(p.port) for p in closed_ports)
    print(_coloring(f"{len(closed_ports)} closed port(s):", clr.RED),
          join_ports)
    