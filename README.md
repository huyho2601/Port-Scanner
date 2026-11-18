# Port Scanner
 
A multithreaded TCP port scanner written in Python, with an optional SYN (half-open) scan mode, service identification, banner grabbing, and JSON/CSV export.
 
I built it to learn socket programming, raw packet crafting with Scapy, concurrency, and CLI design.

```bash
$ python scanner.py -p top1000 127.0.0.1
Start scanning 127.0.0.1 - 998 ports, mode = tcp
Scanning [##############################] 998/998

Scan report for 127.0.0.1
=> Open ports: 8
=> Filtered ports: 990
=> Closed ports: 0

PORT      STATE     SERVICE             DESCRIPTION / BANNER
------------------------------------------------------------
22        open      ssh                 SSH-2.0-OpenSSH_for_Windows_9.5
80        open      http                HTTP/1.1 200 OK | Server: Microsoft-IIS/10.0
135       open      msrpc               MS RPC Endpoint Mapper
445       open      microsoft-ds        SMB over TCP
903       open      unknown             220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t,
3306      open      mysql               J
3389      open      rdp                 Remote Desktop Protocol
5357      open      wsd                 
```

## Features
 
- **Two scan techniques**
  - **TCP connect scan**: completes the full three-way handshake. Needs no special privileges.
  - **SYN scan**: sends a crafted SYN packet and reads the reply without finishing the handshake. Needs Scapy and root/Administrator rights.

## Usage
 
```
port-scanner [-h] [-p PORTS] [-t {tcp,syn}] [--timeout TIMEOUT] [-a]
             [--threads THREADS] [--no-banner] [-o FILE] [--format {json,csv}]
             target
```
