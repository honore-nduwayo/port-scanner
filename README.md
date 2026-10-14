# port-scanner

A small TCP connect port scanner in pure Python (standard library only).

> **Legal / ethical notice:** only scan machines you own or have written
> permission to test. Scanning other people's systems may be illegal.
> Safe targets: `127.0.0.1`, your own devices/VMs, and `scanme.nmap.org`
> (light use only, per the Nmap project's rules).

## What it does
Tries a TCP connection to each port on a target and reports each as
**open** (connection succeeded), **closed** (actively refused) or
**filtered** (no reply before the timeout). Uses a thread pool so
scanning 1000 ports takes seconds, not minutes.

## Why
Built to learn how sockets, timeouts and concurrency work, and to
understand what tools like nmap do at the simplest level.

## Usage
```
python3 scanner.py 127.0.0.1                    # ports 1-1024
python3 scanner.py localhost -p 22,80,443 -b    # specific ports + banners
python3 scanner.py 192.168.1.10 -p 1-65535 -w 300 -o results.json
python3 scanner.py scanme.nmap.org --authorized # non-local needs the flag
```
Options: `-p` ports, `-t` timeout (s), `-w` threads (max 500), `-b` banners,
`-o` JSON output, `--show-closed`, `--authorized`.

## Example output
```
PORT    STATE     SERVICE       BANNER
8765    open      unknown
Done in 1.00s: 1 open, 10 closed, 0 filtered
```

## Limitations
Connect scans only (no SYN/stealth, UDP, OS detection or CIDR ranges).
Connect scans are visible in target logs. Banner grabbing only works on
services that speak first (SSH, FTP, SMTP); HTTP stays silent.

## Timing (fill in from your own runs)
| Threads | 1-1024 on localhost | 1-1024 on a remote host |
|---|---|---|
| 1 | | |
| 10 | | |
| 100 | | |
