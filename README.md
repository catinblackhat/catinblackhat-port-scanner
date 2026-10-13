# CATINBLACKHAT TCP / UDP Port Scanner

A beginner friendly Python networking project that checks TCP or UDP ports on a target you own or are explicitly authorized to test. It includes a CATINBLACKHAT ASCII banner, target validation, DNS resolution, configurable port ranges, concurrent port checks, a scanning indicator, and a summary report.

> **Authorization:** Only scan your own devices, isolated lab machines, or systems for which you have explicit permission. Follow the target's rules and rate limits.

## Features

- Accepts an IPv4 address, domain name, or website URL.
- Resolves hostnames to IPv4 and scans the first address returned.
- Allows a custom start and end port (defaults to ports `1–1000`).
- Supports TCP, UDP, or both protocols.
- Uses a bounded thread pool to scan ports concurrently.
- Displays discovered TCP/UDP responses and a summary.
- Re-prompts when the target, port range, or scan-type input is invalid.
- Uses PyFiglet for the banner when installed; falls back to plain text if it is unavailable.

## Requirements

- Python 3.9 or newer recommended.
- PyFiglet for the styled ASCII banner. Other imports are from Python's standard library.

## Installation

Clone or download this project, then open a terminal in the project directory.

```bash
python -m pip install -r requirements.txt
```

On systems where Python 3 is invoked as `python3`, use:

```bash
python3 -m pip install -r requirements.txt
```

## Run

```bash
python scanner.py
```

Or, on Linux/macOS where appropriate:

```bash
python3 scanner.py
```

The program asks for a target, a port range, and a scan type:

1. TCP
2. UDP
3. Both

Press Enter at the port prompts to use the defaults: start port `1` and end port `1000`.

For a first local test, enter `127.0.0.1`. You can also scan the IP of your own lab VM, provided you are authorized to test it.

## Example session

```text
Enter an IP, domain, or website URL: 127.0.0.1
Starting port [1]: 1
Ending port [1000]: 100

Select scan type:
  1. TCP
  2. UDP
  3. Both
Choice [1]: 1
```

Actual open ports and scan times depend on the machine and network. Do not expect the example inputs to produce specific results.

## Result interpretation and limitations

- **TCP `OPEN`:** a TCP connection was established.
- **TCP `CLOSED`:** the connection was refused.
- **TCP `UNKNOWN`:** the attempt did not establish a connection, but the available result does not confirm that the port is closed. Filtering, timeouts, or network conditions may be involved.
- **UDP `OPEN`:** the probe received a response.
- **UDP `OPEN_OR_FILTERED`:** no response was received. Many UDP services ignore empty datagrams, so this result does not prove the port is open.
- **`ERROR`:** the socket operation returned an OS error.

This is an educational TCP-connect/UDP-probe scanner, not a replacement for Nmap. It does not provide service-version detection, OS fingerprinting, SYN scanning, or protocol-specific UDP probes. For a domain that resolves to multiple IPv4 addresses, this version scans only the first address returned. The path in a URL is ignored; scanning targets the URL's hostname and selected ports.

## Configuration

The following constants can be changed near the top of `scanner.py`:

- `TIMEOUT`: socket timeout in seconds.
- `MAX_WORKERS`: maximum concurrent scan tasks.
- `DEFAULT_START_PORT`: default first port.
- `DEFAULT_END_PORT`: default last port.

Increasing concurrency or scanning large port ranges can generate substantial traffic. Keep scans limited to authorized targets.

## Project files

- `scanner.py` — scanner implementation.
- `requirements.txt` — third-party Python dependencies.
- `.gitignore` — files and directories Git should ignore.