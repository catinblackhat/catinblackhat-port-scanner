import socket
import ipaddress
import errno
import itertools
import threading
import time
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import perf_counter

try:
    from pyfiglet import Figlet
except ImportError:
    Figlet = None


# ==========================================
# CATINBLACKHAT CONFIGURATION
# ==========================================

TIMEOUT = 0.75
MAX_WORKERS = 50
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1000


# ==========================================
# COLORS
# ==========================================

GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ==========================================
# DISPLAY THE ASCII BANNER
# ==========================================

def show_banner():
    # Use PyFiglet when installed; fall back to readable text otherwise.
    if Figlet is not None:
        title = Figlet(font="slant", width=100).renderText("CATINBLACKHAT")
    else:
        title = "CATINBLACKHAT\n"
        print(f"{YELLOW}[!]{RESET} PyFiglet is not installed; showing a plain-text banner.")

    print()
    print(GREEN + BOLD + title + RESET)
    print(f"{GREEN}{'═' * 62}{RESET}")
    print(f"{BLUE}{BOLD}          TCP / UDP PORT SCANNER  ·  VERSION 1.0{RESET}")
    print(f"{GREEN}{'═' * 62}{RESET}")
    print(f"  {BLUE}Author{RESET} : {YELLOW}CATINBLACKHAT{RESET}")
    print(f"  {BLUE}Type{RESET}   : TCP / UDP Port Scanner")
    print(f"{GREEN}{'═' * 62}{RESET}\n")


# ==========================================
# ANIMATED SCANNING INDICATOR
# ==========================================

class Spinner:
    # Keep the animation in one managed thread so it can be stopped cleanly.
    def __init__(self):
        self._stop_event = None
        self._thread = None

    def _animate(self, stop_event):
        symbols = itertools.cycle(["|", "/", "-", "\\"])

        while not stop_event.wait(0.1):
            print(
                f"\r{GREEN}[{next(symbols)}]{RESET} {BLUE}Scanning{RESET}",
                end="",
                flush=True,
            )

    def start(self):
        # Do not start another animation if one is already running.
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._animate,
            args=(self._stop_event,),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        # Stop and wait for the animation thread before writing another line.
        if self._stop_event is not None:
            self._stop_event.set()

        if self._thread is not None:
            self._thread.join()

        print("\r" + " " * 35 + "\r", end="", flush=True)

    def write(self, message):
        # Pause the animation while printing scan results.
        self.stop()
        print(message)
        self.start()


# ==========================================
# VALIDATE AND RESOLVE THE TARGET
# ==========================================

def resolve_target(user_input):
    # Remove leading and trailing whitespace.
    user_input = user_input.strip()

    if not user_input:
        raise ValueError("Target cannot be empty.")

    try:
        # Accept an IP, domain name, or full URL.
        address = user_input if "://" in user_input else "//" + user_input
        parsed = urlsplit(address)
        host = parsed.hostname
    except ValueError as exc:
        raise ValueError("Invalid target format.") from exc

    if not host or any(char.isspace() for char in host):
        raise ValueError("Enter a valid IP address, domain, or URL.")

    # Check whether the target is already an IP address.
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        # This version supports IPv4 only.
        if parsed_ip.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")
        return host, str(parsed_ip)

    # Resolve a domain name to IPv4.
    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"Could not resolve '{host}'. Check the hostname or DNS."
        ) from exc

    # Remove duplicate IP addresses.
    addresses = list(dict.fromkeys(result[4][0] for result in results))

    if not addresses:
        raise ValueError("No IPv4 address was found.")

    # Scan only the first resolved IPv4 address in this version.
    if len(addresses) > 1:
        print(f"{YELLOW}[!]{RESET} Multiple IPv4 addresses found.")
        print(f"{GREEN}[*]{RESET} Using {BLUE}{addresses[0]}{RESET}")

    return host, addresses[0]


# ==========================================
# GET AND VALIDATE THE PORT RANGE
# ==========================================

def get_port_range():
    # Keep asking until the user provides a valid starting port.
    while True:
        start_input = input(
            f"{BLUE}Starting port [{DEFAULT_START_PORT}]: {RESET}"
        ).strip()

        try:
            start_port = int(start_input or DEFAULT_START_PORT)
        except ValueError:
            print(f"{YELLOW}[!]{RESET} Enter a whole number for the starting port.")
            continue

        if not 1 <= start_port <= 65535:
            print(f"{YELLOW}[!]{RESET} Starting port must be between 1 and 65535.")
            continue

        break

    # Keep asking until the ending port is valid and not below the start.
    while True:
        end_input = input(
            f"{BLUE}Ending port [{DEFAULT_END_PORT}]: {RESET}"
        ).strip()

        try:
            end_port = int(end_input or DEFAULT_END_PORT)
        except ValueError:
            print(f"{YELLOW}[!]{RESET} Enter a whole number for the ending port.")
            continue

        if not 1 <= end_port <= 65535:
            print(f"{YELLOW}[!]{RESET} Ending port must be between 1 and 65535.")
            continue

        if end_port < start_port:
            print(
                f"{YELLOW}[!]{RESET} Ending port cannot be less than "
                "the starting port. Please try again."
            )
            continue

        break

    return start_port, end_port


# ==========================================
# SCAN ONE TCP PORT
# ==========================================

def scan_tcp_port(target_ip, port):
    try:
        # Create and automatically close a TCP socket.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                return port, "OPEN", None

            # A connection refusal commonly indicates a closed port.
            if result in (errno.ECONNREFUSED, 10061):
                return port, "CLOSED", None

            # Other failed connections may be filtered or unreachable.
            return port, "UNKNOWN", None

    except socket.timeout:
        return port, "UNKNOWN", None
    except OSError as exc:
        return port, "ERROR", str(exc)


# ==========================================
# SCAN ONE UDP PORT
# ==========================================

def scan_udp_port(target_ip, port):
    try:
        # Create a UDP socket. UDP has no TCP-style handshake.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((target_ip, port))
            sock.send(b"")

            try:
                # A reply means a service responded to this probe.
                sock.recv(1024)
                return port, "OPEN", None
            except socket.timeout:
                # A missing reply cannot confirm that the port is open or closed.
                return port, "OPEN_OR_FILTERED", None

    except ConnectionRefusedError:
        return port, "CLOSED", None
    except OSError as exc:
        # Some systems report an ICMP port-unreachable response this way.
        if (
            getattr(exc, "winerror", None) == 10054
            or exc.errno == errno.ECONNREFUSED
        ):
            return port, "CLOSED", None
        return port, "ERROR", str(exc)


# ==========================================
# RUN THE SELECTED SCAN
# ==========================================

def run_scan(target_ip, start_port, end_port, protocol):
    # Choose the scanner for the selected protocol.
    scan_function = scan_tcp_port if protocol == "TCP" else scan_udp_port
    total_ports = end_port - start_port + 1

    open_ports = []
    closed_count = 0
    unknown_count = 0
    error_count = 0
    interrupted = False

    start_time = perf_counter()

    print(
        f"\n{GREEN}[*]{RESET} Starting {BLUE}{BOLD}{protocol}{RESET} scan "
        f"on ports {BLUE}{start_port}-{end_port}{RESET}"
    )
    print(f"{GREEN}[*]{RESET} Starting scan\n")

    spinner = Spinner()
    spinner.start()
    futures = []

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            try:
                # Submit tasks individually so already-submitted work can be cancelled.
                for port in range(start_port, end_port + 1):
                    futures.append(
                        executor.submit(scan_function, target_ip, port)
                    )

                # Process results as they finish.
                for future in as_completed(futures):
                    port, status, error = future.result()

                    if status == "OPEN":
                        open_ports.append(port)
                        spinner.write(
                            f"{GREEN}[+]{RESET} {BLUE}{port}/{protocol}{RESET}  "
                            f"{GREEN}OPEN{RESET}"
                        )
                    elif status == "CLOSED":
                        closed_count += 1
                    elif status in ("UNKNOWN", "OPEN_OR_FILTERED"):
                        unknown_count += 1
                    elif status == "ERROR":
                        error_count += 1
                        spinner.write(
                            f"{YELLOW}[!]{RESET} Port {BLUE}{port}{RESET}: {error}"
                        )

            except KeyboardInterrupt:
                interrupted = True
                # Stop the animation and cancel tasks that have not started.
                spinner.stop()
                for future in futures:
                    future.cancel()
                print(f"\n{YELLOW}[!]{RESET} Scan interrupted by user.")

    finally:
        spinner.stop()

    if interrupted:
        return False

    # Sort open ports for a readable summary.
    open_ports.sort()
    elapsed = perf_counter() - start_time

    print(f"\n{GREEN}{'═' * 50}{RESET}")
    print(f"{BLUE}{BOLD}               {protocol} SCAN SUMMARY{RESET}")
    print(f"{GREEN}{'═' * 50}{RESET}")
    print(f"  {BLUE}Ports checked{RESET} : {total_ports}")
    print(f"  {BLUE}Open ports{RESET}    : {GREEN}{len(open_ports)}{RESET}")
    print(f"  {BLUE}Closed ports{RESET}  : {closed_count}")
    print(f"  {BLUE}Unknown{RESET}       : {unknown_count}")
    print(f"  {BLUE}Errors{RESET}        : {error_count}")
    print(f"  {BLUE}Elapsed time{RESET}  : {elapsed:.2f} seconds")

    if open_ports:
        print(f"\n{GREEN}Open ports:{RESET}")
        for port in open_ports:
            print(f"  → {BLUE}{port}/{protocol}{RESET}")

    if protocol == "UDP" and unknown_count:
        print(
            f"\n{YELLOW}[!]{RESET} UDP results can be ambiguous: "
            "no response may mean open or filtered."
        )

    print(f"{GREEN}{'═' * 50}{RESET}")
    return True


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():
    show_banner()

    # Keep asking until the target is valid and resolves successfully.
    while True:
        target_input = input(
            f"{BLUE}Enter an IP, domain, or website URL: {RESET}"
        )

        try:
            target_name, target_ip = resolve_target(target_input)
            break
        except ValueError as exc:
            print(f"\n{YELLOW}[!]{RESET} {exc}")
            print(f"{BLUE}Please enter a valid target and try again.\n{RESET}")

    # The port-range function also retries invalid input until it is valid.
    start_port, end_port = get_port_range()

    protocol_options = {
        "1": ["TCP"],
        "2": ["UDP"],
        "3": ["TCP", "UDP"],
    }

    # Keep asking until the user chooses a valid scan type.
    while True:
        print(f"\n{BLUE}Select scan type:{RESET}")
        print(f"  {BLUE}1.{RESET} TCP")
        print(f"  {BLUE}2.{RESET} UDP")
        print(f"  {BLUE}3.{RESET} Both")

        choice = input(f"{BLUE}Choice [1]: {RESET}").strip() or "1"

        if choice in protocol_options:
            break

        print(f"{YELLOW}[!]{RESET} Invalid choice. Enter 1, 2, or 3.\n")

    total_ports = end_port - start_port + 1

    print(f"\n{GREEN}{'═' * 50}{RESET}")
    print(f"  {BLUE}Target{RESET}          : {target_name}")
    print(f"  {BLUE}IPv4{RESET}            : {target_ip}")
    print(f"  {BLUE}Port range{RESET}      : {start_port}-{end_port}")
    print(f"  {BLUE}Ports per protocol{RESET}: {total_ports}")
    print(f"{GREEN}{'═' * 50}{RESET}")

    for protocol in protocol_options[choice]:
        if not run_scan(target_ip, start_port, end_port, protocol):
            print(f"{YELLOW}[*]{RESET} Scanner stopped.")
            return

    print(f"\n{GREEN}[*]{RESET} {YELLOW}CATINBLACKHAT{RESET} | Scan complete\n")


# ==========================================
# PROGRAM ENTRY POINT
# ==========================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*]{RESET} Program cancelled by user.")
