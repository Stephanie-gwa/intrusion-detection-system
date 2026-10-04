"""Optional live packet capture — OFF by default, and only ever usable
against an interface the caller explicitly names and confirms they are
authorized to monitor.

This module intentionally does the least amount of work possible to
turn live packets into the same ConnectionEvent shape the rest of the
pipeline already knows how to score — it is not a packet-analysis
engine. It requires the third-party `scapy` package (not installed by
default; see requirements-live.txt) and, on most platforms, root/admin
privileges to open a raw socket.

Safety properties:
    - `capture_live` NEVER runs unless the caller passes `confirm=True`
      explicitly. The CLI only sets this after the operator both names
      an interface AND responds to an interactive confirmation prompt
      (or passes --yes-i-own-this-network on a non-interactive run).
    - It only ever listens; it never sends a single packet.
    - It only sniffs the one named interface — never "all interfaces".
    - A capture duration or packet-count limit is required, so a live
      run can't be left sniffing indefinitely by accident.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from .events import ConnectionEvent


class LiveCaptureUnavailable(Exception):
    """Raised when live capture can't run (missing dependency, no
    privileges, bad interface, or missing confirmation)."""


class ConfirmationRequiredError(LiveCaptureUnavailable):
    """Raised when capture_live is called without explicit confirmation."""


@dataclass
class LiveCaptureConfig:
    interface: str
    duration_seconds: Optional[int] = 30
    packet_count: Optional[int] = None  # alternative stop condition

    def __post_init__(self):
        if not self.duration_seconds and not self.packet_count:
            raise ValueError(
                "live capture requires a duration_seconds or packet_count limit"
            )


def _import_scapy():
    try:
        from scapy.all import IP, TCP, UDP, sniff  # noqa: F401
    except ImportError as exc:
        raise LiveCaptureUnavailable(
            "Live capture requires the optional 'scapy' package, which is not "
            "installed. Install it with: pip install -r requirements-live.txt "
            "(and run with sufficient privileges to open a raw socket, e.g. "
            "via sudo on Linux/macOS)."
        ) from exc
    return IP, TCP, UDP, sniff


def capture_live(config: LiveCaptureConfig, confirm: bool = False) -> List[ConnectionEvent]:
    """Sniff `config.interface` for connection-attempt-shaped packets and
    return them as ConnectionEvents, ready to feed into the same
    detectors used for sample/offline data.

    Requires confirm=True — the CLI is the only caller allowed to set
    this, and only after the operator has explicitly named the
    interface and confirmed authorization to monitor it.
    """
    if not confirm:
        raise ConfirmationRequiredError(
            "Live capture was not confirmed. Re-run with the CLI's "
            "--iface and --yes-i-own-this-network flags (or answer 'y' to "
            "the interactive prompt) only on a network interface you are "
            "authorized to monitor."
        )

    IP, TCP, UDP, sniff = _import_scapy()

    events: List[ConnectionEvent] = []

    def _on_packet(pkt):
        if IP not in pkt:
            return
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if TCP in pkt:
            proto = "tcp"
            dst_port = int(pkt[TCP].dport)
            flag = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "udp"
            dst_port = int(pkt[UDP].dport)
            flag = ""
        else:
            return

        events.append(ConnectionEvent(
            timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto,
            bytes_sent=len(pkt),
            flag=flag,
        ))

    sniff_kwargs = {"iface": config.interface, "prn": _on_packet, "store": False}
    if config.duration_seconds:
        sniff_kwargs["timeout"] = config.duration_seconds
    if config.packet_count:
        sniff_kwargs["count"] = config.packet_count

    try:
        sniff(**sniff_kwargs)
    except PermissionError as exc:
        raise LiveCaptureUnavailable(
            f"Permission denied opening interface '{config.interface}'. Live "
            f"capture typically requires root/administrator privileges."
        ) from exc
    except OSError as exc:
        raise LiveCaptureUnavailable(
            f"Could not open interface '{config.interface}': {exc}"
        ) from exc

    return events
