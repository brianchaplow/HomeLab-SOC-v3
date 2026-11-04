"""IP allow-list matching shared by enrichment.py and autoblock.py."""
import ipaddress
import logging
from typing import Iterable, List, Union

logger = logging.getLogger(__name__)

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_networks(entries: Iterable[str]) -> List[Network]:
    """Parse whitelist entries (single IPs or CIDRs, IPv4 or IPv6).

    Entries that aren't valid addresses (e.g. the YOUR_HOME_IP_RANGE
    placeholders in the sample config) are skipped with a warning instead of
    crashing the run.
    """
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            logger.warning(f"Ignoring invalid whitelist entry: {entry!r}")
    return networks


def ip_in_networks(ip: str, networks: Iterable[Network]) -> bool:
    """True if ``ip`` falls inside any of ``networks``; False for non-IPs."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in net for net in networks if net.version == addr.version)
