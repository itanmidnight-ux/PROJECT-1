"""
CyberScope — core/net_vendor.py

Layer-2 identification for MAC addresses, built from two independent
signals — both honest about their limits, matching the platform's rule
of never inventing data:

  1. classify_mac() — always available, correct by construction. It's
     derived directly from the IEEE 802 MAC bit layout (the U/L and
     I/G bits of the first octet), not a lookup table:
       - U/L bit set  -> "locally administered" -- the address was
         assigned by software, not burned into hardware by a vendor.
         This is exactly what modern OS MAC-randomization (iOS,
         Android, Windows "random hardware addresses") produces, and
         what most virtual NICs use, so it's a genuinely useful,
         always-accurate security signal on its own.
       - I/G bit set  -> multicast/broadcast address.

  2. lookup_vendor() — a deliberately small table of OUI prefixes this
     codebase can vouch for. It is NOT the IEEE OUI registry (which
     has 50,000+ entries this project has no reliable offline copy
     of) — it currently covers well-known virtualization platforms
     whose default MAC prefixes are part of each project's own public
     documentation. An unmatched MAC returns None, never a guessed
     vendor name. Extend _OUI_TABLE only with similarly verifiable
     entries — a wrong vendor attribution in a security tool is worse
     than no attribution at all.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_MAC_RE = re.compile(r'^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$')


def _normalize(mac: str) -> Optional[str]:
    """Return MAC as 12 uppercase hex chars, no separators, or None if
    the input doesn't look like a MAC address at all."""
    if not mac or not _MAC_RE.match(mac.strip()):
        return None
    return re.sub(r'[:-]', '', mac.strip()).upper()


# Deliberately small, high-confidence seed table. Every entry here is a
# virtualization platform's own well-known, publicly documented default
# MAC prefix -- not a guess. Extend only with similarly verifiable data.
_OUI_TABLE = {
    "000C29": "VMware (virtual NIC)",
    "005056": "VMware (virtual NIC)",
    "080027": "Oracle VirtualBox (virtual NIC)",
    "525400": "QEMU/KVM (virtual NIC)",
    "00163E": "Xen (virtual NIC)",
}


def lookup_vendor(mac: str) -> Optional[str]:
    """Look up a MAC's OUI in the local seed table. Returns None --
    never a guess -- for anything not in the table."""
    norm = _normalize(mac)
    if norm is None:
        return None
    return _OUI_TABLE.get(norm[0:6])


@dataclass
class MacClassification:
    is_valid:                bool
    oui:                      str              # first 6 hex chars, "" if invalid
    is_locally_administered:  bool = False      # U/L bit -- software-assigned/randomized
    is_multicast:             bool = False      # I/G bit
    vendor:                   Optional[str] = None

    @property
    def label(self) -> str:
        """One-line, human-facing summary for list/detail views."""
        if not self.is_valid:
            return "unknown"
        if self.vendor:
            return self.vendor
        if self.is_locally_administered:
            return "Locally administered (randomized/virtual)"
        return "Unknown vendor"


def classify_mac(mac: str) -> MacClassification:
    """Classify a MAC address using the IEEE 802 bit layout -- correct
    by definition, no lookup table involved for the bit-derived fields.
    A vendor name is only ever attached from the small verified table
    above, and only for globally-assigned (non-locally-administered)
    addresses, since a locally administered OUI byte doesn't identify
    real hardware."""
    norm = _normalize(mac)
    if norm is None:
        return MacClassification(is_valid=False, oui="")

    first_octet = int(norm[0:2], 16)
    is_local = bool(first_octet & 0b0000_0010)
    is_mcast = bool(first_octet & 0b0000_0001)
    oui = norm[0:6]
    vendor = None if is_local else lookup_vendor(norm)

    return MacClassification(
        is_valid=True, oui=oui,
        is_locally_administered=is_local, is_multicast=is_mcast,
        vendor=vendor,
    )
