"""
CyberScope — tests/test_net_vendor.py

Tests for core/net_vendor.py: the IEEE-802-bit-derived MAC
classification (always correct by construction) and the small,
high-confidence OUI vendor seed table (never a guess).
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.net_vendor import MacClassification, classify_mac, lookup_vendor


class TestLookupVendor:
    def test_known_vmware_oui(self):
        assert lookup_vendor("00:0C:29:AB:CD:EF") == "VMware (virtual NIC)"

    def test_known_virtualbox_oui(self):
        assert lookup_vendor("08:00:27:11:22:33") == "Oracle VirtualBox (virtual NIC)"

    def test_known_qemu_oui(self):
        assert lookup_vendor("52:54:00:12:34:56") == "QEMU/KVM (virtual NIC)"

    def test_unknown_oui_returns_none(self):
        assert lookup_vendor("AA:BB:CC:DD:EE:FF") is None

    def test_dash_separated_mac(self):
        assert lookup_vendor("00-0C-29-AB-CD-EF") == "VMware (virtual NIC)"

    def test_no_separator_mac(self):
        assert lookup_vendor("000C29ABCDEF") == "VMware (virtual NIC)"

    def test_case_insensitive(self):
        assert lookup_vendor("00:0c:29:ab:cd:ef") == "VMware (virtual NIC)"

    def test_invalid_mac_returns_none(self):
        assert lookup_vendor("not-a-mac") is None
        assert lookup_vendor("") is None
        assert lookup_vendor("00:0C:29") is None  # too short


class TestClassifyMac:
    def test_globally_assigned_known_vendor(self):
        c = classify_mac("00:0C:29:AB:CD:EF")
        assert c.is_valid is True
        assert c.is_locally_administered is False
        assert c.is_multicast is False
        assert c.vendor == "VMware (virtual NIC)"
        assert c.oui == "000C29"

    def test_locally_administered_bit(self):
        # 0x02 = 0b00000010 -- U/L bit set, classic "locally administered" example
        c = classify_mac("02:00:00:00:00:01")
        assert c.is_valid is True
        assert c.is_locally_administered is True
        # locally-administered addresses never get a vendor attribution,
        # even if their OUI byte happens to collide with a known one
        assert c.vendor is None

    def test_multicast_bit(self):
        # 0x01 = 0b00000001 -- I/G bit set
        c = classify_mac("01:00:5E:00:00:01")
        assert c.is_valid is True
        assert c.is_multicast is True

    def test_globally_assigned_unknown_vendor(self):
        # 0x00's U/L bit (0x02) is clear -> globally assigned, and this
        # OUI isn't in the seed table -> unknown vendor.
        c = classify_mac("00:11:22:33:44:55")
        assert c.is_valid is True
        assert c.is_locally_administered is False
        assert c.vendor is None

    def test_invalid_mac(self):
        c = classify_mac("garbage")
        assert c.is_valid is False
        assert c.oui == ""
        assert c.vendor is None

    def test_label_known_vendor(self):
        c = classify_mac("00:0C:29:AB:CD:EF")
        assert c.label == "VMware (virtual NIC)"

    def test_label_locally_administered(self):
        c = classify_mac("02:00:00:00:00:01")
        assert "administered" in c.label.lower()

    def test_label_unknown(self):
        c = classify_mac("00:11:22:33:44:55")
        assert c.label == "Unknown vendor"

    def test_label_invalid(self):
        c = classify_mac("garbage")
        assert c.label == "unknown"

    def test_every_octet_bit_combination_never_raises(self):
        # Sweep the first octet's low nibble to make sure the U/L/I/G bit
        # math never throws regardless of which bits are set.
        for first_byte in range(0, 256, 17):
            mac = f"{first_byte:02X}:11:22:33:44:55"
            c = classify_mac(mac)
            assert isinstance(c, MacClassification)
            assert c.is_valid is True
