import struct
import unittest
from tools.signing.content import unchanged_pe

def unsigned():
    data = bytearray(607)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<H", data, 148, 240)
    struct.pack_into("<H", data, 152, 0x20b)
    struct.pack_into("<I", data, 260, 16)
    data[-7:] = b"overlay"
    return bytes(data)

class SignedPE(unittest.TestCase):
    def test_only_certificate_table_and_alignment_may_change(self):
        old = unsigned()
        new = bytearray(old + b"\0" + struct.pack("<IHH", 16, 512, 2) + bytes(8))
        struct.pack_into("<II", new, 296, 608, 16)
        self.assertTrue(unchanged_pe(old, new))
        new[606] ^= 1
        self.assertFalse(unchanged_pe(old, new))
        self.assertFalse(unchanged_pe(old, new + b"extra"))

class PackagePolicy(unittest.TestCase):
    def test_unexpected_msi_resource_and_changed_helper_rejected(self):
        from tools.signing.check_package import match_streams
        expected = {"Binary": {"Helper": "a"}, "Icon": {"App": "b"}}
        match_streams(expected, expected)
        for actual in ({"Binary":{"Helper":"wrong"},"Icon":{"App":"b"}},
                       {"Binary":{"Helper":"a","Other":"c"},"Icon":{"App":"b"}}):
            with self.assertRaises(ValueError):
                match_streams(expected, actual)
