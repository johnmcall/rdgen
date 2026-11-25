"""Compare signing inputs without trusting an uploaded manifest or running binaries."""
import struct
from pathlib import Path


def unchanged_pe(original, signed):
    def header(data):
        if data[:2] != b"MZ":
            raise ValueError("Invalid DOS header")
        start, = struct.unpack_from("<I", data, 60)
        if data[start:start+4] != b"PE\0\0":
            raise ValueError("Invalid PE header")
        optional = start + 24
        magic, = struct.unpack_from("<H", data, optional)
        directory = optional + {0x10b:96, 0x20b:112}[magic]
        size, = struct.unpack_from("<H", data, start+20)
        if optional + size > len(data) or directory + 40 > optional + size:
            raise ValueError("Invalid data directories")
        if struct.unpack_from("<I", data, directory-4)[0] < 5:
            raise ValueError("Missing certificate directory")
        return optional+64, directory+32

    checksum, directory = header(original)
    if header(signed) != (checksum, directory) or any(original[directory:directory+8]):
        return False
    offset, length = struct.unpack_from("<II", signed, directory)
    end = (len(original)+7) & ~7
    if offset != end or length < 8 or offset+length != len(signed):
        return False
    record, revision, kind = struct.unpack_from("<IHH", signed, offset)
    # This release profile adds exactly one PKCS#7 signature to an unsigned PE.
    if (record+7) & ~7 != length or record < 8 or revision != 512 or kind != 2:
        return False
    if any(signed[offset+record:]) or any(signed[len(original):offset]):
        return False
    return (original[:checksum] == signed[:checksum]
            and original[checksum+4:directory] == signed[checksum+4:directory]
            and original[directory+8:] == signed[directory+8:len(original)])


def msi_structure(path):
    import hashlib
    import olefile
    signatures = {('\x05DigitalSignature',), ('\x05MsiDigitalSignatureEx',)}
    with olefile.OleFileIO(path, raise_defects=olefile.DEFECT_INCORRECT) as db:
        records = {(): ('root', str(db.root.clsid))}
        for entry in db.listdir(streams=True, storages=True):
            key = tuple(entry)
            if key in signatures:
                continue
            kind = db.get_type(entry)
            records[key] = (kind, str(db.getclsid(entry)),
                hashlib.sha256(db.openstream(entry).read()).hexdigest() if kind == olefile.STGTY_STREAM else '')
        return records


def same_content(original, signed):
    suffix = Path(original).suffix.lower()
    if suffix == '.msi':
        return msi_structure(original) == msi_structure(signed)
    if suffix == '.ps1':
        import re
        a, b = Path(original).read_bytes(), Path(signed).read_bytes()
        encoding = 'utf-16' if a.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        if not b.startswith(a):
            return False
        old, new = a.decode(encoding), b.decode(encoding)
        return re.fullmatch(r'(?:\r?\n)?# SIG # Begin signature block\r?\n(?:# [A-Za-z0-9+/=]+\r?\n)+# SIG # End signature block(?:\r?\n)?', new[len(old):]) is not None
    return unchanged_pe(Path(original).read_bytes(), Path(signed).read_bytes())
