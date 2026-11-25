"""Enforce the algorithms in the embedded signature. WinTrust verifies the chains."""
import base64
import hashlib
from pathlib import Path
import struct

from asn1crypto import cms, core, algos, tsp


class IndirectData(core.Sequence):
    _fields = [('attribute', core.Any), ('digest', algos.DigestInfo)]


def embedded_cms(path):
    path = Path(path)
    if path.suffix.lower() == '.msi':
        import olefile
        with olefile.OleFileIO(path) as package:
            return package.openstream('\x05DigitalSignature').read()
    data = path.read_bytes()
    if path.suffix.lower() == '.ps1':
        encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        block = data.decode(encoding).rsplit('# SIG # Begin signature block', 1)[1]
        lines = block.split('# SIG # End signature block', 1)[0].strip().splitlines()
        return base64.b64decode(''.join(line.removeprefix('# ') for line in lines), validate=True)
    offset = struct.unpack_from('<I', data, 60)[0] + 24
    magic = struct.unpack_from('<H', data, offset)[0]
    directory = offset + {0x10b: 96, 0x20b: 112}[magic] + 32
    cert_offset = struct.unpack_from('<I', data, directory)[0]
    length = struct.unpack_from('<I', data, cert_offset)[0]
    return data[cert_offset + 8:cert_offset + length]


def require_sha256_timestamp(path, publisher=None):
    data = embedded_cms(path)
    info = cms.ContentInfo.load(data)
    tail = data[len(info.dump()):]
    if len(tail) > 7 or any(tail) or info['content_type'].native != 'signed_data':
        raise ValueError('Invalid signature encoding')
    signed = info['content']
    encapsulated = signed['encap_content_info']
    if encapsulated['content_type'].dotted != '1.3.6.1.4.1.311.2.1.4':
        raise ValueError('Expected Authenticode indirect data')
    field = encapsulated['content']
    if isinstance(field, core.Any):
        field = field.parsed
    encoded = field.native if isinstance(field, core.OctetString) else field.untag().dump()
    if IndirectData.load(encoded)['digest']['digest_algorithm']['algorithm'].native != 'sha256':
        raise ValueError('Expected a SHA-256 content digest')
    signers = signed['signer_infos']
    if len(signers) != 1 or signers[0]['digest_algorithm']['algorithm'].native != 'sha256':
        raise ValueError('Expected one SHA-256 signer')
    if publisher:
        sid = signers[0]['sid']
        if sid.name != 'issuer_and_serial_number':
            raise ValueError('Unsupported signer identifier')
        identity = sid.chosen
        matches = [item.chosen for item in signed['certificates'] if item.name == 'certificate'
                   and item.chosen.serial_number == identity['serial_number'].native
                   and item.chosen.issuer == identity['issuer']]
        if (len(matches) != 1 or hashlib.sha256(matches[0].dump()).hexdigest().upper() != publisher.upper()
                or matches[0].extended_key_usage_value is None
                or 'code_signing' not in matches[0].extended_key_usage_value.native):
            raise ValueError('Unexpected embedded code-signing certificate')
    attrs = signers[0]['unsigned_attrs']
    timestamps = [attr for attr in attrs if attr['type'].dotted in (
        '1.3.6.1.4.1.311.3.3.1', '1.2.840.113549.1.9.16.2.14')]
    if len(timestamps) != 1 or len(timestamps[0]['values']) != 1 or len(attrs) != 1:
        raise ValueError('Expected one RFC 3161 timestamp')
    token = cms.ContentInfo.load(timestamps[0]['values'][0].dump())['content']['encap_content_info']
    if token['content_type'].dotted != '1.2.840.113549.1.9.16.1.4':
        raise ValueError('Unexpected timestamp content')
    imprint = tsp.TSTInfo.load(token['content'].contents)['message_imprint']
    if (imprint['hash_algorithm']['algorithm'].native != 'sha256' or
            imprint['hashed_message'].native != hashlib.sha256(signers[0]['signature'].native).digest()):
        raise ValueError('Invalid timestamp message imprint')
