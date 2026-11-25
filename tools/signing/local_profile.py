"""Read an RDGen browser export on the publisher's workstation."""
import base64
from dataclasses import dataclass
from io import BytesIO
import ipaddress
import json
from pathlib import Path
import re
import warnings
from urllib.parse import urlsplit

from PIL import Image, UnidentifiedImageError


@dataclass(frozen=True)
class LocalProfile:
    options: dict[str, str]
    icon: bytes | None


DEFAULTS = {
    "platform": "windows", "direction": "both",
    "installation": "installationY", "settings": "settingsY", "theme": "system",
    "themeDorO": "default", "passApproveMode": "password-click", "permissionsType": "custom",
}
CHECKED = set("""enableKeyboard enableClipboard enableFileTransfer enableAudio enableTCP
    enableRemoteRestart enableRecording enableBlockingInput enablePrinter enableCamera enableTerminal
    """.split())
FIELDS = {"serverIP", "serverPort", "relayServer", "apiServer", "key", "iconfile", "iconbase64", "exename"}


def endpoint(host, port="", *, default_port=""):
    if not isinstance(host, str) or not host or re.search(r'[\s/@?#\\]', host):
        raise ValueError("Invalid server address")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if host.endswith(":"):
            raise ValueError("Empty server port")
        parsed = urlsplit("//" + host)
        address = parsed.hostname
        if not address or not re.fullmatch(r"[\w.:-]+", address, re.ASCII):
            raise ValueError("Invalid server hostname")
        if parsed.port is not None:
            if port and str(parsed.port) != str(port):
                raise ValueError("Conflicting server ports")
            port = parsed.port
    else:
        address = str(addr)
    if ":" in address:
        address = "[" + str(ipaddress.IPv6Address(address)) + "]"
    if port == "":
        port = default_port
    if port != "" and (not str(port).isascii() or not str(port).isdigit() or not 1 <= int(port) <= 65535):
        raise ValueError("Invalid server port")
    return address + (":" + str(port) if port != "" else "")


def read_profile(path: Path) -> LocalProfile:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Profile is too large")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("Expected an RDGen JSON object")
    legacy_settings = []
    for name, value in data.items():
        if name in FIELDS:
            continue
        if name == "delayFix" and value in (True, "on", "true"):
            warnings.warn("delayFix is a compile-time option. This neutral kit uses the standard RustDesk handshake.", stacklevel=2)
            continue
        if name == "removeWallpaper" and value in (True, "on", "true"):
            legacy_settings.append(name)
            continue
        if name == "version":
            # RDGen full exports include the version selected when saving the profile.
            accepted = isinstance(value, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
        elif name in CHECKED:
            legacy_settings.append(name)
            accepted = value in (True, "on", "true")
        elif name in DEFAULTS:
            accepted = value == DEFAULTS[name]
        else:
            accepted = value in (None, False, "")
        if not accepted:
            raise ValueError(f"Unsupported local profile option: {name}")
    if legacy_settings:
        warnings.warn("Legacy form options use stock RustDesk settings in this connection-only profile: "
                      + ", ".join(sorted(legacy_settings)), stacklevel=2)
    options = {}
    if data.get("serverIP"):
        options["custom-rendezvous-server"] = endpoint(data["serverIP"], data.get("serverPort") or "", default_port=21116)
    elif data.get("serverPort"):
        raise ValueError("serverPort requires serverIP")
    if data.get("relayServer"):
        options["relay-server"] = endpoint(data["relayServer"], default_port=21117)
    if data.get("apiServer"):
        url = urlsplit(data["apiServer"])
        if url.scheme not in ("http", "https") or not url.hostname or url.username is not None or url.query or url.fragment:
            raise ValueError("Invalid apiServer URL")
        endpoint(url.netloc)
        options["api-server"] = data["apiServer"].rstrip("/")
    if data.get("key"):
        if len(base64.b64decode(data["key"], validate=True)) != 32:
            raise ValueError("Expected a public RustDesk server key")
        options["key"] = data["key"]
    raw = data.get("iconfile") or data.get("iconbase64")
    icon = None
    if raw:
        prefix = "data:image/png;base64,"
        if not isinstance(raw, str) or not raw.startswith(prefix):
            raise ValueError("Expected a PNG icon")
        icon = base64.b64decode(raw[len(prefix):], validate=True)
        try:
            with Image.open(BytesIO(icon)) as im:
                if im.format != "PNG" or im.width != im.height or im.width > 4096:
                    raise ValueError("Expected a square PNG up to 4096 pixels")
                im.verify()
        except (UnidentifiedImageError, OSError) as exc:
            raise ValueError("Invalid PNG icon") from exc
    return LocalProfile(options, icon)
