import base64
import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image
from tools.signing.local_profile import read_profile


class LocalProfileTest(unittest.TestCase):
    def profile(self, **extra):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "site.json")
            p.write_text(json.dumps({"serverIP": "id.example", "apiServer": "https://api.example", **extra}))
            return read_profile(p)

    def test_old_export_and_ipv6(self):
        with self.assertWarnsRegex(UserWarning, "enableAudio"):
            p = self.profile(serverIP="2001:db8::1", serverPort="30116", enableAudio="on")
        self.assertEqual(p.options["custom-rendezvous-server"], "[2001:db8::1]:30116")
        self.assertNotIn("relay-server", p.options)

    def test_icon_and_relay(self):
        b = io.BytesIO()
        Image.new("RGBA", (32, 32)).save(b, "PNG")
        p = self.profile(iconfile="data:image/png;base64," + base64.b64encode(b.getvalue()).decode(),
                         relayServer="relay.example:21117")
        self.assertEqual(p.icon, b.getvalue())
        self.assertEqual(p.options["relay-server"], "relay.example:21117")

    def test_reject_values_not_carried(self):
        for opts in ({"unknown": True}, {"enableAudio": False}, {"iconfile": "not PNG"},
                     {"apiServer": "https://test:pass@example.org"}, {"serverPort": "99999"},
                     {"relayServer": "host/example"}, {"key": "not-a-key"}):
            with self.subTest(opts=list(opts)), self.assertRaises(ValueError):
                self.profile(**opts)

    def test_id_default_port_for_ipv6_and_zero_ports(self):
        self.assertEqual(self.profile(serverIP="2001:db8::1").options["custom-rendezvous-server"], "[2001:db8::1]:21116")
        for relay in ("relay.example:0", "relay.example:"):
            with self.subTest(relay=relay), self.assertRaises(ValueError):
                self.profile(relayServer=relay)

    def test_compile_only_delay_option_is_reported_before_signing(self):
        import warnings
        with self.assertWarnsRegex(UserWarning, "delayFix"):
            self.profile(delayFix="on")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            self.profile(delayFix=False)


    def test_legacy_permission_defaults_are_reported(self):
        with self.assertWarnsRegex(UserWarning, "removeWallpaper"):
            self.profile(removeWallpaper="on")
        self.profile(removeWallpaper=False)
