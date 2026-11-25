import io
from pathlib import Path
import struct
import tempfile
from unittest import TestCase, skipUnless
import sys

from PIL import Image
from tools.signing.windows_resources import icon_resources


class Icons(TestCase):
    def test_group_points_to_every_generated_image(self):
        out = io.BytesIO()
        Image.new("RGBA", (256,256), "blue").save(out, format="ICO")
        images, group = icon_resources(out.getvalue(), 7)
        count, = struct.unpack_from("<H", group, 4)
        ids = [struct.unpack_from("<H", group, 6+i*14+12)[0] for i in range(count)]
        self.assertEqual(list(images), ids)
        self.assertEqual(ids[0], 7)
        self.assertGreater(count, 1)


@skipUnless(sys.platform == "win32", "Win32 resource APIs")
class WinResources(TestCase):
    def test_roundtrip_without_changing_original(self):
        import shutil
        from tools.signing.windows_resources import set_resources, read_resource
        with tempfile.TemporaryDirectory(prefix="rdgen test ") as tmp:
            copied = Path(tmp, "client.exe")
            shutil.copy2(sys.executable, copied)
            set_resources(copied, [(10, "RDGEN_PROFILE", 0, b'{"schema":1}')])
            self.assertEqual(read_resource(copied, 10, "RDGEN_PROFILE"), b'{"schema":1}')
