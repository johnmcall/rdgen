from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools/signing"))
from local_release import publish_release


class ReleaseTests(TestCase):
    def test_incomplete_release_is_kept_private(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            old = root/"older"
            old.mkdir()
            (old/"old.msi").write_bytes(b"old")

            def interrupted(stage):
                (stage/"RustDesk.exe").write_bytes(b"first")
                raise ValueError("Second signature failed")

            with self.assertRaises(ValueError):
                publish_release(root/"new", interrupted)
            self.assertEqual(list(root.iterdir()), [old])
            self.assertEqual((old/"old.msi").read_bytes(), b"old")

    def test_existing_release_cannot_be_overwritten(self):
        with TemporaryDirectory() as td:
            destination = Path(td)/"release"
            def build(folder):
                (folder/"RustDesk.exe").write_bytes(b"exe")
                (folder/"RustDesk.msi").write_bytes(b"msi")
            publish_release(destination, build)
            self.assertEqual((destination/"RustDesk.msi").read_bytes(), b"msi")
            with self.assertRaises(FileExistsError):
                publish_release(destination, build)

class BuildToolsTest(TestCase):
    def test_wrong_msbuild_stops_before_restore(self):
        import json
        from unittest.mock import patch
        from local_release import check_build_tools
        with TemporaryDirectory() as td:
            root = Path(td)
            (root/"template").mkdir()
            (root/"template/tools.json").write_text(json.dumps({"wix_sdk":"4.0.5", "target":"x86_64-pc-windows-msvc", "msbuild_min":"17.0"}))
            with patch("local_release.subprocess.check_output", return_value="16.11.1"), patch("local_release.run") as restore, self.assertRaises(ValueError):
                check_build_tools(root)
            restore.assert_not_called()
            with patch("local_release.subprocess.check_output", return_value="17.10.2"), patch("local_release.run") as restore:
                check_build_tools(root)
            self.assertIn("/t:Restore", restore.call_args.args)
