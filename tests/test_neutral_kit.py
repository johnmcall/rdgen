import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from zipfile import ZipFile

from tools.signing.neutral_kit import unpack, write_manifest, REQUIRED, github_digest


class NeutralKitTests(TestCase):
    def test_verified_tree_and_wrong_origin(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp, "kit")
            for name in REQUIRED:
                p = root/name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"fixture")
            expected = {"repository":"org/repo","revision":"1"*40,"run":"25","attempt":"1"}
            write_manifest(root, expected)
            for variant in ("ok", "case", "path", "missing", "run", "digest"):
                archive = Path(tmp, variant + ".zip")
                with ZipFile(archive, "w") as z:
                    for p in root.rglob("*"):
                        if p.is_file() and not (variant == "missing" and p.name == "CustomActions.dll"):
                            z.write(p, p.relative_to(root))
                    if variant == "case":
                        z.writestr("DIST/RUSTDESK.EXE", b"extra")
                    if variant == "path":
                        z.writestr("../outside", b"extra")
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                if variant == "ok":
                    unpack(archive, Path(tmp, variant), digest, expected)
                else:
                    with self.subTest(variant=variant), self.assertRaises(ValueError):
                        unpack(archive, Path(tmp, variant), digest if variant != "digest" else "0"*64,
                               dict(expected, run="26") if variant == "run" else expected)

class GitHubProvenanceTests(TestCase):
    def test_authenticated_metadata_matches_each_identifier(self):
        origin = dict(repository="example/repo", revision="a"*40, run="51", attempt="2")
        run = dict(head_sha="a"*40, repository={"full_name":"example/repo"}, path=".github/workflows/neutral-windows.yml",
                   conclusion="success", id=51, run_attempt=2)
        artifact = dict(id=11, name="neutral-windows-x64-51-2", expired=False, digest="sha256:"+"b"*64)
        for field, wrong in (("path", "other.yml"), ("head_sha", "c"*40), ("run_attempt", 1), ("id", 50)):
            with self.subTest(field=field), patch("subprocess.check_output", return_value=json.dumps(dict(run, **{field:wrong}))), self.assertRaises(ValueError):
                github_digest(origin)
        with patch("subprocess.check_output", side_effect=[json.dumps(run), json.dumps({"artifacts":[artifact]})]) as call:
            self.assertEqual(github_digest(origin), "b"*64)
            self.assertIn("/attempts/2", call.call_args_list[0].args[0][-1])

    def test_reject_windows_device_aliases(self):
        from tools.signing.neutral_kit import safe_name
        for name in ("CONIN$.txt", "COM¹.dll", "dir/aux.log", "dist/file. ", "dist/a:b"):
            self.assertFalse(safe_name(name), name)

    def test_missing_flutter_runtime_is_rejected_before_upload(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in REQUIRED - {"dist/data/icudtl.dat"}:
                p = root/name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "icudtl.dat"):
                write_manifest(root, {})
