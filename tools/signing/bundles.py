"""Windows runner bundle creation and verification. Archives use relative file entries only."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile, ZIP_DEFLATED

if __package__:
    from .content import same_content
else:
    from content import same_content

TOOLS = Path(__file__).resolve().parent


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def zip_files(output, root, paths, extra=None):
    with ZipFile(output, "x", ZIP_DEFLATED, compresslevel=1) as archive:
        for name in sorted(paths):
            archive.write(root / name, name)
        for name, value in (extra or {}).items():
            archive.writestr(name, json.dumps(value, ensure_ascii=False))


def make_bundle(root, selected, meta, phase, output, inventory=None):
    entries = [{"path":p, "role":role, "size":(root/p).stat().st_size, "sha256":sha(root/p)} for p, role in sorted(selected.items())]
    manifest = dict(schema=1, build=meta["id"], phase=phase, platform=meta["platform"],
                    version=meta["version"], certificate=meta["certificate"], files=entries,
                    inventory=inventory or [], source_revision=meta["source_revision"],
                    workflow_revision=meta["workflow_revision"])
    zip_files(output, root, selected, {"manifest.json":manifest})


def verify_bundle(original, returned, dest, meta):
    with ZipFile(original) as before, ZipFile(returned) as after:
        manifest = json.loads(before.read("manifest.json"))
        names = [v["path"] for v in manifest["files"]]+["manifest.json"]
        if (manifest != json.loads(after.read("manifest.json")) or manifest["build"] != meta["id"]
                or manifest["certificate"] != meta["certificate"] or sorted(after.namelist()) != sorted(names)):
            raise ValueError("Wrong signing manifest or archive contents")
        for entry in manifest["files"]:
            name = entry["path"]
            old, new = dest/"original"/name, dest/"verified"/name
            for archive, target in [(before, old), (after, new)]:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as src, target.open("xb") as out:
                    shutil.copyfileobj(src, out)
            if sha(old) != entry["sha256"] or not same_content(old, new):
                raise ValueError(f"Content changed in {name}")
            from signature_policy import require_sha256_timestamp
            require_sha256_timestamp(new, meta["certificate"])
            subprocess.run(["pwsh","-NoProfile","-File",str(TOOLS/"Inspect-Signature.ps1"),
                            "-File",str(new),"-Publisher",meta["certificate"]], check=True)
        return manifest


def classify(root, app):
    """Unknown unsigned code needs an explicit release-policy decision."""
    policy = json.loads((TOOLS/"windows-policy.json").read_text())
    selected, inventory = {}, []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        role = "data"
        with path.open("rb") as stream:
            magic = stream.read(4)
            pe = magic[:2] == b"MZ"
        if name == "dist/data/app.so" and magic == b"\x7fELF":
            role = "dart-aot"
        elif name == "dist/usbmmidd_v2/deviceinstaller64.exe" and policy["sign_sha256"].get(name) == sha(path):
            role = "vendor-driver-tool"
            selected[name] = role
        elif name.endswith("/no_sleep.js") and policy["preserve_sha256"].get(name) == sha(path):
            role = "reviewed-dependency"
        elif name.startswith(("dist/usbmmidd_v2/", "dist/drivers/")):
            role = "vendor-driver"
            if path.suffix.lower() == ".cat":
                subprocess.run([os.environ["RDGEN_SIGNTOOL"],"verify","/pa",str(path)],check=True)
            elif pe or path.suffix.lower() == ".inf":
                cats = [c for c in (root/("dist/usbmmidd_v2" if name.startswith("dist/usbmmidd_v2/") else "dist/drivers")).rglob("*") if c.suffix.lower()==".cat"]
                if not any(subprocess.run([os.environ["RDGEN_SIGNTOOL"],"verify","/pa","/c",str(c),str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0 for c in cats):
                    raise ValueError(f"Driver catalog membership not established: {name}")
        elif pe or path.suffix.lower() in {".dll",".exe",".ps1",".msi",".sys",".ocx",".scr",".cpl",".cat",".com",".vbs",".js",".cmd",".bat"}:
            signer = subprocess.check_output(["pwsh","-NoProfile","-File",str(TOOLS/"Inspect-Signature.ps1"),
                                              "-File",str(path),"-Classify"],text=True).strip()
            if signer != "unsigned" and policy["vendors"].get(name) == signer:
                role = "vendor-signed"
            elif signer == "unsigned" and name in {f"dist/{app}.exe", *policy["project_files"]}:
                role = "project"
                selected[name] = role
            elif signer == "unsigned" and policy.get("sign_sha256", {}).get(name) == sha(path):
                role = "reviewed-signing-input"
                selected[name] = role
            elif policy["preserve_sha256"].get(name) == sha(path):
                role = "reviewed-dependency"
            else:
                raise ValueError(f"Release policy needs a classification for {name} (SHA-256 {sha(path)}, signer {signer}).")
        inventory.append({"path":name,"role":role,"size":path.stat().st_size,"sha256":sha(path)})
    return selected, inventory
