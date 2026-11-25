"""Manifest for the Actions artifact ZIP and verification on the workstation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from zipfile import ZipFile

SOURCE_SHA = "95cca3f661f635b3cc85c04935fe8d96d8f432ef"
REQUIRED = {
    "dist/rustdesk.exe", "dist/librustdesk.dll", "dist/flutter_windows.dll", "dist/data/app.so",
    "dist/data/icudtl.dat", "dist/data/flutter_assets/AssetManifest.bin",
    "dist/data/flutter_assets/assets/icon.svg", "template/tools.json",
    "dist/WindowInjection.dll", "dist/printer_driver_adapter.dll",
    "dist/usbmmidd_v2/usbmmidd.cat", "dist/usbmmidd_v2/x64/usbmmIdd.dll",
    "dist/drivers/RustDeskPrinterDriver/rustdeskprinterdriver.cat",
    "msi/CustomActions.dll", "template/portable.exe", "res/msi/Package/Package.wixproj",
    "res/msi/preprocess.py", "res/icon.ico", "template/generate.py",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_manifest(root, origin, version="1.5.3", source=SOURCE_SHA):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("Invalid release version or commit")
    files = {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*") if p.is_file()}
    present = {name.casefold() for name in files}
    missing = {name for name in REQUIRED if name.casefold() not in present}
    if missing:
        raise ValueError("Missing kit files: " + ", ".join(sorted(missing)))
    header = dict(schema=1, origin=origin, source=source, version=version, arch="x64", files=files)
    (root/"kit.json").write_text(json.dumps(header, indent=2), encoding="utf-8")


def github_digest(origin):
    repo = origin["repository"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"[0-9a-f]{40}", origin["revision"]):
        raise ValueError("Expected repository and full workflow commit SHA")
    if not all(re.fullmatch(r"[1-9][0-9]*", origin[k]) for k in ("run", "attempt")):
        raise ValueError("Invalid Actions run or attempt")
    def api(path):
        return json.loads(subprocess.check_output(["gh", "api", "--hostname", "github.com", path], text=True))
    prefix = f"repos/{repo}/actions/runs/{origin['run']}"
    run = api(prefix + "/attempts/" + origin["attempt"])
    if (run["head_sha"] != origin["revision"] or run["repository"]["full_name"].lower() != repo.lower()
            or run["path"] != ".github/workflows/neutral-windows.yml" or run["conclusion"] != "success"
            or str(run["id"]) != origin["run"] or str(run["run_attempt"]) != origin["attempt"]):
        raise ValueError("Unexpected GitHub workflow run")
    name = f"neutral-windows-x64-{origin['run']}-{origin['attempt']}"
    pattern = re.escape(name) + r"(?:-[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{40})?"
    records = [item for item in api(prefix + "/artifacts?per_page=100")["artifacts"]
               if re.fullmatch(pattern, item["name"])]
    if len(records) != 1 or records[0]["expired"]:
        raise ValueError("Missing or ambiguous GitHub artifact")
    value = records[0].get("digest") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("GitHub did not supply the artifact digest")
    return value[7:]


def safe_name(name):
    parts = name.split("/")
    return all(part and part not in (".", "..") and not part.endswith((" ", "."))
               and not re.search(r'[<>:"\\|?*\x00-\x1f]', part)
               and not re.fullmatch(r"(?:CON|NUL|AUX|PRN|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?: *\..*)?", part, re.I) for part in parts)


def unpack(archive, target, expected_digest, origin):
    with archive.open("rb") as raw:
        if hashlib.file_digest(raw, "sha256").hexdigest() != expected_digest:
            raise ValueError("GitHub artifact digest mismatch")
        raw.seek(0)
        with ZipFile(raw) as z:
            names = set()
            files = {}
            total = 0
            for entry in z.infolist():
                name = entry.filename.removesuffix("/")
                mode = entry.external_attr >> 16
                if (not safe_name(name) or name.casefold() in names or stat.S_ISLNK(mode)
                        or entry.file_size > 2**31 or len(names) >= 20000):
                    raise ValueError("Invalid archive entry")
                names.add(name.casefold())
                total += entry.file_size
                if total > 6 * 2**30:
                    raise ValueError("Expanded kit too large")
                if not entry.is_dir():
                    files[name] = entry
            manifest = files.pop("kit.json", None)
            if manifest is None or manifest.file_size > 8 * 2**20:
                raise ValueError("Invalid kit manifest")
            m = json.loads(z.read(manifest))
            version, source = m.get("version"), m.get("source")
            if (not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
                    or not isinstance(source, str) or not re.fullmatch(r"[0-9a-f]{40}", source)):
                raise ValueError("Invalid release metadata")
            if version == "1.5.3":
                expected_source = SOURCE_SHA
            else:
                expected_source = subprocess.check_output(
                    ["gh", "api", "--hostname", "github.com", f"repos/rustdesk/rustdesk/commits/refs/tags/{version}",
                     "--jq", ".sha"], text=True).strip()
            if (m.get("schema") != 1 or source != expected_source or m.get("origin") != origin
                    or m.get("arch") != "x64"
                    or set(files) != set(m["files"]) or not all(name.casefold() in names for name in REQUIRED)):
                raise ValueError("Kit source, run or inventory mismatch")
            target.mkdir()
            for name, entry in files.items():
                p = target/name
                p.parent.mkdir(parents=True, exist_ok=True)
                with z.open(entry) as entry_stream, p.open("xb") as dest:
                    shutil.copyfileobj(entry_stream, dest)
                if digest(p) != m["files"][name]:
                    raise ValueError("Kit member digest mismatch")
            return version, source


if __name__ == "__main__":
    import sys
    origin = {name: os.environ[var] for name, var in
              (("repository","GITHUB_REPOSITORY"), ("revision","GITHUB_SHA"),
               ("run","GITHUB_RUN_ID"), ("attempt","GITHUB_RUN_ATTEMPT"))}
    write_manifest(Path(sys.argv[1]), origin)
