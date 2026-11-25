"""Complete an individual Windows release on the publisher's workstation."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from bundles import classify, make_bundle, sha, verify_bundle
from check_package import check_msi, check_portable
from local_profile import read_profile
from neutral_kit import SOURCE_SHA, github_digest, unpack
from windows_resources import apply_profile, read_resource, set_resources

TOOLS = Path(__file__).resolve().parent
EXE = "RustDesk.exe"
MSI = "RustDesk.msi"


def run(*args, cwd=None):
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)


def sign_round(root, selected, scratch, args, meta, phase):
    scratch.mkdir()
    unsigned, returned = scratch/"unsigned.zip", scratch/"signed.zip"
    make_bundle(root, selected, meta, phase, unsigned)
    run("pwsh", "-NoProfile", "-File", TOOLS/"Sign-RDGenBundle.ps1",
        "-Bundle", unsigned, "-Output", returned, "-BundleSHA256", sha(unsigned),
        "-Thumbprint", args.thumbprint, "-TimestampUrl", args.timestamp, "-SignTool", args.signtool)
    verify_bundle(unsigned, returned, scratch, meta)
    for name in selected:
        shutil.copyfile(scratch/"verified"/name, root/name)


def check_build_tools(kit):
    tools = json.loads((kit/"template/tools.json").read_text(encoding="utf-8"))
    if tools["wix_sdk"] != "4.0.5" or tools["target"] != "x86_64-pc-windows-msvc":
        raise ValueError("Incompatible build kit")
    output = subprocess.check_output(["msbuild", "-nologo", "-version"], text=True)
    installed = re.findall(r"(?m)^([0-9]+)\.([0-9]+)(?:\.[0-9]+)*\s*$", output.strip())
    minimum = tuple(map(int, tools["msbuild_min"].split(".")))
    if not installed or tuple(map(int, installed[-1])) < minimum:
        raise ValueError("MSBuild 17 or newer is required")
    run("msbuild", "Package.wixproj", "/t:Restore", "/p:Configuration=Release",
        "/p:Platform=x64", cwd=kit/"res/msi/Package")


def package(kit, inputs, work, out):
    dist = inputs/"dist"
    builder = importlib.util.spec_from_file_location("portable_format", kit/"template/generate.py")
    generate = importlib.util.module_from_spec(builder)
    builder.loader.exec_module(generate)
    table = generate.generate_md5_table(str(dist), 9)
    generate.write_package_metadata(table, str(work), "./rustdesk.exe")
    blob = work/"data.bin"
    portable = out/EXE
    shutil.copyfile(kit/"template/portable.exe", portable)
    set_resources(portable, [(10, "RDPKG", 0, blob.read_bytes())])
    msi = kit/"res/msi"
    project = msi/"Package"
    run(sys.executable, msi/"preprocess.py", "--app-name", "RustDesk", "--version", "1.5.3",
        "--arp", "-d", dist, cwd=msi)
    run("msbuild", "Package.wixproj", "-restore", "/p:Configuration=Release", "/p:Platform=x64",
        f"/p:DefineConstants=SignedHelper={inputs/'msi/CustomActions.dll'}", cwd=project)
    shutil.copyfile(project/"bin/x64/Release/en-us/Package.msi", out/MSI)
    return blob


def check_outputs(kit, inputs, out, blob):
    if read_resource(out/EXE, 10, "RDPKG") != blob.read_bytes():
        raise ValueError("Unexpected portable resource")
    check_portable(out/EXE, blob, inputs/"dist", "rustdesk.exe")
    check_msi(out/MSI, inputs/"dist", inputs/"msi/CustomActions.dll", kit/"res/msi/Package/Resources")


def publish_release(destination, build):
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError(destination)
    with tempfile.TemporaryDirectory(prefix=".rdgen-", dir=destination.parent) as tmp:
        stage = Path(tmp)/"release"
        stage.mkdir()
        build(stage)
        for name in (EXE, MSI):
            if not (stage/name).is_file():
                raise ValueError("Missing verified release output")
        hashes = {name:sha(stage/name) for name in (EXE, MSI)}
        (stage/"SHA256.json").write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8")
        stage.rename(destination)  # Windows refuses replacement of an existing destination.


def release(args):
    profile = read_profile(args.profile)
    origin = {"repository":args.repository, "revision":args.revision, "run":args.run, "attempt":args.attempt}
    expected = github_digest(origin)
    with tempfile.TemporaryDirectory(prefix="rdgen-work-") as tmp:
        work = Path(tmp)
        kit = work/"kit"
        unpack(args.kit, kit, expected, origin)
        check_build_tools(kit)
        apply_profile(kit, profile)
        inputs = work/"inputs"
        inputs.mkdir()
        for name in ("dist", "msi"):
            (kit/name).rename(inputs/name)
        selected, inventory = classify(inputs, "rustdesk")
        if not {"dist/rustdesk.exe", "msi/CustomActions.dll"}.issubset(selected):
            raise ValueError("Missing required signing inputs")
        meta = dict(id=args.run + "-" + args.attempt, platform="windows", version="1.5.3",
                    certificate=args.certificate, source_revision=SOURCE_SHA, workflow_revision=args.revision)
        sign_round(inputs, selected, work/"payload-round", args, meta, "payload")
        for item in inventory:
            if item["path"] not in selected and sha(inputs/item["path"]) != item["sha256"]:
                raise ValueError("Preserved distribution file changed")
        def build(out):
            blob = package(kit, inputs, work, out)
            check_outputs(kit, inputs, out, blob)
            sign_round(out, {EXE:"package", MSI:"package"}, work/"packages-round", args, meta, "packages")
            check_outputs(kit, inputs, out, blob)
        publish_release(args.output, build)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for key in ("kit","profile","output"):
        parser.add_argument("--"+key, required=True, type=lambda x: Path(x).resolve())
    for key in ("repository","revision","run","attempt","certificate","thumbprint","timestamp","signtool"):
        parser.add_argument("--"+key, required=True)
    release(parser.parse_args())
