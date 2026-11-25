"""Stage a Windows artifact from the pinned, neutral RustDesk build on Actions."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

from neutral_kit import write_manifest


def run(*args, cwd):
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)


def prepare(source, kit):
    version = os.environ["RELEASE_VERSION"]
    revision = os.environ["RELEASE_SOURCE"]
    with (source/"Cargo.toml").open("rb") as cargo:
        if tomllib.load(cargo)["package"]["version"] != version:
            raise ValueError("RustDesk package version differs from release tag")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != revision:
        raise ValueError("Unexpected RustDesk source revision")
    kit.mkdir()
    dist = kit/"dist"
    shutil.copytree(source/"rustdesk", dist)
    # CMake records the exact Flutter runtime, plugin DLLs and assets selected for this build.
    flutter_build = source/"flutter/build/windows/x64"
    original = flutter_build/"runner/Release"
    installed = (flutter_build/"install_manifest.txt").read_text(encoding="utf-8-sig").splitlines()
    expected = [Path(name).relative_to(original) for name in installed if name.strip()]
    if not expected or not all((dist/rel).is_file() for rel in expected):
        raise ValueError("Incomplete Flutter distribution compared with CMake install manifest")
    sdk = source/"libs/portable"
    # The packer reads all personalized files from its RDPKG resource.
    (sdk/"data.bin").write_bytes(b"rustdeskrustdesk")
    (sdk/"app_metadata.toml").write_text("timestamp = 0\n")
    run("cargo", "build", "--release", "--locked", "-p", "rustdesk-portable-packer", cwd=source)
    template = kit/"template"
    template.mkdir()
    (template/"tools.json").write_text(json.dumps({
        "python_min": "3.11", "powershell_min": "7.2", "msbuild_min": "17.0", "wix_sdk": "4.0.5",
        "msbuild_build": subprocess.check_output(["msbuild", "-nologo", "-version"], text=True).strip(),
        "rustc_build": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "target": "x86_64-pc-windows-msvc",
    }, indent=2), encoding="utf-8")
    shutil.copy2(source/"target/release/rustdesk-portable-packer.exe", template/"portable.exe")
    shutil.copy2(sdk/"generate.py", template)
    msi = source/"res/msi"
    run("nuget", "restore", "msi.sln", cwd=msi)
    helper = kit/"msi"
    helper.mkdir()
    build_out = source/"rdgen-msi-helper"
    run("msbuild", "CustomActions/CustomActions.vcxproj", "/p:Configuration=Release", "/p:Platform=x64",
        "/p:TargetVersion=Windows10", f"/p:OutDir={build_out}/", cwd=msi)
    shutil.copy2(build_out/"CustomActions.dll", helper/"CustomActions.dll")
    package = kit/"res/msi/Package"
    shutil.copytree(msi/"Package", package, ignore=shutil.ignore_patterns("bin","obj"))
    shutil.copy2(source/"res/icon.ico", kit/"res/icon.ico")
    # The upstream preprocessor reads the executable's build date. Preserve paths
    # with spaces and never pass those paths through cmd.exe.
    processor = (msi/"preprocess.py").read_text(encoding="utf-8")
    if processor.count('f"{dist_app} {args}",') != 1 or processor.count("shell=True,") != 1:
        raise ValueError("Unexpected WiX preprocessor")
    processor = processor.replace('f"{dist_app} {args}",', '[str(dist_app), args],').replace("shell=True,", "shell=False,")
    (kit/"res/msi/preprocess.py").write_text(processor, encoding="utf-8")
    fragment = package/"Fragments/CustomActions.wxs"
    old = "$(var.CustomActions.TargetDir)$(var.CustomActions.TargetName).dll"
    contents = fragment.read_text(encoding="utf-8-sig")
    if contents.count(old) != 1:
        raise ValueError("Unexpected WiX custom action")
    fragment.write_text(contents.replace(old, "$(var.SignedHelper)"), encoding="utf-8")
    proj = package/"Package.wixproj"
    xml = ET.parse(proj)
    refs = [(g, r) for g in xml.getroot() for r in g.findall("ProjectReference")]
    if len(refs) != 1 or "CustomActions" not in refs[0][1].get("Include", ""):
        raise ValueError("Unexpected WiX project references")
    refs[0][0].remove(refs[0][1])
    xml.write(proj, encoding="utf-8", xml_declaration=True)
    origin = {k:os.environ[v] for k, v in (("repository","GITHUB_REPOSITORY"),("revision","GITHUB_SHA"),
                                            ("run","GITHUB_RUN_ID"),("attempt","GITHUB_RUN_ATTEMPT"))}
    write_manifest(kit, origin, version, revision)


if __name__ == "__main__":
    prepare(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
