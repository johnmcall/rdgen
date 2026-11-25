"""Compare extracted package members without installing or launching the package."""
from contextlib import contextmanager
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

if __package__:
    from .bundles import sha
else:
    from bundles import sha


def check_portable(exe, blob, dist, startup):
    import brotli
    data = blob.read_bytes()
    if data[:8] != b"rustdesk" or exe.read_bytes().count(data) != 1:
        raise ValueError("Expected one embedded portable payload")
    index, members = 8, {}
    while data[index:index+8] != b"rustdesk":
        size, = struct.unpack_from(">I", data, index)
        raw = data[index+4:index+4+size].decode()
        name = raw.replace("\\","/").removeprefix("./")
        index += 4+size
        size, = struct.unpack_from(">I", data, index)
        content = brotli.decompress(data[index+4:index+4+size])
        if name in members:
            raise ValueError("Duplicate portable entry")
        members[name] = hashlib.sha256(content).hexdigest()
        index += 4 + size + 32
    entry = data[index+8:].decode().replace("\\","/").removeprefix("./")
    expected = {p.relative_to(dist).as_posix():sha(p) for p in dist.rglob("*") if p.is_file()}
    if members != expected or entry != startup:
        raise ValueError("Portable contents differ from the signed inputs")


def match_streams(expected, actual):
    if expected != actual:
        raise ValueError("Unexpected or changed MSI Binary/Icon resource")


def check_msi(msi, dist, helper, resources):
    lib = ctypes.WinDLL("msi")
    uint = ctypes.c_uint
    def check(code):
        if code:
            raise OSError(code, "Windows Installer database read failed")
    @contextmanager
    def handle(function, *args):
        h = uint()
        check(function(*args,ctypes.byref(h)))
        try:
            yield h
        finally:
            lib.MsiCloseHandle(h)
    def string(rec,col):
        length = uint(32767)
        out = ctypes.create_unicode_buffer(length.value+1)
        check(lib.MsiRecordGetStringW(rec,col,out,ctypes.byref(length)))
        return out.value
    def stream(rec,col,path):
        with path.open("xb") as f:
            buf = ctypes.create_string_buffer(65536)
            while True:
                size = uint(len(buf))
                check(lib.MsiRecordReadStream(rec,col,buf,ctypes.byref(size)))
                if not size.value:
                    break
                f.write(buf.raw[:size.value])
    def query(db,sql):
        with handle(lib.MsiDatabaseOpenViewW,db,sql) as view:
            check(lib.MsiViewExecute(view,0))
            while True:
                row = uint()
                code = lib.MsiViewFetch(view,ctypes.byref(row))
                if code == 259:
                    break
                check(code)
                try:
                    yield row
                finally:
                    lib.MsiCloseHandle(row)
    with tempfile.TemporaryDirectory() as folder, handle(lib.MsiOpenDatabaseW,str(msi),None) as db:
        tmp = Path(folder)
        binary = json.loads(Path(__file__).with_name("windows-policy.json").read_text())["msi_binary"]
        overrides = {"WixUI_Bmp_Banner":"WixUIBannerBmp", "WixUI_Bmp_Dialog":"WixUIDialogBmp",
                     "WixUI_Ico_Exclam":"WixUIExclamationIco", "WixUI_Ico_Info":"WixUIInfoIco",
                     "WixUI_Bmp_New":"WixUINewIco", "WixUI_Bmp_Up":"WixUIUpIco"}
        for key, name in overrides.items():
            resource = resources / (name + ".bmp")
            if resource.exists():
                binary[key] = sha(resource)
        binary["Custom_Actions_Dll"] = sha(helper)
        expected = {"Binary":binary, "Icon":{"AppIcon":sha(resources/"icon.ico")}}
        actual = {}
        for table in expected:
            actual[table] = {}
            for index, row in enumerate(query(db, f"SELECT `Name`,`Data` FROM `{table}`")):
                target = tmp / f"{table}-{index}"
                stream(row, 2, target)
                actual[table][string(row, 1)] = sha(target)
        match_streams(expected, actual)
        disks = [string(row,1) for row in query(db,"SELECT `Cabinet` FROM `Media`")]
        if disks != ["#cab1.cab"]:
            raise ValueError("Unexpected MSI cabinet layout")
        for row in query(db,"SELECT `Data` FROM `_Streams` WHERE `Name`='cab1.cab'"):
            stream(row,1,tmp/"payload.cab")
        tree = tmp/"files"
        tree.mkdir()
        subprocess.run(["expand.exe","-F:*",str(tmp/"payload.cab"),str(tree)],check=True,stdout=subprocess.DEVNULL)
        dirs = {string(r,1):(string(r,2),string(r,3)) for r in query(db,"SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`")}
        comps = {string(r,1):string(r,2) for r in query(db,"SELECT `Component`,`Directory_` FROM `Component`")}
        found = {}
        for row in query(db,"SELECT `File`,`Component_`,`FileName` FROM `File`"):
            file_id, parent, filename = string(row,1), comps[string(row,2)], string(row,3)
            parts = [filename.split("|")[-1]]
            visited = set()
            while parent != "INSTALLFOLDER_INNER":
                if parent in visited or parent not in dirs:
                    raise ValueError("Unexpected MSI install directory")
                visited.add(parent)
                parent, directory = dirs[parent]
                leaf = directory.split(":")[0].split("|")[-1]
                if leaf != ".":
                    parts.insert(0,leaf)
            key = "/".join(parts).casefold()
            if key in found or Path(file_id).name != file_id:
                raise ValueError("Ambiguous MSI file")
            found[key] = sha(tree/file_id)
        expected = {p.relative_to(dist).as_posix().casefold():sha(p) for p in dist.rglob("*") if p.is_file()}
        if found != expected or len(found) != len(list(tree.iterdir())):
            raise ValueError("MSI contents differ from signed inputs")
