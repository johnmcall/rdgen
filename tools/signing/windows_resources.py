"""Write and read Windows resources before Authenticode signing."""
import ctypes
from ctypes import wintypes as w
import io
import json
from pathlib import Path
import struct
from PIL import Image


def kernel_function(name, result, *args):
    fn = getattr(ctypes.WinDLL("kernel32", use_last_error=True), name)
    fn.argtypes = args
    fn.restype = result
    return fn


def identifier(value):
    if isinstance(value, int):
        if not 1 <= value <= 65535:
            raise ValueError("Invalid Win32 resource identifier")
        return ctypes.c_void_p(value)
    return ctypes.cast(ctypes.c_wchar_p(value), ctypes.c_void_p)


def checked(value):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


def set_resources(path, entries):
    ptr = ctypes.c_void_p
    begin = kernel_function("BeginUpdateResourceW", w.HANDLE, w.LPCWSTR, w.BOOL)
    update = kernel_function("UpdateResourceW", w.BOOL, w.HANDLE, ptr, ptr, w.WORD, ptr, w.DWORD)
    end = kernel_function("EndUpdateResourceW", w.BOOL, w.HANDLE, w.BOOL)
    handle = checked(begin(str(path), False))
    try:
        for kind, name, language, data in entries:
            buf = ctypes.create_string_buffer(data, len(data))
            checked(update(handle, identifier(kind), identifier(name), language, buf, len(data)))
    except BaseException:
        end(handle, True)
        raise
    checked(end(handle, False))


def read_resource(path, kind, name):
    ptr = ctypes.c_void_p
    load = kernel_function("LoadLibraryExW", w.HMODULE, w.LPCWSTR, w.HANDLE, w.DWORD)
    free = kernel_function("FreeLibrary", w.BOOL, w.HMODULE)
    find = kernel_function("FindResourceW", ptr, w.HMODULE, ptr, ptr)
    length = kernel_function("SizeofResource", w.DWORD, w.HMODULE, ptr)
    resource = kernel_function("LoadResource", ptr, w.HMODULE, ptr)
    lock = kernel_function("LockResource", ptr, ptr)
    module = checked(load(str(path), None, 0x22))  # data file and image resource, no entry point
    try:
        info = checked(find(module, identifier(name), identifier(kind)))
        addr = checked(lock(checked(resource(module, info))))
        return ctypes.string_at(addr, checked(length(module, info)))
    finally:
        free(module)


def icon_resources(ico, first_id):
    reserved, kind, count = struct.unpack_from("<HHH", ico)
    if reserved or kind != 1 or not count or first_id + count > 65536:
        raise ValueError("Invalid icon directory")
    group = bytearray(ico[:6])
    images = {}
    for i in range(count):
        offset = 6 + 16*i
        size, start = struct.unpack_from("<II", ico, offset+8)
        if start+size > len(ico) or not size:
            raise ValueError("Truncated icon")
        images[first_id+i] = ico[start:start+size]
        group.extend(ico[offset:offset+12] + struct.pack("<H", first_id+i))
    return images, bytes(group)


def icon_entries(exe, ico):
    import pefile
    with pefile.PE(str(exe), fast_load=True) as pe:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        types = {e.id:e.directory.entries for e in pe.DIRECTORY_ENTRY_RESOURCE.entries}
        groups = types.get(14, [])
        if not groups:
            raise ValueError("Expected an application icon resource")
        # Windows displays the first application icon group. Preserve unrelated groups.
        main = groups[0]
        group_name = main.id if main.id is not None else str(main.name)
        first_id = max((e.id or 0 for e in types.get(3, [])), default=0) + 1
        images, group = icon_resources(ico, first_id)
        entries = []
        for lang in main.directory.entries:
            entries.extend((3, key, lang.id, value) for key, value in images.items())
            entries.append((14, group_name, lang.id, group))
    return entries


def apply_profile(kit: Path, profile):
    wire = json.dumps({"schema":1, "options":profile.options}, separators=(",", ":")).encode()
    if len(wire) > 65536:
        raise ValueError("Profile exceeds client resource limit")
    exe = kit/"dist/rustdesk.exe"
    changes = [(10, "RDGEN_PROFILE", 0, wire)]
    if profile.icon:
        assets = kit/"dist/data/flutter_assets/assets"
        with Image.open(io.BytesIO(profile.icon)) as image:
            image = image.convert("RGBA").resize((256, 256), Image.Resampling.LANCZOS)
            buf = io.BytesIO()
            image.save(buf, format="ICO")
            ico = buf.getvalue()
            image.resize((48,48), Image.Resampling.LANCZOS).save(assets/"icon.png")
        (assets/"icon.ico").write_bytes(ico)
        (kit/"res/icon.ico").write_bytes(ico)
        changes.extend(icon_entries(exe, ico))
        wrapper = kit/"template/portable.exe"
        set_resources(wrapper, icon_entries(wrapper, ico))
    set_resources(exe, changes)
    if read_resource(exe, 10, "RDGEN_PROFILE") != wire:
        raise ValueError("Client profile resource read-back failed")
