"""Reports whether the injected runtime patched DXGI Present."""

import ctypes
from ctypes import wintypes

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

PID = 3656
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
process = kernel.OpenProcess(0x0410 | 0x0010, False, PID)


class MODULEINFO(ctypes.Structure):
	"""Stores the base and size of one loaded module."""

	_fields_ = [("lpBaseOfDll", ctypes.c_uint64), ("SizeOfImage", wintypes.DWORD), ("EntryPoint", ctypes.c_uint64)]


def modules():
	"""Yields loaded module names and bases."""
	handles = (ctypes.c_uint64 * 512)()
	needed = wintypes.DWORD()
	psapi.EnumProcessModules(process, handles, ctypes.sizeof(handles), ctypes.byref(needed))
	count = needed.value // 8
	for index in range(count):
		name = ctypes.create_unicode_buffer(260)
		psapi.GetModuleBaseNameW(process, ctypes.c_void_p(handles[index]), name, 260)
		yield name.value, handles[index]


def read(address, size):
	"""Reads bytes from the target process."""
	buffer = (ctypes.c_char * size)()
	got = ctypes.c_size_t()
	ok = kernel.ReadProcessMemory(process, ctypes.c_void_p(address), buffer, size, ctypes.byref(got))
	if not ok:
		return None
	return bytes(buffer[: got.value])


def main():
	"""Prints runtime modules and the Present prologue."""
	for name, base in modules():
		if "mcd" in name.lower() or "dxgi" in name.lower() or "overlay" in name.lower() or "d3d11" in name.lower():
			print(f"{name} {base:#x}")
	dxgi = next(base for name, base in modules() if name.lower() == "dxgi.dll")
	# Present was previously at the export-independent vtable; locate the function by its known prologue.
	info = MODULEINFO()
	psapi.GetModuleInformation(process, ctypes.c_void_p(dxgi), ctypes.byref(info), ctypes.sizeof(info))
	blob = read(info.lpBaseOfDll, info.SizeOfImage)
	needle = bytes.fromhex("48895c2410488974241855574156")
	offset = blob.find(needle)
	print(f"prologue offset {offset:#x}" if offset >= 0 else "prologue not found")
	if offset >= 0:
		address = info.lpBaseOfDll + offset
		data = read(address, 24)
		print(data.hex())
		engine = Cs(CS_ARCH_X86, CS_MODE_64)
		for instruction in engine.disasm(data, address):
			print(f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")


if __name__ == "__main__":
	main()
