"""Prints the live DXGI Present prologue from a dummy swap chain."""

import ctypes
from ctypes import wintypes

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

user32 = ctypes.WinDLL("user32", use_last_error=True)
d3d11 = ctypes.WinDLL("d3d11", use_last_error=True)

WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
	"""Stores one window class registration."""

	_fields_ = [
		("style", wintypes.UINT),
		("lpfnWndProc", WNDPROC),
		("cbClsExtra", ctypes.c_int),
		("cbWndExtra", ctypes.c_int),
		("hInstance", wintypes.HINSTANCE),
		("hIcon", wintypes.HICON),
		("hCursor", wintypes.HANDLE),
		("hbrBackground", wintypes.HBRUSH),
		("lpszMenuName", wintypes.LPCWSTR),
		("lpszClassName", wintypes.LPCWSTR),
	]


class RECT(ctypes.Structure):
	"""Stores an empty window rectangle."""

	_fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


class DXGI_SAMPLE_DESC(ctypes.Structure):
	"""Stores one swap-chain sample description."""

	_fields_ = [("Count", wintypes.UINT), ("Quality", wintypes.UINT)]


class DXGI_RATIONAL(ctypes.Structure):
	"""Stores an unused refresh rate."""

	_fields_ = [("Numerator", wintypes.UINT), ("Denominator", wintypes.UINT)]


class DXGI_MODE_DESC(ctypes.Structure):
	"""Stores one back-buffer mode."""

	_fields_ = [
		("Width", wintypes.UINT),
		("Height", wintypes.UINT),
		("RefreshRate", DXGI_RATIONAL),
		("Format", ctypes.c_int),
		("ScanlineOrdering", ctypes.c_int),
		("Scaling", ctypes.c_int),
	]


class DXGI_SWAP_CHAIN_DESC(ctypes.Structure):
	"""Stores one dummy swap-chain description."""

	_fields_ = [
		("BufferDesc", DXGI_MODE_DESC),
		("SampleDesc", DXGI_SAMPLE_DESC),
		("BufferUsage", wintypes.UINT),
		("BufferCount", wintypes.UINT),
		("OutputWindow", wintypes.HWND),
		("Windowed", wintypes.BOOL),
		("SwapEffect", ctypes.c_int),
		("Flags", wintypes.UINT),
	]


def wndproc(hwnd, msg, wparam, lparam):
	"""Forwards dummy-window messages to the default handler."""
	return user32.DefWindowProcW(hwnd, msg, wparam, lparam)


def main():
	"""Creates a throwaway device and disassembles Present."""
	callback = WNDPROC(wndproc)
	klass = WNDCLASSW()
	klass.lpfnWndProc = callback
	kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
	kernel32.GetModuleHandleW.restype = ctypes.c_void_p
	klass.hInstance = kernel32.GetModuleHandleW(None)
	user32.CreateWindowExW.argtypes = [
		wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
		ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
		wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
	]
	user32.CreateWindowExW.restype = wintypes.HWND
	klass.lpszClassName = "mcd_present_probe"
	user32.RegisterClassW(ctypes.byref(klass))
	hwnd = user32.CreateWindowExW(0, klass.lpszClassName, "mcd", 0, 0, 0, 8, 8, None, None, klass.hInstance, None)
	desc = DXGI_SWAP_CHAIN_DESC()
	desc.BufferDesc.Width = 8
	desc.BufferDesc.Height = 8
	desc.BufferDesc.Format = 28
	desc.SampleDesc.Count = 1
	desc.BufferUsage = 32
	desc.BufferCount = 2
	desc.OutputWindow = hwnd
	desc.Windowed = True
	desc.SwapEffect = 0
	device = ctypes.c_void_p()
	context = ctypes.c_void_p()
	swap = ctypes.c_void_p()
	feature = ctypes.c_int()
	hr = d3d11.D3D11CreateDeviceAndSwapChain(
		None, 1, None, 0, None, 0, 7,
		ctypes.byref(desc), ctypes.byref(swap), ctypes.byref(device), ctypes.byref(feature), ctypes.byref(context),
	)
	print(f"hr {hr:#x} swap {swap.value:#x}" if swap.value else f"hr {hr:#x}")
	if not swap.value:
		return
	vtable = ctypes.cast(swap, ctypes.POINTER(ctypes.c_void_p))[0]
	present = ctypes.cast(vtable, ctypes.POINTER(ctypes.c_void_p))[8]
	resize = ctypes.cast(vtable, ctypes.POINTER(ctypes.c_void_p))[13]
	print(f"present {present:#x}")
	print(f"resize {resize:#x}")
	blob = (ctypes.c_ubyte * 32).from_address(present)
	data = bytes(blob)
	print(data.hex())
	engine = Cs(CS_ARCH_X86, CS_MODE_64)
	for instruction in engine.disasm(data, present):
		print(f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str} ({instruction.size})")


if __name__ == "__main__":
	main()
