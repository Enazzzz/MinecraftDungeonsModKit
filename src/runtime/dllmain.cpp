#include <windows.h>

#include "mcd/runtime/runtime.hpp"

namespace
{
/// Pins this DLL without loading another module or invoking external code.
bool pin_runtime_module(const HMODULE expected_module) noexcept
{
	HMODULE pinned_module = nullptr;
	if(!GetModuleHandleExW(
		   GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			   GET_MODULE_HANDLE_EX_FLAG_PIN,
		   reinterpret_cast<LPCWSTR>(&pin_runtime_module),
		   &pinned_module))
	{
		return false;
	}
	return pinned_module == expected_module;
}

/// Runs runtime work while the process-lifetime module pin remains active.
DWORD WINAPI mcd_runtime_thread(const LPVOID parameter)
{
	const auto module = static_cast<HMODULE>(parameter);
	return mcd::runtime::Runtime::instance().start(module);
}
}

/// Pins the image for process lifetime before scheduling detached runtime work.
BOOL WINAPI DllMain(const HINSTANCE instance, const DWORD reason, LPVOID)
{
	if(reason != DLL_PROCESS_ATTACH)
	{
		return TRUE;
	}

	if(!DisableThreadLibraryCalls(instance))
	{
		return FALSE;
	}

	// Kernel32 module pinning does not load a DLL or invoke user code, so the
	// process-attach callback keeps all loader-lock work within the safe subset.
	if(!pin_runtime_module(instance))
	{
		return FALSE;
	}

	const HANDLE thread = CreateThread(nullptr, 0U, &mcd_runtime_thread, instance, 0U, nullptr);
	if(thread == nullptr)
	{
		// The irreversible pin leaves an inert image mapped, with no worker or
		// callbacks to clean up, rather than exposing an unsafe unload path.
		return TRUE;
	}

	CloseHandle(thread);
	return TRUE;
}
