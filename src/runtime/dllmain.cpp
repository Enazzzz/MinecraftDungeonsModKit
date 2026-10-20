#include <windows.h>

#include "mcd/runtime/runtime.hpp"

namespace
{
/// Releases the worker-owned module reference atomically with thread exit.
[[noreturn]] void exit_runtime_thread(const HMODULE module, const DWORD result) noexcept
{
	FreeLibraryAndExitThread(module, result);
}

/// Owns a module reference for the complete detached runtime worker lifetime.
DWORD WINAPI mcd_runtime_thread(const LPVOID parameter)
{
	const auto attached_module = static_cast<HMODULE>(parameter);
	HMODULE owned_module = nullptr;
	if(!GetModuleHandleExW(
		   GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		   reinterpret_cast<LPCWSTR>(&mcd_runtime_thread),
		   &owned_module))
	{
		const DWORD error = GetLastError();
		ExitThread(error);
	}

	if(owned_module != attached_module)
	{
		exit_runtime_thread(owned_module, ERROR_MOD_NOT_FOUND);
	}

	const DWORD result = mcd::runtime::Runtime::instance().start(owned_module);
	exit_runtime_thread(owned_module, result);
}
}

/// Starts a private worker that self-pins before performing any runtime work.
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

	const HANDLE thread = CreateThread(nullptr, 0U, &mcd_runtime_thread, instance, 0U, nullptr);
	if(thread == nullptr)
	{
		return FALSE;
	}

	CloseHandle(thread);
	return TRUE;
}
