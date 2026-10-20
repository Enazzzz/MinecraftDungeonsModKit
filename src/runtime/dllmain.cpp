#include <windows.h>

#include "mcd/runtime/runtime.hpp"

/// Runs all runtime initialization after the loader-lock callback returns.
DWORD WINAPI mcd_runtime_thread(const LPVOID parameter)
{
	const auto module = static_cast<HMODULE>(parameter);
	return mcd::runtime::Runtime::instance().start(module);
}

/// Defers runtime initialization to one worker and avoids thread notifications.
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
