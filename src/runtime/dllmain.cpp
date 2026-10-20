#include <windows.h>

// Keeps DLL startup minimal by disabling thread notifications on attach.
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	(void)reserved;

	if(reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(module);
	}

	return TRUE;
}
