#include <cassert>

// Verifies the test harness is running on a 64-bit build.
int main()
{
	static_assert(sizeof(void*) == 8, "Smoke tests require x64.");
	assert(sizeof(void*) == 8);
	return 0;
}
