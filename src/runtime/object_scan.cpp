#include "mcd/object_array.hpp"
#include "mcd/runtime/runtime.hpp"

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "mcd/build_identity.hpp"

#include <windows.h>
#include <psapi.h>

namespace
{
/// Reads memory only when the complete destination is committed.
class ProcessReader final : public mcd::ByteReader
{
public:
	/// Copies bytes from the current process after checking the full range.
	[[nodiscard]] bool read(
		const std::uintptr_t address,
		const std::span<std::byte> destination) const override
	{
		if(destination.empty())
		{
			return true;
		}
		std::size_t remaining = destination.size();
		auto cursor = address;
		while(remaining > 0U)
		{
			MEMORY_BASIC_INFORMATION region {};
			if(VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region)) == 0U ||
				region.State != MEM_COMMIT ||
				(region.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0U)
			{
				return false;
			}
			const auto region_start = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
			const auto region_end = region_start + region.RegionSize;
			if(cursor < region_start || cursor >= region_end)
			{
				return false;
			}
			const auto available = static_cast<std::size_t>(region_end - cursor);
			const auto chunk = available < remaining ? available : remaining;
			std::memcpy(
				destination.data() + (destination.size() - remaining),
				reinterpret_cast<const void*>(cursor),
				chunk);
			cursor += chunk;
			remaining -= chunk;
		}
		return true;
	}
};
}

namespace mcd::runtime
{
/// Reads the supported build's name pool and chunked UObject array.
std::string discover_host_objects(const std::string_view profile_id)
{
	const std::vector<mcd::ObjectSample> empty;
	const auto profile = mcd::profile_for_id(profile_id);
	const HMODULE module = GetModuleHandleW(nullptr);
	MODULEINFO information {};
	if(!profile || module == nullptr ||
		!GetModuleInformation(GetCurrentProcess(), module, &information, sizeof(information)))
	{
		return mcd::object_discovery_json(std::nullopt, empty);
	}

	const auto base = reinterpret_cast<std::uintptr_t>(information.lpBaseOfDll);
	ProcessReader reader;
	const auto array = mcd::inspect_reflection(
		reader,
		base + profile->names_global_rva,
		base + profile->object_array_rva);
	if(!array)
	{
		return mcd::object_discovery_json(std::nullopt, empty);
	}
	const auto sample = mcd::sample_objects(
		reader,
		base + profile->names_global_rva,
		*array,
		8U);
	return mcd::object_discovery_json(array, sample);
}
}
