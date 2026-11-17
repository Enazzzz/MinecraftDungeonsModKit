#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace mcd
{
/// Reads process or test memory without throwing on unmapped addresses.
class ByteReader
{
public:
	/// Releases a derived memory reader.
	virtual ~ByteReader() = default;

	/// Copies bytes from an absolute address into the destination span.
	[[nodiscard]] virtual bool read(
		std::uintptr_t address,
		std::span<std::byte> destination) const = 0;
};

/// Describes the validated chunked UObject array for one supported build.
struct ObjectArrayInfo
{
	std::uintptr_t address {};
	std::uintptr_t chunks {};
	std::int32_t capacity {};
	std::int32_t count {};
	std::int32_t chunk_count {};
};

/// Describes one readable UObject slot, including its resolved names.
struct ObjectSample
{
	std::int32_t index {};
	std::uintptr_t object {};
	std::uint32_t flags {};
	std::uintptr_t type {};
	std::int32_t name_index {};
	std::int32_t name_number {};
	std::uintptr_t outer {};
	std::string name;
	std::string type_name;
};

/// Validates the chunked name pool and UObject array used by this build.
[[nodiscard]] std::optional<ObjectArrayInfo> inspect_reflection(
	const ByteReader& reader,
	std::uintptr_t names_global,
	std::uintptr_t objects);

/// Reads a bounded sample of occupied object slots and resolves their names.
[[nodiscard]] std::vector<ObjectSample> sample_objects(
	const ByteReader& reader,
	std::uintptr_t names_global,
	const ObjectArrayInfo& array,
	std::size_t limit);

/// Formats a bounded JSON reflection report.
[[nodiscard]] std::string object_discovery_json(
	const std::optional<ObjectArrayInfo>& array,
	const std::vector<ObjectSample>& sample);
}
