#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "mcd/object_array.hpp"
#include "mcd/pattern.hpp"

namespace
{
/// Throws a deterministic test failure with a human-readable message.
[[noreturn]] void fail(const std::string_view message)
{
	throw std::runtime_error(std::string(message));
}

/// Fails fast when a required test condition is false.
void require(const bool condition, const std::string_view message)
{
	if(!condition)
	{
		fail(message);
	}
}

/// Expands one active test oracle check with its source expression text.
#define REQUIRE(condition) require(static_cast<bool>(condition), #condition)

/// Serves a flat synthetic address space.
class BufferReader final : public mcd::ByteReader
{
public:
	/// Stores the synthetic address space.
	explicit BufferReader(std::vector<std::byte> bytes)
		: bytes_(std::move(bytes))
	{
	}

	/// Copies an in-range address span.
	[[nodiscard]] bool read(
		const std::uintptr_t address,
		const std::span<std::byte> destination) const override
	{
		if(address > bytes_.size() || destination.size() > bytes_.size() - address)
		{
			return false;
		}
		std::memcpy(destination.data(), bytes_.data() + address, destination.size());
		return true;
	}

private:
	std::vector<std::byte> bytes_;
};

/// Writes a trivially copyable value into the synthetic image.
template <typename T>
void write_at(std::vector<std::byte>& bytes, const std::size_t offset, const T& value)
{
	std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

/// Verifies masked pattern matching and RIP-relative resolution.
void test_pattern_matching()
{
	const auto pattern = mcd::parse_pattern("48 8D ?? 78");
	REQUIRE(pattern.has_value());
	const std::vector<std::byte> bytes {
		std::byte {0x00},
		std::byte {0x48},
		std::byte {0x8D},
		std::byte {0x0D},
		std::byte {0x78},
	};
	const auto match = mcd::find_pattern(bytes, *pattern);
	REQUIRE(match == 1U);
	REQUIRE(!mcd::parse_pattern("GG").has_value());
	REQUIRE(mcd::resolve_rip_relative(0x1000U, -8, 7U) == 0xFFFU);
}

/// Writes a null-terminated ANSI name entry.
void write_name(
	std::vector<std::byte>& image,
	const std::uintptr_t entry,
	const std::uint32_t header,
	const std::string_view text)
{
	write_at(image, entry + 8U, header);
	std::memcpy(image.data() + entry + 12U, text.data(), text.size());
}

/// Verifies the chunked name pool and 24-byte UObject slots used by this build.
void test_object_array_discovery()
{
	std::vector<std::byte> image(0x44000U);
	const std::uintptr_t names_global = 0x10000U;
	const std::uintptr_t names = 0x20000U;
	const std::uintptr_t name_chunk = 0x21000U;
	const std::uintptr_t none_entry = 0x22000U;
	const std::uintptr_t byte_entry = 0x22100U;
	const std::uintptr_t objects = 0x30000U;
	const std::uintptr_t object_chunks = 0x40000U;
	const std::uintptr_t object_items = 0x41000U;
	const std::uintptr_t object = 0x42000U;
	const std::uintptr_t type = 0x43000U;

	write_at(image, names_global, names);
	write_at(image, names, name_chunk);
	write_at(image, names + 0x800U, std::int32_t {2});
	write_at(image, names + 0x804U, std::int32_t {1});
	write_at(image, name_chunk, none_entry);
	write_at(image, name_chunk + 8U, byte_entry);
	write_name(image, none_entry, 0U, "None");
	write_name(image, byte_entry, 2U, "ByteProperty");

	write_at(image, objects + 0x10U, object_chunks);
	write_at(image, objects + 0x20U, std::int32_t {65536});
	write_at(image, objects + 0x24U, std::int32_t {1});
	write_at(image, objects + 0x28U, std::int32_t {1});
	write_at(image, objects + 0x2CU, std::int32_t {1});
	write_at(image, object_chunks, object_items);
	write_at(image, object_items, object);
	write_at(image, object + 8U, std::uint32_t {7U});
	write_at(image, object + 12U, std::int32_t {0});
	write_at(image, object + 16U, type);
	write_at(image, object + 24U, std::int32_t {0});
	write_at(image, object + 28U, std::int32_t {0});
	write_at(image, object + 32U, std::uintptr_t {0U});
	write_at(image, type + 24U, std::int32_t {1});

	BufferReader reader(image);
	const auto found = mcd::inspect_reflection(reader, names_global, objects);
	REQUIRE(found.has_value());
	REQUIRE(found->count == 1);
	REQUIRE(found->capacity == 65536);
	const auto sample = mcd::sample_objects(reader, names_global, *found, 4U);
	REQUIRE(sample.size() == 1U);
	REQUIRE(sample[0].name == "None");
	REQUIRE(sample[0].type_name == "ByteProperty");
	const auto json = mcd::object_discovery_json(found, sample);
	REQUIRE(json.find("\"count\":1") != std::string::npos);
	REQUIRE(json.find("\"name\":\"None\"") != std::string::npos);

	write_name(image, none_entry, 0U, "Nope");
	BufferReader rejected(image);
	REQUIRE(!mcd::inspect_reflection(rejected, names_global, objects).has_value());
}
}

/// Runs the object-discovery regression checks.
int main()
{
	try
	{
		test_pattern_matching();
		test_object_array_discovery();
	}
	catch(const std::exception&)
	{
		return 1;
	}
	return 0;
}
