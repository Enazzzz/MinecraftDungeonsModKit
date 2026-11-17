#include "mcd/object_array.hpp"

#include <cstring>
#include <string>

namespace
{
/// Name entries stored in one GNames chunk. Matches the live divide-by-16384.
constexpr std::int32_t name_chunk_entries = 16'384;

/// UObject items stored in one GUObjectArray chunk. Matches the live divide-by-65536.
constexpr std::int32_t object_chunk_entries = 65'536;

/// Byte offset of the name-pool element count.
constexpr std::uintptr_t name_count_offset = 0x800U;

/// Byte offset of the name-pool chunk count.
constexpr std::uintptr_t name_chunk_count_offset = 0x804U;

/// Byte offset of an FNameEntry header. Bit 0 marks a wide string; the index is header >> 1.
constexpr std::uintptr_t name_header_offset = 8U;

/// Byte offset of the characters in an FNameEntry.
constexpr std::uintptr_t name_text_offset = 12U;

/// Byte offset of the UObject chunk-pointer array.
constexpr std::uintptr_t object_chunks_offset = 0x10U;

/// Byte offset of the rounded UObject capacity.
constexpr std::uintptr_t object_capacity_offset = 0x20U;

/// Byte offset of the live UObject count.
constexpr std::uintptr_t object_count_offset = 0x24U;

/// Byte offset of the allocated chunk capacity.
constexpr std::uintptr_t object_max_chunks_offset = 0x28U;

/// Byte offset of the populated chunk count.
constexpr std::uintptr_t object_chunk_count_offset = 0x2CU;

/// FUObjectItem stride confirmed by the allocator's 24-byte zero loop.
constexpr std::uintptr_t object_item_stride = 24U;

/// Copies a trivially copyable value through the memory reader.
template <typename T>
bool read_value(const mcd::ByteReader& reader, const std::uintptr_t address, T& value)
{
	std::byte bytes[sizeof(T)] {};
	if(!reader.read(address, bytes))
	{
		return false;
	}
	std::memcpy(&value, bytes, sizeof(T));
	return true;
}

/// Returns whether a pointer has plausible user-space alignment.
bool aligned_pointer(const std::uintptr_t value)
{
	return value >= 0x10000ULL && (value & 0x7ULL) == 0U;
}

/// Encodes one Unicode code point as UTF-8.
void append_utf8(std::string& text, const char32_t code)
{
	if(code < 0x80U)
	{
		text.push_back(static_cast<char>(code));
	}
	else if(code < 0x800U)
	{
		text.push_back(static_cast<char>(0xC0U | (code >> 6U)));
		text.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
	}
	else
	{
		text.push_back(static_cast<char>(0xE0U | (code >> 12U)));
		text.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3FU)));
		text.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
	}
}

/// Reads one ANSI or UTF-16 name entry into UTF-8 text.
std::optional<std::string> read_name_text(
	const mcd::ByteReader& reader,
	const std::uintptr_t entry,
	const bool wide)
{
	std::byte raw[256] {};
	if(!reader.read(entry + name_text_offset, raw))
	{
		return std::nullopt;
	}
	std::string text;
	if(!wide)
	{
		for(const std::byte value : raw)
		{
			if(value == std::byte {0})
			{
				return text;
			}
			const auto code = std::to_integer<unsigned char>(value);
			if(code < 0x20U || code > 0x7EU)
			{
				return std::nullopt;
			}
			text.push_back(static_cast<char>(code));
		}
		return std::nullopt;
	}

	for(std::size_t index = 0U; index + 1U < sizeof(raw); index += 2U)
	{
		const char32_t code =
			std::to_integer<unsigned char>(raw[index]) |
			(static_cast<char32_t>(std::to_integer<unsigned char>(raw[index + 1U])) << 8U);
		if(code == 0U)
		{
			return text;
		}
		if(code < 0x20U || code > 0x7EU)
		{
			return std::nullopt;
		}
		append_utf8(text, code);
	}
	return std::nullopt;
}

/// Resolves one comparison-name index through the chunked name pool.
std::optional<std::string> resolve_name(
	const mcd::ByteReader& reader,
	const std::uintptr_t names,
	const std::int32_t count,
	const std::int32_t index)
{
	if(index < 0 || index >= count)
	{
		return std::nullopt;
	}
	const auto chunk_index = static_cast<std::uintptr_t>(index / name_chunk_entries);
	const auto entry_index = static_cast<std::uintptr_t>(index % name_chunk_entries);
	std::uintptr_t chunk = 0U;
	std::uintptr_t entry = 0U;
	std::uint32_t header = 0U;
	if(!read_value(reader, names + chunk_index * sizeof(std::uintptr_t), chunk) ||
		!aligned_pointer(chunk) ||
		!read_value(reader, chunk + entry_index * sizeof(std::uintptr_t), entry) ||
		!aligned_pointer(entry) ||
		!read_value(reader, entry + name_header_offset, header))
	{
		return std::nullopt;
	}
	if((header >> 1U) != static_cast<std::uint32_t>(index))
	{
		return std::nullopt;
	}
	return read_name_text(reader, entry, (header & 1U) != 0U);
}

/// Appends one hexadecimal address as a JSON string.
void append_hex(std::string& json, const std::uintptr_t value)
{
	constexpr char digits[] = "0123456789abcdef";
	json += "\"0x";
	for(int shift = 60; shift >= 0; shift -= 4)
	{
		json.push_back(digits[(value >> shift) & 0x0FULL]);
	}
	json.push_back('"');
}

/// Appends one UTF-8 value as a quoted JSON string.
void append_json_string(std::string& json, const std::string& value)
{
	json.push_back('"');
	for(const unsigned char code : value)
	{
		if(code == '"' || code == '\\')
		{
			json.push_back('\\');
			json.push_back(static_cast<char>(code));
		}
		else if(code < 0x20U)
		{
			constexpr char digits[] = "0123456789abcdef";
			json += "\\u00";
			json.push_back(digits[code >> 4U]);
			json.push_back(digits[code & 0x0FU]);
		}
		else
		{
			json.push_back(static_cast<char>(code));
		}
	}
	json.push_back('"');
}
}

namespace mcd
{
/// Validates the chunked name pool and UObject array used by this build.
std::optional<ObjectArrayInfo> inspect_reflection(
	const ByteReader& reader,
	const std::uintptr_t names_global,
	const std::uintptr_t objects)
{
	std::uintptr_t names = 0U;
	std::int32_t name_count = 0;
	std::int32_t name_chunks = 0;
	if(!read_value(reader, names_global, names) || !aligned_pointer(names) ||
		!read_value(reader, names + name_count_offset, name_count) ||
		!read_value(reader, names + name_chunk_count_offset, name_chunks))
	{
		return std::nullopt;
	}
	if(name_count < 2 || name_count > 5'000'000 || name_chunks < 1 || name_chunks > 256 ||
		name_count > name_chunks * name_chunk_entries)
	{
		return std::nullopt;
	}
	const auto none = resolve_name(reader, names, name_count, 0);
	const auto byte_property = resolve_name(reader, names, name_count, 1);
	if(!none || !byte_property || *none != "None" || *byte_property != "ByteProperty")
	{
		return std::nullopt;
	}

	std::uintptr_t chunks = 0U;
	std::int32_t capacity = 0;
	std::int32_t count = 0;
	std::int32_t max_chunks = 0;
	std::int32_t chunk_count = 0;
	if(!read_value(reader, objects + object_chunks_offset, chunks) ||
		!read_value(reader, objects + object_capacity_offset, capacity) ||
		!read_value(reader, objects + object_count_offset, count) ||
		!read_value(reader, objects + object_max_chunks_offset, max_chunks) ||
		!read_value(reader, objects + object_chunk_count_offset, chunk_count))
	{
		return std::nullopt;
	}
	if(!aligned_pointer(chunks) || capacity < object_chunk_entries || capacity > 5'000'000 ||
		capacity % object_chunk_entries != 0 || max_chunks != capacity / object_chunk_entries ||
		chunk_count < 1 || chunk_count > max_chunks || count < 1 || count > capacity)
	{
		return std::nullopt;
	}

	std::uintptr_t first_chunk = 0U;
	std::uintptr_t first_object = 0U;
	std::int32_t internal_index = 0;
	if(!read_value(reader, chunks, first_chunk) || !aligned_pointer(first_chunk) ||
		!read_value(reader, first_chunk, first_object) || !aligned_pointer(first_object) ||
		!read_value(reader, first_object + 12U, internal_index) || internal_index != 0)
	{
		return std::nullopt;
	}
	return ObjectArrayInfo {
		.address = objects,
		.chunks = chunks,
		.capacity = capacity,
		.count = count,
		.chunk_count = chunk_count,
	};
}

/// Reads a bounded sample of occupied object slots and resolves their names.
std::vector<ObjectSample> sample_objects(
	const ByteReader& reader,
	const std::uintptr_t names_global,
	const ObjectArrayInfo& array,
	const std::size_t limit)
{
	std::vector<ObjectSample> sample;
	std::uintptr_t names = 0U;
	std::int32_t name_count = 0;
	if(!read_value(reader, names_global, names) ||
		!read_value(reader, names + name_count_offset, name_count))
	{
		return sample;
	}

	const auto available = static_cast<std::size_t>(array.count);
	const auto slots = available < limit ? available : limit;
	for(std::size_t index = 0U; index < slots; ++index)
	{
		const auto chunk_index = index / static_cast<std::size_t>(object_chunk_entries);
		const auto item_index = index % static_cast<std::size_t>(object_chunk_entries);
		std::uintptr_t chunk = 0U;
		std::uintptr_t object = 0U;
		if(!read_value(reader, array.chunks + chunk_index * sizeof(std::uintptr_t), chunk) ||
			!aligned_pointer(chunk) ||
			!read_value(reader, chunk + item_index * object_item_stride, object) ||
			!aligned_pointer(object))
		{
			continue;
		}

		std::uint32_t flags = 0U;
		std::int32_t internal_index = 0;
		std::uintptr_t type = 0U;
		std::int32_t name_index = 0;
		std::int32_t name_number = 0;
		std::uintptr_t outer = 0U;
		std::int32_t type_name_index = 0;
		if(!read_value(reader, object + 8U, flags) ||
			!read_value(reader, object + 12U, internal_index) ||
			internal_index != static_cast<std::int32_t>(index) ||
			!read_value(reader, object + 16U, type) ||
			!read_value(reader, object + 24U, name_index) ||
			!read_value(reader, object + 28U, name_number) ||
			!read_value(reader, object + 32U, outer))
		{
			continue;
		}
		const auto name = resolve_name(reader, names, name_count, name_index);
		if(!name)
		{
			continue;
		}
		std::string type_name;
		if(aligned_pointer(type) && read_value(reader, type + 24U, type_name_index))
		{
			if(const auto resolved = resolve_name(reader, names, name_count, type_name_index))
			{
				type_name = *resolved;
			}
		}
		sample.push_back(ObjectSample {
			.index = static_cast<std::int32_t>(index),
			.object = object,
			.flags = flags,
			.type = type,
			.name_index = name_index,
			.name_number = name_number,
			.outer = outer,
			.name = *name,
			.type_name = std::move(type_name),
		});
	}
	return sample;
}

/// Formats a bounded JSON reflection report.
std::string object_discovery_json(
	const std::optional<ObjectArrayInfo>& array,
	const std::vector<ObjectSample>& sample)
{
	std::string json = "{\"count\":";
	json += std::to_string(array ? array->count : 0);
	json += ",\"capacity\":";
	json += std::to_string(array ? array->capacity : 0);
	json += ",\"chunks\":";
	json += std::to_string(array ? array->chunk_count : 0);
	json += ",\"sample\":[";
	for(std::size_t index = 0U; index < sample.size(); ++index)
	{
		if(index != 0U)
		{
			json.push_back(',');
		}
		const auto& object = sample[index];
		json += "{\"index\":";
		json += std::to_string(object.index);
		json += ",\"object\":";
		append_hex(json, object.object);
		json += ",\"flags\":";
		json += std::to_string(object.flags);
		json += ",\"type\":";
		append_json_string(json, object.type_name);
		json += ",\"name\":";
		append_json_string(json, object.name);
		json += ",\"name_index\":";
		json += std::to_string(object.name_index);
		json += ",\"outer\":";
		append_hex(json, object.outer);
		json.push_back('}');
	}
	json += "]}";
	return json;
}
}
