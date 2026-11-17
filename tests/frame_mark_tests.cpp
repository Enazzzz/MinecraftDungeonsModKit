#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

#include "mcd/frame_overlay.hpp"
#include "mcd/x64_prologue.hpp"

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

/// Verifies the live DXGI Present prologue can be relocated as 14 whole bytes.
void test_present_prologue()
{
	const std::byte present[] {
		std::byte {0x48}, std::byte {0x89}, std::byte {0x5C}, std::byte {0x24}, std::byte {0x10},
		std::byte {0x48}, std::byte {0x89}, std::byte {0x74}, std::byte {0x24}, std::byte {0x18},
		std::byte {0x55}, std::byte {0x57}, std::byte {0x41}, std::byte {0x56},
		std::byte {0x48}, std::byte {0x8D}, std::byte {0x6C}, std::byte {0x24}, std::byte {0x90},
	};
	REQUIRE(mcd::steal_size(present, 14U) == 14U);
	const std::byte relative[] {
		std::byte {0x48}, std::byte {0x8D}, std::byte {0x0D}, std::byte {0x00},
		std::byte {0x00}, std::byte {0x00}, std::byte {0x00},
	};
	REQUIRE(!mcd::steal_size(relative, 5U).has_value());
	REQUIRE(!mcd::steal_size(std::span<const std::byte>(present, 10U), 14U).has_value());
}

/// Verifies the corner mark has a dark field and a lit text pixel.
void test_runtime_mark()
{
	const mcd::OverlayImage image = mcd::make_runtime_mark();
	REQUIRE(image.width > 32U);
	REQUIRE(image.height > 16U);
	REQUIRE(image.rgba.size() == static_cast<std::size_t>(image.width) * image.height * 4U);
	REQUIRE(image.rgba[0] < 40U);
	const auto text = (static_cast<std::size_t>(8U) * image.width + 8U) * 4U;
	REQUIRE(image.rgba[text] == 255U);
}
}

/// Runs the frame-mark regression checks.
int main()
{
	try
	{
		test_present_prologue();
		test_runtime_mark();
	}
	catch(const std::exception&)
	{
		return 1;
	}
	return 0;
}
