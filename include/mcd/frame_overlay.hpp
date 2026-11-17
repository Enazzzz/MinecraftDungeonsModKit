#pragma once

#include <cstdint>
#include <vector>

namespace mcd
{
/// Holds one CPU-side image of the runtime corner mark.
struct OverlayImage
{
	std::uint32_t width {};
	std::uint32_t height {};
	std::vector<std::uint8_t> rgba;
};

/// Rasterizes the "mcd runtime" corner mark into an opaque RGBA image.
[[nodiscard]] OverlayImage make_runtime_mark();
}
