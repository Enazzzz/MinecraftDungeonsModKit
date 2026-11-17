#include "mcd/frame_overlay.hpp"

#include <cstring>
#include <string_view>

namespace
{
constexpr std::uint32_t glyph_scale = 3U;
constexpr std::uint32_t glyph_gap = 2U;
constexpr std::uint32_t padding = 8U;

/// Returns the seven rows of one 5-pixel glyph. Bit 4 is the left pixel.
const std::uint8_t* glyph_rows(const char character)
{
	switch(character)
	{
	case 'c': {
		static constexpr std::uint8_t rows[] {0x0EU, 0x11U, 0x10U, 0x10U, 0x10U, 0x11U, 0x0EU};
		return rows;
	}
	case 'd': {
		static constexpr std::uint8_t rows[] {0x1EU, 0x11U, 0x11U, 0x11U, 0x11U, 0x11U, 0x1EU};
		return rows;
	}
	case 'e': {
		static constexpr std::uint8_t rows[] {0x0EU, 0x11U, 0x11U, 0x1FU, 0x10U, 0x11U, 0x0EU};
		return rows;
	}
	case 'i': {
		static constexpr std::uint8_t rows[] {0x04U, 0x00U, 0x04U, 0x04U, 0x04U, 0x04U, 0x04U};
		return rows;
	}
	case 'm': {
		static constexpr std::uint8_t rows[] {0x1DU, 0x15U, 0x15U, 0x15U, 0x15U, 0x15U, 0x15U};
		return rows;
	}
	case 'n': {
		static constexpr std::uint8_t rows[] {0x1EU, 0x11U, 0x11U, 0x11U, 0x11U, 0x11U, 0x11U};
		return rows;
	}
	case 'r': {
		static constexpr std::uint8_t rows[] {0x1EU, 0x11U, 0x11U, 0x1EU, 0x14U, 0x12U, 0x11U};
		return rows;
	}
	case 't': {
		static constexpr std::uint8_t rows[] {0x1FU, 0x04U, 0x04U, 0x04U, 0x04U, 0x04U, 0x04U};
		return rows;
	}
	case 'u': {
		static constexpr std::uint8_t rows[] {0x11U, 0x11U, 0x11U, 0x11U, 0x11U, 0x11U, 0x0EU};
		return rows;
	}
	case ' ': {
		static constexpr std::uint8_t rows[] {0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
		return rows;
	}
	default: {
		return nullptr;
	}
	}
}

/// Paints one scaled glyph pixel into the RGBA image.
void fill_pixel(
	mcd::OverlayImage& image,
	const std::uint32_t x,
	const std::uint32_t y,
	const std::uint8_t red,
	const std::uint8_t green,
	const std::uint8_t blue)
{
	if(x >= image.width || y >= image.height)
	{
		return;
	}
	const auto offset = (static_cast<std::size_t>(y) * image.width + x) * 4U;
	image.rgba[offset + 0U] = red;
	image.rgba[offset + 1U] = green;
	image.rgba[offset + 2U] = blue;
	image.rgba[offset + 3U] = 255U;
}
}

namespace mcd
{
/// Rasterizes the "mcd runtime" corner mark into an opaque RGBA image.
OverlayImage make_runtime_mark()
{
	constexpr std::string_view text = "mcd runtime";
	const auto glyph_width = 5U * glyph_scale;
	const auto glyph_height = 7U * glyph_scale;
	OverlayImage image;
	image.width = padding * 2U + static_cast<std::uint32_t>(text.size()) * (glyph_width + glyph_gap);
	image.height = padding * 2U + glyph_height;
	image.rgba.assign(static_cast<std::size_t>(image.width) * image.height * 4U, 0U);
	for(std::uint32_t y = 0U; y < image.height; ++y)
	{
		for(std::uint32_t x = 0U; x < image.width; ++x)
		{
			fill_pixel(image, x, y, 12U, 12U, 12U);
		}
	}

	std::uint32_t cursor = padding;
	for(const char character : text)
	{
		const auto* rows = glyph_rows(character);
		if(rows != nullptr)
		{
			for(std::uint32_t row = 0U; row < 7U; ++row)
			{
				for(std::uint32_t column = 0U; column < 5U; ++column)
				{
					const auto bit = static_cast<std::uint8_t>(0x10U >> column);
					if((rows[row] & bit) == 0U)
					{
						continue;
					}
					for(std::uint32_t sy = 0U; sy < glyph_scale; ++sy)
					{
						for(std::uint32_t sx = 0U; sx < glyph_scale; ++sx)
						{
							fill_pixel(
								image,
								cursor + column * glyph_scale + sx,
								padding + row * glyph_scale + sy,
								255U,
								255U,
								255U);
						}
					}
				}
			}
		}
		cursor += glyph_width + glyph_gap;
	}
	return image;
}
}
