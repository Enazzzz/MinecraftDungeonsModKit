#pragma once

namespace mcd::runtime
{
/// Hooks DXGI Present and copies the runtime mark into the game's back buffer.
[[nodiscard]] bool install_frame_mark() noexcept;
}
