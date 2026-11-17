#include "mcd/runtime/frame_mark.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mcd/frame_overlay.hpp"
#include "mcd/x64_prologue.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

namespace
{
using PresentFunction = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);
using Present1Function = HRESULT(STDMETHODCALLTYPE*)(
	IDXGISwapChain1*,
	UINT,
	UINT,
	const DXGI_PRESENT_PARAMETERS*);

void note(const std::string& text);

PresentFunction original_present = nullptr;
Present1Function original_present1 = nullptr;
std::atomic<bool> mark_enabled {false};
std::mutex draw_mutex;
Microsoft::WRL::ComPtr<ID3D11Texture2D> overlay_texture;
ID3D11Device* overlay_device = nullptr;
DXGI_FORMAT overlay_format = DXGI_FORMAT_UNKNOWN;

/// Suspends every other thread in this process and resumes them on destruction.
class SuspendedThreads
{
public:
	/// Suspends other process threads so a code patch cannot tear an instruction.
	SuspendedThreads()
	{
		const DWORD self = GetCurrentThreadId();
		const DWORD process_id = GetCurrentProcessId();
		const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U);
		if(snapshot == INVALID_HANDLE_VALUE)
		{
			return;
		}
		THREADENTRY32 entry {};
		entry.dwSize = sizeof(entry);
		if(!Thread32First(snapshot, &entry))
		{
			CloseHandle(snapshot);
			return;
		}
		do
		{
			if(entry.th32OwnerProcessID != process_id || entry.th32ThreadID == self)
			{
				continue;
			}
			const HANDLE thread = OpenThread(
				THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
				FALSE,
				entry.th32ThreadID);
			if(thread == nullptr)
			{
				continue;
			}
			if(SuspendThread(thread) == static_cast<DWORD>(-1))
			{
				CloseHandle(thread);
				resume();
				CloseHandle(snapshot);
				return;
			}
			threads_.push_back(thread);
		} while(Thread32Next(snapshot, &entry));
		CloseHandle(snapshot);
		armed_ = true;
	}

	/// Resumes any threads this object still holds.
	~SuspendedThreads()
	{
		resume();
	}

	/// Reports whether every attempted suspension succeeded.
	[[nodiscard]] bool armed() const noexcept
	{
		return armed_;
	}

	/// Returns whether no suspended thread is executing inside the patch window.
	[[nodiscard]] bool instruction_pointer_clear(const void* address, const std::size_t size) const
	{
		const auto begin = reinterpret_cast<std::uintptr_t>(address);
		const auto end = begin + size;
		for(const HANDLE thread : threads_)
		{
			CONTEXT context {};
			context.ContextFlags = CONTEXT_CONTROL;
			if(!GetThreadContext(thread, &context))
			{
				return false;
			}
			if(context.Rip >= begin && context.Rip < end)
			{
				return false;
			}
		}
		return true;
	}

	SuspendedThreads(const SuspendedThreads&) = delete;
	SuspendedThreads& operator=(const SuspendedThreads&) = delete;

private:
	/// Resumes and closes every suspended thread exactly once.
	void resume() noexcept
	{
		for(const HANDLE thread : threads_)
		{
			ResumeThread(thread);
			CloseHandle(thread);
		}
		threads_.clear();
	}

	std::vector<HANDLE> threads_;
	bool armed_ {false};
};

/// Writes a 14-byte indirect jump to an absolute address.
void write_absolute_jump(std::byte* destination, const void* target)
{
	destination[0] = std::byte {0xFF};
	destination[1] = std::byte {0x25};
	std::memset(destination + 2, 0, 4U);
	std::memcpy(destination + 6, &target, sizeof(target));
}

/// Allocates executable memory close enough for a direct 32-bit jump.
std::byte* allocate_near(const void* target, const std::size_t size)
{
	SYSTEM_INFO information {};
	GetSystemInfo(&information);
	const auto step = static_cast<std::uintptr_t>(information.dwAllocationGranularity);
	const auto origin = reinterpret_cast<std::uintptr_t>(target) & ~(step - 1U);
	for(std::uintptr_t distance = step; distance < 0x70000000ULL; distance += step * 16U)
	{
		for(const std::intptr_t sign : {std::intptr_t {1}, std::intptr_t {-1}})
		{
			if(sign < 0 && distance > origin)
			{
				continue;
			}
			const auto address = static_cast<std::uintptr_t>(
				static_cast<std::intptr_t>(origin) + sign * static_cast<std::intptr_t>(distance));
			auto* memory = static_cast<std::byte*>(VirtualAlloc(
				reinterpret_cast<void*>(address),
				size,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE));
			if(memory != nullptr)
			{
				return memory;
			}
		}
	}
	return nullptr;
}

/// Builds a nearby trampoline that runs stolen bytes and jumps directly back.
void* create_trampoline(const void* target, const std::size_t stolen)
{
	auto* memory = allocate_near(target, stolen + 5U);
	if(memory == nullptr)
	{
		return nullptr;
	}
	std::memcpy(memory, target, stolen);
	const auto return_address = static_cast<const std::byte*>(target) + stolen;
	const auto next_instruction = memory + stolen + 5U;
	const auto displacement = return_address - next_instruction;
	if(displacement < static_cast<std::ptrdiff_t>(INT32_MIN) ||
		displacement > static_cast<std::ptrdiff_t>(INT32_MAX))
	{
		VirtualFree(memory, 0U, MEM_RELEASE);
		return nullptr;
	}
	memory[stolen] = std::byte {0xE9};
	const auto relative = static_cast<std::int32_t>(displacement);
	std::memcpy(memory + stolen + 1U, &relative, sizeof(relative));
	DWORD previous = 0U;
	if(VirtualProtect(memory, stolen + 5U, PAGE_EXECUTE_READ, &previous) == 0)
	{
		return nullptr;
	}
	FlushInstructionCache(GetCurrentProcess(), memory, stolen + 5U);
	return memory;
}

/// Replaces the target prologue with a jump while other threads are suspended.
bool patch_prologue(void* target, void* replacement, void** trampoline_slot)
{
	std::byte prologue[32] {};
	std::memcpy(prologue, target, sizeof(prologue));
	const auto stolen = mcd::steal_size(prologue, 14U);
	if(!stolen)
	{
		return false;
	}
	void* trampoline = create_trampoline(target, *stolen);
	if(trampoline == nullptr)
	{
		return false;
	}

	SuspendedThreads suspended;
	if(!suspended.armed() || !suspended.instruction_pointer_clear(target, *stolen))
	{
		return false;
	}
	DWORD previous = 0U;
	if(VirtualProtect(target, *stolen, PAGE_EXECUTE_READWRITE, &previous) == 0)
	{
		return false;
	}
	std::vector<std::byte> patch(*stolen, std::byte {0x90});
	const auto next_instruction = static_cast<const std::byte*>(target) + 5U;
	const auto hook_displacement = static_cast<const std::byte*>(replacement) - next_instruction;
	if(hook_displacement >= static_cast<std::ptrdiff_t>(INT32_MIN) &&
		hook_displacement <= static_cast<std::ptrdiff_t>(INT32_MAX))
	{
		patch[0] = std::byte {0xE9};
		const auto relative = static_cast<std::int32_t>(hook_displacement);
		std::memcpy(patch.data() + 1U, &relative, sizeof(relative));
	}
	else
	{
		write_absolute_jump(patch.data(), replacement);
	}
	std::memcpy(target, patch.data(), patch.size());
	DWORD restored = 0U;
	VirtualProtect(target, *stolen, previous, &restored);
	FlushInstructionCache(GetCurrentProcess(), target, *stolen);
	*trampoline_slot = trampoline;
	return true;
}

/// Points an existing absolute jump at the replacement and returns its old target.
bool retarget_absolute_jump(void* target, void* replacement, void** previous_target)
{
	const auto* bytes = static_cast<const std::byte*>(target);
	std::byte head[14] {};
	std::memcpy(head, bytes, sizeof(head));
	if(head[0] != std::byte {0xFF} || head[1] != std::byte {0x25})
	{
		return false;
	}
	std::int32_t displacement = 0;
	std::memcpy(&displacement, head + 2, sizeof(displacement));
	if(displacement != 0)
	{
		return false;
	}
	auto* slot = reinterpret_cast<void**>(static_cast<std::byte*>(target) + 6);
	SuspendedThreads suspended;
	if(!suspended.armed() || !suspended.instruction_pointer_clear(target, sizeof(head)))
	{
		return false;
	}
	DWORD previous = 0U;
	if(VirtualProtect(slot, sizeof(void*), PAGE_EXECUTE_READWRITE, &previous) == 0)
	{
		return false;
	}
	*previous_target = *slot;
	*slot = replacement;
	DWORD restored = 0U;
	VirtualProtect(slot, sizeof(void*), previous, &restored);
	FlushInstructionCache(GetCurrentProcess(), target, sizeof(head));
	return *previous_target != nullptr;
}

/// Installs one hook, chaining an existing absolute jump when one is already present.
bool install_hook(void* target, void* replacement, void** original, const int depth)
{
	if(target == nullptr || replacement == nullptr || original == nullptr || depth > 1)
	{
		return false;
	}
	std::byte head[2] {};
	std::memcpy(head, target, sizeof(head));
	if(head[0] == std::byte {0xFF} && head[1] == std::byte {0x25})
	{
		return retarget_absolute_jump(target, replacement, original);
	}
	if(head[0] == std::byte {0xE9})
	{
		std::int32_t displacement = 0;
		std::memcpy(&displacement, static_cast<std::byte*>(target) + 1, sizeof(displacement));
		auto* followed = static_cast<std::byte*>(target) + 5 + displacement;
		return install_hook(followed, replacement, original, depth + 1);
	}
	return patch_prologue(target, replacement, original);
}

/// Returns the byte order used by one supported 8-bit swap-chain format.
std::optional<bool> format_is_bgra(const DXGI_FORMAT format)
{
	if(format == DXGI_FORMAT_B8G8R8A8_UNORM || format == DXGI_FORMAT_B8G8R8A8_UNORM_SRGB)
	{
		return true;
	}
	if(format == DXGI_FORMAT_R8G8B8A8_UNORM || format == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB)
	{
		return false;
	}
	return std::nullopt;
}

/// Creates the staging texture for the current device and fill it once.
bool ensure_overlay(ID3D11Device* device, ID3D11DeviceContext* context, const DXGI_FORMAT format)
{
	if(overlay_texture && overlay_device == device && overlay_format == format)
	{
		return true;
	}
	overlay_texture.Reset();
	overlay_device = nullptr;
	overlay_format = DXGI_FORMAT_UNKNOWN;
	const auto order = format_is_bgra(format);
	if(!order)
	{
		return false;
	}
	const mcd::OverlayImage image = mcd::make_runtime_mark();
	D3D11_TEXTURE2D_DESC description {};
	description.Width = image.width;
	description.Height = image.height;
	description.MipLevels = 1U;
	description.ArraySize = 1U;
	description.Format = format;
	description.SampleDesc.Count = 1U;
	description.Usage = D3D11_USAGE_DEFAULT;
	std::vector<std::uint8_t> pixels(static_cast<std::size_t>(image.width) * image.height * 4U);
	for(std::size_t pixel_index = 0U; pixel_index < pixels.size(); pixel_index += 4U)
	{
		const auto red = image.rgba[pixel_index + 0U];
		const auto green = image.rgba[pixel_index + 1U];
		const auto blue = image.rgba[pixel_index + 2U];
		const auto alpha = image.rgba[pixel_index + 3U];
		if(*order)
		{
			pixels[pixel_index + 0U] = blue;
			pixels[pixel_index + 1U] = green;
			pixels[pixel_index + 2U] = red;
			pixels[pixel_index + 3U] = alpha;
		}
		else
		{
			pixels[pixel_index + 0U] = red;
			pixels[pixel_index + 1U] = green;
			pixels[pixel_index + 2U] = blue;
			pixels[pixel_index + 3U] = alpha;
		}
	}
	Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
	if(FAILED(device->CreateTexture2D(&description, nullptr, texture.GetAddressOf())))
	{
		return false;
	}
	context->UpdateSubresource(
		texture.Get(),
		0U,
		nullptr,
		pixels.data(),
		image.width * 4U,
		0U);
	overlay_texture = std::move(texture);
	overlay_device = device;
	overlay_format = format;
	return true;
}

/// Copies the corner mark onto one swap-chain back buffer.
void draw_mark(IDXGISwapChain* swap)
{
	if(!mark_enabled.load(std::memory_order_acquire) || swap == nullptr)
	{
		return;
	}
	thread_local bool drawing = false;
	if(drawing)
	{
		return;
	}
	drawing = true;
	const std::scoped_lock lock(draw_mutex);
	Microsoft::WRL::ComPtr<ID3D11Device> device;
	if(FAILED(swap->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void**>(device.GetAddressOf()))))
	{
		drawing = false;
		return;
	}
	Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
	device->GetImmediateContext(context.GetAddressOf());
	Microsoft::WRL::ComPtr<ID3D11Texture2D> buffer;
	if(!context || FAILED(swap->GetBuffer(0U, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(buffer.GetAddressOf()))))
	{
		drawing = false;
		return;
	}
	D3D11_TEXTURE2D_DESC description {};
	buffer->GetDesc(&description);
	if(description.SampleDesc.Count != 1U || description.Width < 320U || description.Height < 240U ||
		!ensure_overlay(device.Get(), context.Get(), description.Format))
	{
		drawing = false;
		return;
	}
	D3D11_BOX box {};
	box.left = 0U;
	box.top = 0U;
	box.front = 0U;
	box.right = 0U;
	box.bottom = 0U;
	box.back = 1U;
	D3D11_TEXTURE2D_DESC overlay_description {};
	overlay_texture->GetDesc(&overlay_description);
	box.right = overlay_description.Width;
	box.bottom = overlay_description.Height;
	context->CopySubresourceRegion(buffer.Get(), 0U, 24U, 24U, 0U, overlay_texture.Get(), 0U, &box);
	static std::atomic<bool> noted {false};
	if(!noted.exchange(true))
	{
		note("drew format " + std::to_string(static_cast<int>(description.Format)));
	}
	drawing = false;
}

/// Draws the mark and forwards one IDXGISwapChain::Present call.
HRESULT STDMETHODCALLTYPE present_hook(IDXGISwapChain* swap, const UINT sync, const UINT flags)
{
	draw_mark(swap);
	if(original_present == nullptr)
	{
		return E_FAIL;
	}
	return original_present(swap, sync, flags);
}

/// Draws the mark and forwards one IDXGISwapChain1::Present1 call.
HRESULT STDMETHODCALLTYPE present1_hook(
	IDXGISwapChain1* swap,
	const UINT sync,
	const UINT flags,
	const DXGI_PRESENT_PARAMETERS* parameters)
{
	draw_mark(swap);
	if(original_present1 == nullptr)
	{
		return E_FAIL;
	}
	return original_present1(swap, sync, flags, parameters);
}

/// Appends one diagnostic line for the frame-mark install.
void note(const std::string& text)
{
	wchar_t local_app_data[MAX_PATH] {};
	const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH);
	if(length == 0U || length >= MAX_PATH)
	{
		return;
	}
	const std::wstring directory = std::wstring(local_app_data) + L"\\mcd";
	CreateDirectoryW(directory.c_str(), nullptr);
	const std::wstring path = directory + L"\\frame-mark.log";
	const HANDLE file = CreateFileW(
		path.c_str(),
		FILE_APPEND_DATA,
		FILE_SHARE_READ,
		nullptr,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if(file == INVALID_HANDLE_VALUE)
	{
		return;
	}
	const std::string line = text + "\r\n";
	DWORD written = 0U;
	WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
	CloseHandle(file);
}

/// Returns whether a pointer can be read for the requested size.
bool readable(const void* address, const std::size_t size)
{
	MEMORY_BASIC_INFORMATION information {};
	if(VirtualQuery(address, &information, sizeof(information)) == 0U)
	{
		return false;
	}
	const auto begin = reinterpret_cast<std::uintptr_t>(information.BaseAddress);
	const auto end = begin + information.RegionSize;
	const auto value = reinterpret_cast<std::uintptr_t>(address);
	return information.State == MEM_COMMIT &&
		(information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0U &&
		value >= begin && size <= end - value;
}

/// Finds a swap-chain Present that Steam replaced, falling back to DXGI's own Present.
void* find_live_present(void** real_vtable)
{
	const auto real_present = real_vtable[8];
	const auto real_get_device = real_vtable[7];
	const auto real_get_buffer = real_vtable[9];
	std::uintptr_t address = 0U;
	while(true)
	{
		MEMORY_BASIC_INFORMATION information {};
		if(VirtualQuery(reinterpret_cast<void*>(address), &information, sizeof(information)) == 0U)
		{
			break;
		}
		const auto begin = reinterpret_cast<std::uintptr_t>(information.BaseAddress);
		const auto end = begin + information.RegionSize;
		const bool scannable = information.State == MEM_COMMIT &&
			(information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0U &&
			information.RegionSize <= 64U * 1024U * 1024U;
		if(scannable)
		{
			for(std::uintptr_t cursor = begin; cursor + sizeof(void*) <= end; cursor += sizeof(void*))
			{
				void* value = nullptr;
				std::memcpy(&value, reinterpret_cast<const void*>(cursor), sizeof(value));
				if(value != real_get_buffer)
				{
					continue;
				}
				auto* vtable = reinterpret_cast<void**>(cursor - 9U * sizeof(void*));
				if(!readable(vtable, 10U * sizeof(void*)))
				{
					continue;
				}
				if(vtable[7] == real_get_device && vtable[8] != nullptr && vtable[8] != real_present)
				{
					return vtable[8];
				}
			}
		}
		if(end <= address)
		{
			break;
		}
		address = end;
	}
	return real_present;
}

/// Reads one slot from a COM vtable.
void* vtable_slot(IUnknown* object, const std::size_t index)
{
	return (*reinterpret_cast<void***>(object))[index];
}

/// Creates a hidden device solely to discover the process-wide DXGI vtable.
bool discover_present_targets(void** present, void** present1)
{
	WNDCLASSW window_class {};
	window_class.lpfnWndProc = DefWindowProcW;
	window_class.hInstance = GetModuleHandleW(nullptr);
	window_class.lpszClassName = L"mcd_frame_mark_probe";
	RegisterClassW(&window_class);
	const HWND window = CreateWindowExW(
		0U,
		window_class.lpszClassName,
		L"mcd",
		0U,
		0,
		0,
		8,
		8,
		nullptr,
		nullptr,
		window_class.hInstance,
		nullptr);
	if(window == nullptr)
	{
		return false;
	}
	DXGI_SWAP_CHAIN_DESC description {};
	description.BufferDesc.Width = 8U;
	description.BufferDesc.Height = 8U;
	description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	description.SampleDesc.Count = 1U;
	description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	description.BufferCount = 2U;
	description.OutputWindow = window;
	description.Windowed = TRUE;
	description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
	Microsoft::WRL::ComPtr<IDXGISwapChain> swap;
	Microsoft::WRL::ComPtr<ID3D11Device> device;
	Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
	const HRESULT created = D3D11CreateDeviceAndSwapChain(
		nullptr,
		D3D_DRIVER_TYPE_HARDWARE,
		nullptr,
		0U,
		nullptr,
		0U,
		D3D11_SDK_VERSION,
		&description,
		swap.GetAddressOf(),
		device.GetAddressOf(),
		nullptr,
		context.GetAddressOf());
	bool found = false;
	if(SUCCEEDED(created) && swap)
	{
		*present = vtable_slot(swap.Get(), 8U);
		Microsoft::WRL::ComPtr<IDXGISwapChain1> swap1;
		if(SUCCEEDED(swap.As(&swap1)))
		{
			*present1 = vtable_slot(swap1.Get(), 22U);
		}
		found = *present != nullptr;
	}
	swap.Reset();
	context.Reset();
	device.Reset();
	DestroyWindow(window);
	UnregisterClassW(window_class.lpszClassName, window_class.hInstance);
	return found;
}
}

namespace mcd::runtime
{
/// Hooks DXGI Present and copies the runtime mark into the game's back buffer.
bool install_frame_mark() noexcept
{
	try
	{
		void* present = nullptr;
		void* present1 = nullptr;
		if(!discover_present_targets(&present, &present1))
		{
			note("discover failed");
			return false;
		}
		void* live_present = present;
		{
			WNDCLASSW window_class {};
			window_class.lpfnWndProc = DefWindowProcW;
			window_class.hInstance = GetModuleHandleW(nullptr);
			window_class.lpszClassName = L"mcd_frame_mark_probe";
			const HWND window = CreateWindowExW(
				0U, window_class.lpszClassName, L"mcd", 0U, 0, 0, 8, 8, nullptr, nullptr, window_class.hInstance, nullptr);
			DXGI_SWAP_CHAIN_DESC description {};
			description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
			description.SampleDesc.Count = 1U;
			description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
			description.BufferCount = 2U;
			description.OutputWindow = window;
			description.Windowed = TRUE;
			Microsoft::WRL::ComPtr<ID3D11Device> device;
			Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
			Microsoft::WRL::ComPtr<IDXGISwapChain> swap;
			if(window != nullptr && SUCCEEDED(D3D11CreateDeviceAndSwapChain(
				nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0U, nullptr, 0U, D3D11_SDK_VERSION,
				&description, swap.GetAddressOf(), device.GetAddressOf(), nullptr, context.GetAddressOf())) && swap)
			{
				live_present = find_live_present(*reinterpret_cast<void***>(swap.Get()));
			}
			DestroyWindow(window);
		}
		note(live_present == present ? "hooking dxgi present" : "hooking replaced present");
		if(!install_hook(live_present, reinterpret_cast<void*>(&present_hook), reinterpret_cast<void**>(&original_present), 0))
		{
			note("hook failed");
			return false;
		}
		if(present1 != nullptr && live_present == present)
		{
			(void)install_hook(
				present1,
				reinterpret_cast<void*>(&present1_hook),
				reinterpret_cast<void**>(&original_present1),
				0);
		}
		mark_enabled.store(true, std::memory_order_release);
		note("hook installed");
		return true;
	}
	catch(...)
	{
		mark_enabled.store(false, std::memory_order_release);
		return false;
	}
}
}
