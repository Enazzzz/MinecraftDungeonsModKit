#include <array>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

#include "mcd/build_identity.hpp"
#include "mcd/launcher/injector.hpp"
#include "mcd/launcher/pipe_client.hpp"
#include "mcd/launcher/process.hpp"
#include "mcd/sha256.hpp"

namespace
{
enum class ExitCode
{
	success = 0,
	usage = 2,
	file_error = 3,
	unsupported_build = 4,
	process_error = 5,
	injection_error = 6,
	status_error = 7,
};

/// Captures the canonical path and exact supported-build measurement.
struct Inspection
{
	std::filesystem::path path;
	std::uint64_t size;
	mcd::Sha256Digest digest;
	std::optional<mcd::BuildProfile> profile;
};

/// Converts a SHA-256 digest to stable uppercase hexadecimal text.
std::wstring digest_text(const mcd::Sha256Digest& digest)
{
	constexpr std::array<wchar_t, 16> digits {
		L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7',
		L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F',
	};
	std::wstring text;
	text.reserve(digest.size() * 2U);
	for(const std::byte value : digest)
	{
		const auto byte = std::to_integer<unsigned int>(value);
		text.push_back(digits[(byte >> 4U) & 0x0FU]);
		text.push_back(digits[byte & 0x0FU]);
	}
	return text;
}

/// Measures and identifies one exact executable without modifying it.
std::optional<Inspection> inspect_file(const std::filesystem::path& requested_path)
{
	std::error_code canonical_error;
	const auto path = std::filesystem::canonical(requested_path, canonical_error);
	if(canonical_error)
	{
		std::wcerr << L"error: executable path could not be canonicalized ("
				   << canonical_error.value() << L")\n";
		return std::nullopt;
	}

	std::error_code status_error;
	if(!std::filesystem::is_regular_file(path, status_error) || status_error)
	{
		std::wcerr << L"error: executable path is not a regular file\n";
		return std::nullopt;
	}

	std::error_code size_error;
	const auto size = std::filesystem::file_size(path, size_error);
	if(size_error)
	{
		std::wcerr << L"error: executable size could not be read ("
				   << size_error.value() << L")\n";
		return std::nullopt;
	}
	const auto digest = mcd::sha256_file(path);
	if(!digest)
	{
		std::wcerr << L"error: executable SHA-256 failed ("
				   << digest.error().value() << L")\n";
		return std::nullopt;
	}

	return Inspection {
		.path = path,
		.size = static_cast<std::uint64_t>(size),
		.digest = *digest,
		.profile = mcd::identify_build(size, *digest),
	};
}

/// Prints the stable exact-file inspection report.
void print_inspection(const Inspection& inspection)
{
	std::wcout << L"path: " << inspection.path.native() << L'\n'
			   << L"size: " << inspection.size << L'\n'
			   << L"sha256: " << digest_text(inspection.digest) << L'\n'
			   << L"profile: ";
	if(inspection.profile)
	{
		std::wcout << std::wstring(
			inspection.profile->id.begin(),
			inspection.profile->id.end());
	}
	else
	{
		std::wcout << L"unsupported";
	}
	std::wcout << L'\n';
}

/// Prints the supported command syntax.
void print_usage()
{
	std::wcerr
		<< L"usage:\n"
		<< L"  mcd-launcher inspect <game-exe>\n"
		<< L"  mcd-launcher inject <game-exe> <runtime-dll>\n"
		<< L"  mcd-launcher status <pid>\n"
		<< L"  mcd-launcher objects <pid>\n";
}

/// Runs exact-file inspection and reports whether the build is supported.
ExitCode run_inspect(const std::filesystem::path& game_path)
{
	const auto inspection = inspect_file(game_path);
	if(!inspection)
	{
		return ExitCode::file_error;
	}
	print_inspection(*inspection);
	return inspection->profile ? ExitCode::success : ExitCode::unsupported_build;
}

/// Validates the file, selects its exact process, and injects the runtime.
ExitCode run_inject(
	const std::filesystem::path& game_path,
	const std::filesystem::path& runtime_path)
{
	const auto inspection = inspect_file(game_path);
	if(!inspection)
	{
		return ExitCode::file_error;
	}
	if(!inspection->profile)
	{
		std::wcerr << L"error: executable fingerprint is unsupported\n";
		return ExitCode::unsupported_build;
	}

	const auto validated_runtime =
		mcd::launcher::validate_runtime_path(runtime_path);
	if(!validated_runtime)
	{
		const mcd::launcher::InjectFailure failure {
			.error = validated_runtime.error(),
			.win32_error = ERROR_INVALID_PARAMETER,
		};
		const auto message = mcd::launcher::inject_error_message(failure);
		std::wcerr << L"error: " << std::wstring(message.begin(), message.end()) << L'\n';
		return ExitCode::injection_error;
	}

	const auto process = mcd::launcher::find_process(inspection->path);
	if(!process)
	{
		const auto message = mcd::launcher::process_error_message(process.error());
		std::wcerr << L"error: " << std::wstring(message.begin(), message.end())
				   << L" (" << process.error().win32_error << L")\n";
		return ExitCode::process_error;
	}

	const auto result = mcd::launcher::inject_runtime(
		*process,
		inspection->path,
		std::wstring(
			inspection->profile->id.begin(),
			inspection->profile->id.end()),
		*validated_runtime);
	if(!result)
	{
		const auto message = mcd::launcher::inject_error_message(result.error());
		std::wcerr << L"error: " << std::wstring(message.begin(), message.end())
				   << L" (" << result.error().win32_error << L")\n";
		return ExitCode::injection_error;
	}

	std::wcout << (result == mcd::launcher::InjectionResult::already_loaded
			? L"runtime already loaded"
			: L"runtime injected")
			   << L" into process " << process->id << L'\n';
	return ExitCode::success;
}

/// Queries and prints one current-user runtime status response.
ExitCode run_status(const wchar_t* process_id_text)
{
	const auto process_id = mcd::launcher::parse_process_id(process_id_text);
	if(!process_id)
	{
		std::wcerr << L"error: process ID must be a nonzero decimal integer\n";
		return ExitCode::usage;
	}

	const auto status = mcd::launcher::query_status(*process_id);
	if(!status)
	{
		const auto message = mcd::launcher::pipe_error_message(status.error());
		std::wcerr << L"error: " << std::wstring(message.begin(), message.end())
				   << L" (" << status.error().win32_error << L")\n";
		return ExitCode::status_error;
	}
	std::wcout << std::wstring(status->begin(), status->end()) << L'\n';
	return ExitCode::success;
}

/// Queries and prints the validated Unreal object-array report.
ExitCode run_objects(const wchar_t* process_id_text)
{
	const auto process_id = mcd::launcher::parse_process_id(process_id_text);
	if(!process_id)
	{
		std::wcerr << L"error: process ID must be a nonzero decimal integer\n";
		return ExitCode::usage;
	}

	const auto report = mcd::launcher::query_objects(*process_id);
	if(!report)
	{
		const auto message = mcd::launcher::pipe_error_message(report.error());
		std::wcerr << L"error: " << std::wstring(message.begin(), message.end())
				   << L" (" << report.error().win32_error << L")\n";
		return ExitCode::status_error;
	}
	std::wcout << std::wstring(report->begin(), report->end()) << L'\n';
	return ExitCode::success;
}
}

/// Dispatches the fail-closed launcher command line.
int wmain(const int argument_count, wchar_t* arguments[])
{
	if(argument_count == 3 && std::wstring_view(arguments[1]) == L"inspect")
	{
		return static_cast<int>(run_inspect(arguments[2]));
	}
	if(argument_count == 4 && std::wstring_view(arguments[1]) == L"inject")
	{
		return static_cast<int>(run_inject(arguments[2], arguments[3]));
	}
	if(argument_count == 3 && std::wstring_view(arguments[1]) == L"status")
	{
		return static_cast<int>(run_status(arguments[2]));
	}
	if(argument_count == 3 && std::wstring_view(arguments[1]) == L"objects")
	{
		return static_cast<int>(run_objects(arguments[2]));
	}

	print_usage();
	return static_cast<int>(ExitCode::usage);
}
