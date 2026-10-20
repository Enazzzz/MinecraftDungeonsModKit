#include <cassert>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>

#include "mcd/build_identity.hpp"

namespace
{
/// Fails fast when a required test condition is false.
#define REQUIRE(condition) assert(condition)

/// Returns the temporary file path used by the hashing test.
std::filesystem::path make_temp_path()
{
	return std::filesystem::temp_directory_path() / "mcd-build-identity-test.bin";
}

/// Writes a binary test file with deterministic content.
void write_test_file(const std::filesystem::path& path, std::string_view contents)
{
	std::ofstream stream(path, std::ios::binary);
	REQUIRE(stream.is_open());
	stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
	REQUIRE(stream.good());
}

/// Removes the temporary test file if it exists.
void remove_test_file(const std::filesystem::path& path)
{
	std::error_code error;
	std::filesystem::remove(path, error);
}

/// Verifies that valid uppercase SHA-256 text decodes and invalid text is rejected.
void test_parse_sha256()
{
	const auto digest = mcd::parse_sha256(
		"6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73");
	REQUIRE(digest.has_value());
	REQUIRE((*digest)[0] == std::byte {0x6A});
	REQUIRE((*digest)[31] == std::byte {0x73});
	REQUIRE(!mcd::parse_sha256(
		"6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC7")
			 .has_value());
	REQUIRE(!mcd::parse_sha256(
		"6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC7G")
			 .has_value());
}

/// Verifies that BCrypt hashing returns the known digest for a test file.
void test_sha256_file()
{
	const auto path = make_temp_path();
	remove_test_file(path);
	write_test_file(path, "abc");

	const auto digest = mcd::sha256_file(path);
	REQUIRE(digest.has_value());

	const auto expected = mcd::parse_sha256(
		"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
	REQUIRE(expected.has_value());
	REQUIRE(*digest == *expected);

	remove_test_file(path);
}

/// Verifies that only the measured Steam executable selects the initial profile.
void test_exact_build_profile()
{
	const auto digest = mcd::parse_sha256(
		"6A48471423B41CDCDD4F0322560DCAFAE0F433F3BC30721FAE861564A4F5CC73");
	REQUIRE(digest.has_value());
	const auto profile = mcd::identify_build(37'814'288, *digest);
	REQUIRE(profile.has_value());
	REQUIRE(profile->id == "steam-2026-10-19");
	REQUIRE(profile->image_size == 37'814'288);
	REQUIRE(!mcd::identify_build(37'814'289, *digest).has_value());

	auto wrong_digest = *digest;
	wrong_digest[0] ^= std::byte {0x01};
	REQUIRE(!mcd::identify_build(37'814'288, wrong_digest).has_value());
}
}

/// Runs the build identity regression tests.
int main()
{
	test_parse_sha256();
	test_sha256_file();
	test_exact_build_profile();
	return 0;
}
