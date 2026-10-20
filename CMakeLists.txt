cmake_minimum_required(VERSION 3.22)

project(MinecraftDungeonsModKit VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	message(FATAL_ERROR "MinecraftDungeonsModKit requires Windows x64")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/compiler_options.cmake)

add_library(mcd-common STATIC
	src/common/build_identity.cpp
	src/common/protocol.cpp
	src/common/sha256_windows.cpp
)
target_include_directories(mcd-common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(mcd-common PUBLIC mcd_project_options PRIVATE bcrypt ntdll)

add_executable(mcd-launcher src/launcher/main.cpp)
add_library(mcd-runtime SHARED src/runtime/dllmain.cpp)
set_target_properties(mcd-runtime PROPERTIES PREFIX "")

target_link_libraries(mcd-launcher PRIVATE mcd_project_options mcd-common)
target_link_libraries(mcd-runtime PRIVATE mcd_project_options mcd-common)

include(CTest)
if(BUILD_TESTING)
	add_subdirectory(tests)
endif()
