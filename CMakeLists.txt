cmake_minimum_required(VERSION 3.22)

project(MinecraftDungeonsModKit VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	message(FATAL_ERROR "MinecraftDungeonsModKit requires Windows x64")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/compiler_options.cmake)

add_executable(mcd-launcher src/launcher/main.cpp)
add_library(mcd-runtime SHARED src/runtime/dllmain.cpp)
set_target_properties(mcd-runtime PROPERTIES PREFIX "")

target_link_libraries(mcd-launcher PRIVATE mcd_project_options)
target_link_libraries(mcd-runtime PRIVATE mcd_project_options)

include(CTest)
if(BUILD_TESTING)
	add_subdirectory(tests)
endif()
