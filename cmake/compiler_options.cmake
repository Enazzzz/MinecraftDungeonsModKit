add_library(mcd_project_options INTERFACE)

target_compile_features(mcd_project_options INTERFACE cxx_std_20)

target_compile_options(mcd_project_options INTERFACE
	/W4
	/permissive-
	/EHsc
	/utf-8
)

target_compile_definitions(mcd_project_options INTERFACE
	WIN32_LEAN_AND_MEAN
	NOMINMAX
	_WIN32_WINNT=0x0A00
)
