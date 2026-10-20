add_executable(mcd_smoke_tests smoke_tests.cpp)
target_link_libraries(mcd_smoke_tests PRIVATE mcd_project_options)

add_executable(mcd_build_identity_tests build_identity_tests.cpp)
target_link_libraries(mcd_build_identity_tests PRIVATE mcd_project_options mcd-common)

add_executable(mcd_protocol_tests protocol_tests.cpp)
target_link_libraries(mcd_protocol_tests PRIVATE mcd_project_options mcd-common)

add_executable(mcd_runtime_tests runtime_tests.cpp)
target_link_libraries(mcd_runtime_tests PRIVATE mcd_project_options mcd-runtime-core)

add_custom_target(mcd_tests
	DEPENDS
		mcd_smoke_tests
		mcd_build_identity_tests
		mcd_protocol_tests
		mcd_runtime_tests
)

add_test(NAME smoke COMMAND mcd_smoke_tests)
add_test(NAME build_identity COMMAND mcd_build_identity_tests)
add_test(NAME protocol COMMAND mcd_protocol_tests)
add_test(NAME runtime COMMAND mcd_runtime_tests)
