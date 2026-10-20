add_executable(mcd_tests smoke_tests.cpp)

target_link_libraries(mcd_tests PRIVATE mcd_project_options)

add_test(NAME smoke COMMAND mcd_tests)
