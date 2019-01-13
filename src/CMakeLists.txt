file(GLOB_RECURSE PEDetour_SRC
	"*.h"
	"*.cc"
)
add_executable(PEDetour ${PEDetour_SRC})
target_link_libraries(PEDetour capstone-static keystone)

configure_file(TestDLL.dll ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TestDLL.bak COPYONLY)
configure_file(TestDLL_test.exe ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TestDLL_test.exe COPYONLY)
