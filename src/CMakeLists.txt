file(GLOB_RECURSE PEDetour_SRC
	"*.h"
	"*.cc"
)
add_executable(PEDetour ${PEDetour_SRC})
target_link_libraries(PEDetour capstone-static keystone)
