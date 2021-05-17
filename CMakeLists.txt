cmake_minimum_required (VERSION 2.8.11)
project (emp-ag2pc)
set(NAME "emp-ag2pc")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)

include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/enable_rdseed.cmake)
include(${CMAKE_FOLDER}/cmake/enable_float.cmake)

FIND_PACKAGE(emp-ot REQUIRED)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})

install(DIRECTORY emp-ag2pc DESTINATION include)
install(DIRECTORY cmake/ DESTINATION cmake)

# Test cases
macro(add_test_executable _name)
	add_executable(${_name} "test/${_name}.cpp")
	target_link_libraries(${_name} ${EMP-OT_LIBRARIES})
endmacro()


add_test_executable(aes)
add_test_executable(sha1)
add_test_executable(sha256)
add_test_executable (simple_circuit)
add_test_executable (abit)
add_test_executable (triple)
add_test_executable (amortized_2pc)

