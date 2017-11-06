cmake_minimum_required (VERSION 2.8.11)
project (emp-c2pc)

include_directories(${CMAKE_SOURCE_DIR})

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)

FIND_PACKAGE(emp-ot)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})

#FIND_PACKAGE(emp-sh2pc)
#INCLUDE_DIRECTORIES(${EMP-SH2PC_INCLUDE_DIRS})

set (CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes -mavx2 -mrdseed")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")

macro (add_test _name)
	add_executable("test_${_name}" "test/${_name}.cpp" ${basics})
	target_link_libraries("test_${_name}"  relic  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES})
endmacro()

macro (add_bench _name)
	add_executable("bench_${_name}" "bench/${_name}.cpp" ${basics})
	target_link_libraries("bench_${_name}"  relic  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES})
endmacro()

macro (add_example _name)
	add_executable("example_${_name}" "example/${_name}.cpp" ${basics})
	target_link_libraries("example_${_name}"  relic  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES})
endmacro()

add_test (scratch)
add_test (abit)
add_test (2pc)
add_test (amortized_2pc)

add_bench (2pc)
add_bench (2pc_scal)
add_bench (amortized_2pc)
add_bench (generate_circuit)
#add_bench(circuit_file)
