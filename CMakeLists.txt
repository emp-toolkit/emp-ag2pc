cmake_minimum_required (VERSION 2.8.11)
project (emp-ag2pc)
set(NAME "emp-ag2pc")

if(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW) # use rpath on macOS
endif()

include_directories(${CMAKE_SOURCE_DIR})
if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_SOURCE_DIR}/cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} cmake/)

FIND_PACKAGE(emp-ot REQUIRED)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})
OPTION(USE_RANDOM_DEVICE "Option description" OFF)
IF(USE_RANDOM_DEVICE)
     ADD_DEFINITIONS(-DEMP_USE_RANDOM_DEVICE)
ENDIF(USE_RANDOM_DEVICE)

set (CMAKE_C_FLAGS "-pthread -Wall -march=native -O3 -maes -mavx2 -mrdseed")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++0x")

macro (add_test _name)
	add_executable("${_name}" "test/${_name}.cpp" ${basics})
	target_link_libraries("${_name}" ${EMP-OT_LIBRARIES})
endmacro()

add_test(aes)
add_test(sha1)
add_test(sha256)
#add_test (abit)
#add_test (amortized_2pc)

