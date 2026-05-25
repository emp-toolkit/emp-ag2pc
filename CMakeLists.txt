cmake_minimum_required(VERSION 3.21)
project(emp-ag2pc VERSION 1.0.0 LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not allowed. Use a separate build directory:\n"
        "  cmake -B build && cmake --build build")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

# ---------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------
option(EMP_AG2PC_BUILD_TESTS "Build emp-ag2pc tests"      ${PROJECT_IS_TOP_LEVEL})
option(EMP_AG2PC_DEBUG       "Enable internal MAC / correctness checks (defines EMP_DEBUG_PHASE)" OFF)

# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------
# Local-dev tip: point at sibling build trees with
#   -Demp-tool_DIR=/path/to/emp-tool/build  -Demp-ot_DIR=/path/to/emp-ot/build
# or one common -DCMAKE_PREFIX_PATH covering both installs.
find_package(emp-tool 1.0 REQUIRED)
find_package(emp-ot   1.0 REQUIRED)

# ---------------------------------------------------------------------
# Library target (header-only)
# ---------------------------------------------------------------------
# emp-ag2pc has no compiled units of its own — protocol logic lives in
# headers, the Backend / circ_exec singletons live in upstream emp-tool.
add_library(emp-ag2pc INTERFACE)
add_library(emp-ag2pc::emp-ag2pc ALIAS emp-ag2pc)

target_compile_features(emp-ag2pc INTERFACE cxx_std_17)

target_include_directories(emp-ag2pc INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(emp-ag2pc INTERFACE
    emp-tool::emp-tool
    emp-ot::emp-ot)

# Bristol-format circuit files used by tests (e.g. AES, SHA). Files now
# live in upstream emp-tool. Stored as absolute path so test binaries can
# be run from any cwd.
target_compile_definitions(emp-ag2pc INTERFACE
    EMP_CIRCUIT_PATH="/Users/wangxiao/Documents/emp-tool/emp-tool/circuits/files/")

if(EMP_AG2PC_DEBUG)
    target_compile_definitions(emp-ag2pc INTERFACE EMP_DEBUG_PHASE)
endif()

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------
if(EMP_AG2PC_BUILD_TESTS)
    include(CTest)
    add_subdirectory(test)
endif()
