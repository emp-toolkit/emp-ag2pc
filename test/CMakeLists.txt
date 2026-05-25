# Test binaries land in the build's bin/ for a uniform ./bin/test_X path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Tests that need multiple parties depend on a top-level `run` helper
# that spawns the right number of processes. Single-party benchmarks
# don't need it.

function(add_test_case _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-agmpc::emp-agmpc)
    add_test(NAME ${_name}
             COMMAND test_${_name}
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

function(add_test_case_with_run _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-agmpc::emp-agmpc)
    add_test(NAME ${_name}
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

# Lower-layer protocol tests (triples / auth-shares / IKNP)
add_test_case_with_run(triple)
add_test_case_with_run(prof_triple)
add_test_case_with_run(three_party_iknp)
add_test_case_with_run(auth_share)

# Native Bit frontend (WRKBackend -> WireGraph -> CMPC) + IR
add_test_case_with_run(wire_graph_test)
add_test_case_with_run(wrk_recording)
add_test_case_with_run(wrk_aes)
add_test_case_with_run(wrk_rounds)
add_test_case_with_run(wrk_chain)
add_test_case_with_run(wrk_reactive)
add_test_case_with_run(wrk_sha256)
add_test_case_with_run(cutchoose_mult)
