# Test binaries land in the build's bin/ for a uniform ./bin/test_X path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Tests that need multiple parties depend on a top-level `run` helper
# that spawns the right number of processes. Single-party benchmarks
# don't need it.

function(add_test_case _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    add_test(NAME ${_name}
             COMMAND test_${_name}
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

function(add_test_case_with_run _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    add_test(NAME ${_name}
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

# Native Bit frontend (AG2PCBackend -> WireGraph -> C2PC) + IR
add_test_case_with_run(wire_graph_test)
add_test_case_with_run(test_recording)
add_test_case_with_run(test_aes)
add_test_case_with_run(test_rounds)
add_test_case_with_run(test_chain)
add_test_case_with_run(test_reactive)
add_test_case_with_run(test_sha256)
# cutchoose_mult: the cut-and-choose leaky-AND path is no longer wired in
# (triple_pool.h no longer #includes triple_pool_cutchoose.h). Re-enable the
# include there to build this again.
# add_test_case_with_run(cutchoose_mult)
