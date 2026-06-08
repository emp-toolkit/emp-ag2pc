# Test binaries land in the build's bin/ for a uniform ./bin/test_X path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Two-party tests run both parties on localhost via the top-level `run` helper.

# Forbid memcpy on non-trivially-copyable types. A cheap, always-on guard against
# blanket-copying a circuit value that ever gains a non-trivial member. GCC and
# Clang spell it differently.
function(_apply_strict_memaccess _tgt)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${_tgt} PRIVATE -Werror=nontrivial-memaccess)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${_tgt} PRIVATE -Werror=class-memaccess)
    endif()
endfunction()

function(add_test_case_with_run _name)
    add_executable(test_${_name} test_${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

# Single-process unit test (no parties, no network) — runs the binary directly.
function(add_unit_test _name)
    add_executable(test_${_name} test_${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name} COMMAND test_${_name})
endfunction()

# Pure planner logic (no network).
add_unit_test(flush_plan)                   # direct-chunk DCE / compaction / stale-operand detection

# The AG2PCCtx surface and its three execution strategies.
add_test_case_with_run(context_api)         # typed input/reveal, arithmetic, signed Int, PUBLIC const, reveal-to-one
add_test_case_with_run(direct_chunks)       # input batching, checkpoint prune+carry, reveal keep-list, no-arg cleanup
add_test_case_with_run(program_replay)      # compiled run, hand-authored run_program, fp32 builtin
add_test_case_with_run(body_replay_equiv)   # run_body == compiled run, BYTE-identical transcript (the gate)
add_test_case_with_run(aes_sha_builtin)     # aes128 + sha256_256 .empbc replay vs ClearCtx oracle

# ---- Manual benchmarks -------------------------------------------------------
# Built with -DEMP_AG2PC_BUILD_BENCHES=ON. Intentionally not registered with
# add_test(), so ctest never runs them.
if(EMP_AG2PC_BUILD_BENCHES)
    find_package(OpenSSL REQUIRED)
    add_executable(bench_100m bench_100m.cpp)
    target_link_libraries(bench_100m PRIVATE emp-ag2pc::emp-ag2pc OpenSSL::Crypto)
    _apply_strict_memaccess(bench_100m)
endif()
