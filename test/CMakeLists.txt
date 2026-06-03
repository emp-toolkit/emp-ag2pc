# Test binaries land in the build's bin/ for a uniform ./bin/test_X path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Tests that need multiple parties depend on a top-level `run` helper
# that spawns the right number of processes. Single-party benchmarks
# don't need it.

# Forbid memcpy on non-trivially-copyable types (= Bit_T<AG2PCWire>, anything
# that contains it). Catches regressions like the numeric_kernels.h memcpy bug
# at build time before they silently corrupt AG2PCWire's refcount. GCC and
# Clang spell it differently.
function(_apply_strict_memaccess _tgt)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${_tgt} PRIVATE -Werror=nontrivial-memaccess)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${_tgt} PRIVATE -Werror=class-memaccess)
    endif()
endfunction()

function(add_test_case _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND test_${_name}
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

function(add_test_case_with_run _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

# Same, but compiles just this one binary as C++20 (e.g. for template-lambda
# circuit bodies). The libraries stay C++17; cxx_std_17 there is a floor, so
# CMake resolves this target to C++20 without affecting anything else.
function(add_test_case_with_run_cxx20 _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    target_compile_features(test_${_name} PRIVATE cxx_std_20)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..)
endfunction()

# AG2PC has ONE protocol executor — LambdaRunner::run_engine_ — fed by several
# circuit sources (a live frontend body run<Ins...>, a compiled TypedCircuit
# run_compiled<Ins...>, a raw BooleanProgram run_program, the flat lambda
# run_circuit, and the direct recorder, which emits BooleanProgram chunks into
# run_program). The tests are grouped by architectural surface, not by source x
# circuit. Shared helpers live in test_common.h.

# ---- Frontend front-doors ---------------------------------------------------
# Small/fast API behavior (add, chaining, typed lambda, public const, raw
# BooleanProgram) and crypto-sized circuits (AES / SHA-256 with oracle checks).
add_test_case_with_run_cxx20(test_frontend_api)    # run / run_compiled / run_program / chain / typed / const
add_test_case_with_run(test_frontend_crypto)       # AES (live + compiled), SHA-256 (run_circuit), vs oracle

# ---- Direct recorder (imperative adapter over BooleanProgram + run_program) --
# Recorder-distinguishing semantics, then the same recorder on real circuits.
add_test_case_with_run(test_direct_recorder)       # record/reveal, batching, checkpoint, reactive, liveness
add_test_case_with_run(test_direct_crypto)         # AES + SHA-256 via the recorder, vs oracle

# ---- Cross-source equivalence (transcript-sensitive; kept standalone) -------
add_test_case_with_run(test_wire_equiv)            # BYTE (body == flat lambda) + SEMANTIC (compiled) equiv

# ---- Manual benchmarks -------------------------------------------------------
# Built with -DEMP_AG2PC_BUILD_BENCHES=ON. Intentionally not registered with
# add_test(), so ctest never runs it.
if(EMP_AG2PC_BUILD_BENCHES)
    add_executable(bench_modes bench_modes.cpp)
    target_link_libraries(bench_modes PRIVATE emp-ag2pc::emp-ag2pc)
    _apply_strict_memaccess(bench_modes)
endif()
