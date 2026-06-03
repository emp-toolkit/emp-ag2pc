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

# Native Bit frontend (AG2PCBackend -> WireGraph -> C2PC) + IR
add_test_case_with_run(wire_graph_test)
add_test_case_with_run(test_recording)
add_test_case_with_run(test_aes)
add_test_case_with_run(test_rounds)
add_test_case_with_run(test_chain)
add_test_case_with_run(test_reactive)
add_test_case_with_run(test_sha256)
add_test_case_with_run(test_keep_all)

# Frontend compile/run driven through the live AG2PCBackend (direct recorder):
# frontend::compile -> frontend::run(circuit) replays gates onto the recorder.
add_test_case_with_run(test_frontend)
add_test_case_with_run(test_frontend_chain)
add_test_case_with_run_cxx20(test_frontend_typed)   # C++20 template-lambda body

# Compiled circuit (frontend::compile) replayed through the streaming engine
# (LambdaRunner::run_compiled); includes a public-constant case.
add_test_case_with_run(test_frontend_materialized)

# Lambda-mode runner (no recording; lambda re-replayed per phase)
add_test_case_with_run(test_lambda_aes)
add_test_case_with_run(test_lambda_sha256)

# Streaming executor driven by a frontend body (LambdaRunner::run<Ins...>)
add_test_case_with_run(test_lambda_frontend)

# Compiled circuit replayed through the streaming engine (run_compiled<Ins...>)
add_test_case_with_run(test_lambda_compiled)

# Wire-byte equivalence: legacy run_circuit vs frontend run<Ins...> (transcript
# digest equality under EMP_TEST_MODE). Guards crypto-neutral refactors.
add_test_case_with_run(test_wire_equiv)
