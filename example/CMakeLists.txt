# Example binaries land beside tests/benchmarks for the same ./run invocation.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

function(add_ag2pc_example _name)
    add_executable(example_${_name} ${_name}.cpp)
    target_link_libraries(example_${_name} PRIVATE emp-ag2pc::emp-ag2pc)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(example_${_name} PRIVATE -Werror=nontrivial-memaccess)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(example_${_name} PRIVATE -Werror=class-memaccess)
    endif()
endfunction()

add_ag2pc_example(1_basics)
add_ag2pc_example(2_reveal_and_continue)
add_ag2pc_example(3_reusable_circuit)
add_ag2pc_example(4_bit_strings)
add_ag2pc_example(5_chunking)
add_ag2pc_example(6_raw_program)
