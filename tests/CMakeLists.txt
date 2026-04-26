include(GoogleTest)

function(add_nids_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE nids_core GTest::gtest_main)
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    gtest_discover_tests(${name})
endfunction()

add_nids_test(test_pool)
add_nids_test(test_queue)
add_nids_test(test_ebpf_loader)
