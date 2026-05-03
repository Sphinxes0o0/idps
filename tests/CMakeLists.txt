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
add_nids_test(test_rule_parser)
add_nids_test(test_bmh_search)
add_nids_test(test_icmp_flood_threshold)
add_nids_test(test_dns_amplification)
add_nids_test(test_af_xdp_frame_recycle)
add_nids_test(test_rule_index_consistency)
add_nids_test(test_ipv4_ipv6_dual_stack)

# F-03/F-04/F-05/F-13: Email protocols, DNS query, TLS certificate tests
add_nids_test(test_email_protocols)
add_nids_test(test_dns_query)
add_nids_test(test_tls_cert)
