# nids_core -- header-only + small compile units
add_library(nids_core
    core/logger.cpp
    ipc/event_queue.cpp
    nic/ebpf_nic.cpp
    ebpf/ebpf_loader.cpp
    ebpf/ringbuf_reader.cpp
    threads/comm_thread.cpp
    rules/rule_parser.cpp
    app/nids_app.cpp
    # xdp/af_xdp.cpp  # Requires linux/if_xdp.h (CONFIG_XDP_SOCKETS kernel)
)

target_include_directories(nids_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBBPF_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/bpf
)
target_link_libraries(nids_core PUBLIC
    pthread
    nlohmann_json::nlohmann_json
    /usr/lib/aarch64-linux-gnu/libbpf.a
    elf
    z
)

# Main executable
add_executable(nids main.cpp)
target_link_libraries(nids PRIVATE nids_core)
