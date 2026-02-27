# nids_core -- header-only + small compile units
add_library(nids_core
    core/logger.cpp
    ipc/event_queue.cpp
    nic/af_packet_nic.cpp
    stages/preprocess_stage.cpp
    stages/decode_stage.cpp
    stages/detection_stage.cpp
    stages/matching_stage.cpp
    stages/event_stage.cpp
    threads/capture_thread.cpp
    threads/processing_thread.cpp
    threads/comm_thread.cpp
    app/nids_app.cpp
)

target_include_directories(nids_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(nids_core PUBLIC pthread nlohmann_json::nlohmann_json)

# Main executable
add_executable(nids main.cpp)
target_link_libraries(nids PRIVATE nids_core)
