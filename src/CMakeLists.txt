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

# Apply logger backend compile definitions and library linkage
if(NIDS_LOGGER_BACKEND STREQUAL "syslog")
    target_compile_definitions(nids_core PRIVATE LOGGER_BACKEND_SYSLOG)
elseif(NIDS_LOGGER_BACKEND STREQUAL "android")
    target_compile_definitions(nids_core PRIVATE LOGGER_BACKEND_ANDROID)
    target_link_libraries(nids_core PRIVATE log)          # Android log library
elseif(NIDS_LOGGER_BACKEND STREQUAL "nlog")
    target_compile_definitions(nids_core PRIVATE LOGGER_BACKEND_NLOG)
    target_link_libraries(nids_core PRIVATE spdlog::spdlog)
endif()

# Main executable
add_executable(nids main.cpp)
target_link_libraries(nids PRIVATE nids_core)
