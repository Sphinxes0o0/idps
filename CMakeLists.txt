cmake_minimum_required(VERSION 3.16)
project(NIDS VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic")

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Dependencies ----------------------------------------------------------------

# libbpf (system installed)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
# Also find bpf headers that might be in a different location
find_path(LIBBPF_INCLUDE_DIR bpf/libbpf.h PATHS /usr/include /usr/include/bpf /usr/local/include)

# GoogleTest (system installed)
find_package(GTest CONFIG)
if(NOT GTest_FOUND)
    # Fallback to FetchContent if system GTest not available
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF)
    FetchContent_MakeAvailable(googletest)
endif()

# nlohmann/json (header-only, system installed)
find_package(nlohmann_json 3.10 CONFIG)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# eBPF BPF Compiler ------------------------------------------------------------
# Find clang for BPF target compilation
find_program(CLANG_EXECUTABLE clang REQUIRED)
message(STATUS "Found clang: ${CLANG_EXECUTABLE}")

# Determine target architecture for BPF
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(BPF_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(BPF_ARCH "arm64")
else()
    set(BPF_ARCH "x86")
endif()
message(STATUS "BPF target architecture: ${BPF_ARCH}")

# Create bpf build directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bpf)

# Custom command to compile BPF program
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bpf/nids_bpf.o
    COMMAND ${CLANG_EXECUTABLE}
        -target bpf
        -g
        -O2
        -Wall
        -I${CMAKE_SOURCE_DIR}/bpf
        -I${LIBBPF_INCLUDE_DIR}
        -I/usr/include/bpf
        -I/usr/include
        -I/usr/include/aarch64-linux-gnu
        -D__TARGET_ARCH_${BPF_ARCH}
        -D__BPF_TRACING___
        -c ${CMAKE_SOURCE_DIR}/bpf/nids_bpf.c
        -o ${CMAKE_BINARY_DIR}/bpf/nids_bpf.o
    DEPENDS
        ${CMAKE_SOURCE_DIR}/bpf/nids_bpf.c
        ${CMAKE_SOURCE_DIR}/bpf/nids_common.h
    COMMENT "Compiling eBPF program with clang"
    VERBATIM
)

# Custom command to compile tracepoint BPF program
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bpf/nids_trace.o
    COMMAND ${CLANG_EXECUTABLE}
        -target bpf
        -g
        -O2
        -Wall
        -I${CMAKE_SOURCE_DIR}/bpf
        -I${LIBBPF_INCLUDE_DIR}
        -I/usr/include/bpf
        -I/usr/include
        -I/usr/include/aarch64-linux-gnu
        -D__TARGET_ARCH_${BPF_ARCH}
        -D__BPF_TRACING___
        -c ${CMAKE_SOURCE_DIR}/bpf/nids_trace.c
        -o ${CMAKE_BINARY_DIR}/bpf/nids_trace.o
    DEPENDS
        ${CMAKE_SOURCE_DIR}/bpf/nids_trace.c
        ${CMAKE_SOURCE_DIR}/bpf/nids_common.h
    COMMENT "Compiling eBPF tracepoint program with clang"
    VERBATIM
)

# Custom target for BPF (build with: make bpf)
add_custom_target(bpf ALL
    DEPENDS ${CMAKE_BINARY_DIR}/bpf/nids_bpf.o ${CMAKE_BINARY_DIR}/bpf/nids_trace.o
    COMMENT "Building eBPF objects"
)

# Copy BPF objects to known location for runtime loading
add_custom_command(
    TARGET bpf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/bpf/nids_bpf.o
        ${CMAKE_BINARY_DIR}/bin/nids_bpf.o
    COMMENT "Copying BPF object to bin directory"
)

add_custom_command(
    TARGET bpf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/bpf/nids_trace.o
        ${CMAKE_BINARY_DIR}/bin/nids_trace.o
    COMMENT "Copying trace BPF object to bin directory"
)

# Generate BPF skeleton header using bpftool
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/ebpf/nids_bpf.skel.h
    COMMAND bpftool gen skeleton ${CMAKE_BINARY_DIR}/bpf/nids_bpf.o > ${CMAKE_SOURCE_DIR}/src/ebpf/nids_bpf.skel.h
    DEPENDS ${CMAKE_BINARY_DIR}/bpf/nids_bpf.o
    COMMENT "Generating BPF skeleton header"
    VERBATIM
)

# Custom target for skeleton generation
add_custom_target(skeleton ALL
    DEPENDS ${CMAKE_SOURCE_DIR}/src/ebpf/nids_bpf.skel.h ${CMAKE_SOURCE_DIR}/src/ebpf/nids_trace.skel.h
    COMMENT "Generating BPF skeleton"
)

# Ensure skeleton is regenerated when BPF object changes
add_dependencies(skeleton bpf)

# Generate BPF trace skeleton header using bpftool
add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/ebpf/nids_trace.skel.h
    COMMAND bpftool gen skeleton ${CMAKE_BINARY_DIR}/bpf/nids_trace.o > ${CMAKE_SOURCE_DIR}/src/ebpf/nids_trace.skel.h
    DEPENDS ${CMAKE_BINARY_DIR}/bpf/nids_trace.o
    COMMENT "Generating BPF trace skeleton header"
    VERBATIM
)

# Source modules --------------------------------------------------------------

add_subdirectory(src)

# Tests -----------------------------------------------------------------------

enable_testing()
add_subdirectory(tests)
