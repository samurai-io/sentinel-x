cmake_minimum_required(VERSION 3.10)
project(SentinelX C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable compiler warnings, optimization, debug info, and security hardening options
add_compile_options(
    -Wall 
    -Wextra 
    -O2 
    -g 
    -D_GNU_SOURCE 
    -fstack-protector-all
)

# Include directories
include_directories(include)

# Find Threads library (pthread)
find_package(Threads REQUIRED)

# Component sources
set(COMMON_SOURCES
    src/common/log.c
    src/common/hashmap.c
    src/common/notification.c
)

set(CORE_SOURCES
    src/core/filter.c
    src/core/state_table.c
    src/core/live_capture.c
)

set(DPI_SOURCES
    src/dpi/dpi.c
    src/dpi/http_parser.c
    src/dpi/dns_parser.c
    src/dpi/tls_parser.c
)

set(WAF_SOURCES
    src/waf/waf.c
)

set(IDS_IPS_SOURCES
    src/ids_ips/ids.c
    src/ids_ips/ips.c
)

set(ZT_SOURCES
    src/zero_trust/trust_engine.c
)

# Compile executable
add_executable(sentinel_x
    src/main.c
    ${COMMON_SOURCES}
    ${CORE_SOURCES}
    ${DPI_SOURCES}
    ${WAF_SOURCES}
    ${IDS_IPS_SOURCES}
    ${ZT_SOURCES}
)

# Link threads library
target_link_libraries(sentinel_x PRIVATE Threads::Threads)
