cmake_minimum_required(VERSION 3.20)
project(mod_auth_rest C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_path(PROFTPD_INCLUDE_DIR NAMES conf.h
        PATHS /usr/include/proftpd /usr/local/include/proftpd)
find_path(CURL_INCLUDE_DIR NAMES curl/curl.h
        PATHS /usr/include /usr/include/x86_64-linux-gnu /usr/local/include)
find_library(CURL_LIBRARY NAMES curl
        PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib)

if(NOT PROFTPD_INCLUDE_DIR)
    message(FATAL_ERROR "proftpd headers not found. Install 'proftpd-dev' or set PROFTPD_INCLUDE_DIR.")
endif()
if(NOT CURL_INCLUDE_DIR OR NOT CURL_LIBRARY)
    message(FATAL_ERROR "libcurl not found. Install 'libcurl4-openssl-dev'.")
endif()

include_directories(
        ${PROFTPD_INCLUDE_DIR}
        ${CURL_INCLUDE_DIR}
)

add_library(mod_auth_rest MODULE mod_auth_rest.c)
target_link_libraries(mod_auth_rest PRIVATE ${CURL_LIBRARY})

# ProFTPD modules are .so; name convention usually mod_xxx.so
set_target_properties(mod_auth_rest PROPERTIES
        OUTPUT_NAME "mod_auth_rest"
        PREFIX ""      # produce mod_auth_rest.so, not libmod_auth_rest.so
)

# (Optional) emit compile_commands.json for better IDE hints
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
