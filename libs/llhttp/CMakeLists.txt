cmake_minimum_required(VERSION 3.14)

project(
    llhttp
    LANGUAGES C
    DESCRIPTION "A Http Parser."
)

set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)

# Main Library
add_library(llhttp_parser llhttp/src/api.c llhttp/src/http.c llhttp/src/llhttp.c)
target_include_directories(llhttp_parser PUBLIC llhttp/include)
