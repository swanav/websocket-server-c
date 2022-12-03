# String Utility Functions
add_library(StringUtils string_utils.c)
target_include_directories(StringUtils PUBLIC .)


# =====================================================
#                    TEST CASES
# =====================================================
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING AND NOT "${TARGET}" STREQUAL "esp32")

add_executable(test_string_utils tests/string_utils.cpp)
target_link_libraries(test_string_utils StringUtils gtest_main)

include(GoogleTest)
gtest_discover_tests(test_string_utils TEST_PREFIX Utilities:)
endif()


add_library(Server INTERFACE)
target_include_directories(Server INTERFACE .)

# TCP Server Library (TCP)
add_library(TcpServer tcp_server.c tcp_methods.c)
# target_include_directories(TcpServer PRIVATE priv)
target_include_directories(TcpServer PUBLIC .)
target_link_libraries(TcpServer PUBLIC Server LinkedList)
if("${TARGET}" STREQUAL "windows")
	# Link to the windows DLLs for Winsock2 support 
	target_link_libraries(TcpServer PUBLIC wsock32 ws2_32)
endif()
target_compile_options(TcpServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# TLS Server Library (TLS)
add_library(TlsServer tls_server.c)
target_include_directories(TlsServer PUBLIC .)
target_link_libraries(TlsServer PUBLIC Server LinkedList TcpServer)
if("${TARGET}" STREQUAL "esp32")
	# Use the mbedtls port in esp-idf
	target_link_libraries(TlsServer PUBLIC __idf_mbedtls)
else()
	target_link_libraries(TlsServer PUBLIC mbedtls)
endif()
target_compile_options(TlsServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# WebSocket Server Library (WS)
add_library(WsServer ws_server.c ws_protocol.c)
target_include_directories(WsServer PUBLIC .)
target_link_libraries(WsServer PUBLIC Server LinkedList llhttp_parser StringUtils TcpServer TlsServer)

if("${TARGET}" STREQUAL "esp32")
	# Use the mbedtls port in esp-idf
	target_link_libraries(WsServer PUBLIC __idf_mbedtls)
else()
	target_link_libraries(WsServer PUBLIC mbedtls)
endif()
target_compile_options(WsServer PRIVATE -Werror -Wall -Wextra -Wimplicit)


# =======================================================
#                      TEST CASES
# =======================================================
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING AND NOT "${TARGET}" STREQUAL "esp32")

add_executable(test_ws_handshake tests/test_ws_handshake.cpp)
target_link_libraries(test_ws_handshake WsServer gtest_main)

add_executable(test_ws_protocol tests/test_ws_protocol.cpp)
target_link_libraries(test_ws_protocol WsServer gtest_main)

include(GoogleTest)
gtest_discover_tests(test_ws_handshake TEST_PREFIX WebsocketServer:)
gtest_discover_tests(test_ws_protocol TEST_PREFIX WebsocketServer:)
endif()
