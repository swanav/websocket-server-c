# Example Applications

# TCP Echo Server
add_executable(TcpEchoServer tcp_echo_server.c)
target_link_libraries(TcpEchoServer TcpServer)
target_compile_options(TcpEchoServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# TCP Broadcast Server
add_executable(TcpBroadcastServer tcp_broadcast_server.c)
target_link_libraries(TcpBroadcastServer TcpServer)
target_compile_options(TcpBroadcastServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# TLS Echo Server
add_executable(TlsEchoServer tls_echo_server.c)
target_link_libraries(TlsEchoServer TlsServer)
target_compile_options(TlsEchoServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# TLS Broadcast Server
add_executable(TlsBroadcastServer tls_broadcast_server.c)
target_link_libraries(TlsBroadcastServer TlsServer)
target_compile_options(TlsBroadcastServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# Websocket Echo Server
add_executable(WsEchoServer ws_echo_server.c)
target_link_libraries(WsEchoServer WsServer)
target_compile_options(WsEchoServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# Websocket Broadcast Server
add_executable(WsBroadcastServer ws_broadcast_server.c)
target_link_libraries(WsBroadcastServer WsServer)
target_compile_options(WsBroadcastServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# Websocket Secure Echo Server
add_executable(WssEchoServer wss_echo_server.c)
target_link_libraries(WssEchoServer WsServer)
target_compile_options(WssEchoServer PRIVATE -Werror -Wall -Wextra -Wimplicit)

# Websocket Secure Broadcast Server
add_executable(WssBroadcastServer wss_broadcast_server.c)
target_link_libraries(WssBroadcastServer WsServer)
target_compile_options(WssBroadcastServer PRIVATE -Werror -Wall -Wextra -Wimplicit)
