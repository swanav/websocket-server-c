#ifndef TCP_METHODS_H
#define TCP_METHODS_H

#include "tcp_server.h"

Err_t CreateTcpServer(TcpServer_t* server);

Err_t CloseEndpoint(TcpEndpoint_t* endpoint);

TcpEndpoint_t* GetTcpEndpointFromFileDescriptor(TcpServer_t* server, const int fd);

Err_t HandleTcpServerFileDescriptor(TcpServer_t* server);

Err_t HandleTcpEndpointFileDescriptor(TcpEndpoint_t* endpoint);

#endif // TCP_METHODS_H
