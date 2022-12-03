#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "tcp_server.h"
#include "tcp_methods.h"

#if BUILD_TARGET_LINUX || BUILD_TARGET_ESP32
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h> 
#include <sys/select.h>
#elif  BUILD_TARGET_WINDOWS
#include <winsock2.h>
#endif


TcpServer_t* tcp_server_Init(TcpServerConfig_t* tcpConfig) {
    Err_t ret;

    TcpServer_t* server = (TcpServer_t*) malloc(sizeof(TcpServer_t));    
    if(!server) {
        // printf("Failed to allocate memory for socket.\n");
        return NULL;
    }
    memset(server, 0, sizeof(TcpServer_t));

    TcpContext_t* context = (TcpContext_t*) malloc(sizeof(TcpContext_t));    
    if(!context) {
        // printf("Failed to allocate memory for socket.\n");
        return NULL;
    }
    memset(context, 0, sizeof(TcpContext_t));

	server->context = context;


    if(tcpConfig->onConnect) {
        server->onConnect = tcpConfig->onConnect;
    }

    if(tcpConfig->onDisconnect) {
        server->onDisconnect = tcpConfig->onDisconnect;
    }

    if(tcpConfig->onServerError) {
        server->onServerError = tcpConfig->onServerError;
    }

    if(tcpConfig->onEndpointError) {
        server->onEndpointError = tcpConfig->onEndpointError;
    }

    if(tcpConfig->beforeRead) {
        context->beforeRead = tcpConfig->beforeRead;
    } else if(tcpConfig->onMessage) {
        server->onMessage = tcpConfig->onMessage;
    }

    if((ret = CreateTcpServer(server)) != LWS_ERR_OK) {
        return NULL;
    }
	
    return server;
}

static void freeEndpoints(void* endpoint) {
    TcpEndpoint_t* ptr = (TcpEndpoint_t*) endpoint;
    int fd = GET_FD(ptr->super);
	TcpContext_t* context = ptr->server->context;
	if(FD_ISSET(fd, &context->MasterFdSet)) {
        FD_CLR(fd, &context->MasterFdSet);
    }
    free(endpoint);
}

Err_t tcp_server_DeInit(TcpServer_t* server) {
    if(!server) {
        return LWS_ERR_FAIL;
    }

    if(server->endpoints) {
        linked_list_Drop(&server->endpoints, freeEndpoints);
    }

	int fd = GET_FD(server->super);

	TcpContext_t* context = (TcpContext_t*) server->context;
    if(FD_ISSET(fd, &context->MasterFdSet)) {
        FD_CLR(fd, &context->MasterFdSet);
    }

    if(close(fd)) {
		LWS_LOGE(tcp_server_DeInit, "close(%d) failed with errno=%d.", fd, errno);
    }

	free(server->super);
	free(context);
    free(server);

    return LWS_ERR_OK;
}

Err_t tcp_server_Bind(TcpServer_t* server, int port) {

	int fd = GET_FD(server->super);

    struct sockaddr_in addr;

    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return LWS_ERR_FAIL;
    }
    if (listen(fd, MAX_TCP_CLIENTS) < 0)
    {
        close(fd);
        return LWS_ERR_FAIL;
    }
    return LWS_ERR_OK;
}

Err_t tcp_server_SendMessage(TcpEndpoint_t* endpoint, unsigned char* buffer, size_t length) {
	if(tcp_server_send_raw((void*)endpoint, (const unsigned char*) buffer, length) < 0) {
		return LWS_ERR_FAIL;		
	}
    return LWS_ERR_OK;
}

static void SendMessageCallback(int index, void* endpoint, void* messageData) {
	(void) index;
    Message_t* message = (Message_t*) messageData;
    tcp_server_SendMessage((TcpEndpoint_t*) endpoint, message->data, message->size);
}

Err_t tcp_server_BroadcastMessage(TcpServer_t* server, unsigned char* buffer, size_t length) {
	if(!server || !buffer || length == 0) {
        return LWS_ERR_FAIL;
    }

    Message_t message = {
        .data = buffer,
        .size = length
    };

    linked_list_Iterate(&server->endpoints, SendMessageCallback, (void*) &message);

    return LWS_ERR_OK;
}

Err_t tcp_server_Tick(TcpServer_t* server) {

	if(!server || !server->context) return LWS_ERR_FAIL;

	TcpContext_t* context = (TcpContext_t*) server->context;
    int ret, desc_ready;
    fd_set working_set;

    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = 100*1000
    };

    memcpy(&working_set, &context->MasterFdSet, sizeof(context->MasterFdSet));
	ret = select(context->maxFd + 1, &working_set, NULL, NULL, &timeout);

    if (ret < 0) {
		LWS_LOGE(tcp_server_Tick, "select() failed.");
        return LWS_ERR_FAIL;
    } else if (ret == 0) {
		// LWS_LOGV(tcp_server_Tick, "select() timed out.");
        return LWS_ERR_OK;
    }
    desc_ready = ret;

    // Performance optimisation?
    // i = s_ListenFd
    for (SOCKET fd = 0; fd <= context->maxFd && desc_ready > 0; ++fd) {
    
        if (FD_ISSET(fd, &working_set)) {
            desc_ready -= 1;
	
	        if (fd == GET_FD(server->super)) {
                ret = HandleTcpServerFileDescriptor(server);
            } else {
                TcpEndpoint_t* endpoint = GetTcpEndpointFromFileDescriptor(server, fd);
                if(endpoint) {
					if (context->beforeRead) {
						if (!context->beforeRead(endpoint)) {
							CloseEndpoint(endpoint);
						}
					} else {
						ret = HandleTcpEndpointFileDescriptor(endpoint);
					}
                }
            }
        }
    }

    return LWS_ERR_OK;
}

Err_t tcp_server_CloseConnection(TcpEndpoint_t* endpoint) {
	return CloseEndpoint(endpoint);
}