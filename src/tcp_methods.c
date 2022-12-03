#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

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

static TcpEndpoint_t* CreateTcpEndpoint(TcpServer_t* server, SOCKET endpointFd) {
	TcpContext_t* context = (TcpContext_t*) server->context;
    TcpEndpoint_t* newEndpoint = (TcpEndpoint_t*) malloc(sizeof(TcpEndpoint_t));
    if(!newEndpoint) {
        return NULL;
    } 
    memset(newEndpoint, 0, sizeof(TcpEndpoint_t));
	int* super = (int*) malloc(sizeof(int));
	*super = endpointFd;
    newEndpoint->super = (void*) super;
    newEndpoint->server = server;
    
    linked_list_Insert(&newEndpoint->server->endpoints, (void*) newEndpoint);

    FD_SET(endpointFd, &context->MasterFdSet);
    if (endpointFd > context->maxFd) {
        context->maxFd = endpointFd;
    }

#if BUILD_TARGET_LINUX || BUILD_TARGET_ESP32
    // Set timeout for recv
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(endpointFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
#endif
    return newEndpoint;
}

static Err_t OnEndpointConnect(TcpServer_t* server, SOCKET endpointFd) {

	LWS_LOGV(OnEndpointConnect, "Received new connection at fd=%d.", endpointFd);

    TcpEndpoint_t* endpoint = CreateTcpEndpoint(server, endpointFd);

    if(server && server->onConnect) {
        server->onConnect(endpoint);
    }

	LWS_LOGD(OnEndpointConnect, "TCP Endpoint %d Connected.", endpointFd);

    return LWS_ERR_OK;
}

static Err_t OnEndpointDisconnect(TcpEndpoint_t* endpoint) {
	LWS_LOGD(OnEndpointDisconnect, "TCP Endpoint %d Disconnected.", GET_FD(endpoint->super));
    if(endpoint && endpoint->server && endpoint->server->onDisconnect) {
        endpoint->server->onDisconnect(endpoint);
        return LWS_ERR_OK;
    }
    return LWS_ERR_FAIL;
}

static Err_t OnEndpointMessage(TcpEndpoint_t* endpoint, unsigned char* buffer, int length) {
	LWS_LOGD(OnEndpointMessage, "TCP Message from endpoint %d. %d bytes.", GET_FD(endpoint->super), length);
	if(endpoint && endpoint->server && endpoint->server->onMessage) {
        endpoint->server->onMessage(endpoint, buffer, length);
        return LWS_ERR_OK;
    }
    return LWS_ERR_FAIL;
}



Err_t CreateTcpServer(TcpServer_t* server) {

	int enable = true;
#if BUILD_TARGET_WINDOWS
    WSADATA wsaData;
    int iResult;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
        LWS_LOGE(CreateTcpServer, "Error at WSAStartup()");
    }
#endif

	int fd = socket(AF_INET, SOCK_STREAM, 0);

	int* super = (int*) malloc(sizeof(int));
	*super = fd;

    server->super = (void*) super; 

    if (fd == INVALID_SOCKET) {
        LWS_LOGE(CreateTcpServer, "Failed to create socket.");
        return LWS_ERR_FAIL;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&enable, sizeof(enable)) < 0) {
		LWS_LOGE(CreateTcpServer, "Failed to set socket option.");
        close(fd);
        return LWS_ERR_FAIL;
    }

#if BUILD_TARGET_LINUX || BUILD_TARGET_ESP32
    if (ioctl(fd, FIONBIO, (char *)&enable) < 0)
#elif  BUILD_TARGET_WINDOWS
    if(ioctlsocket(fd, FIONBIO, &enable) == SOCKET_ERROR)
#endif
    {
		LWS_LOGE(CreateTcpServer, "ioctl() failed.");
        close(fd);
        return LWS_ERR_FAIL;
    }

	TcpContext_t* context = (TcpContext_t*) server->context;

	context->maxFd = fd;
	FD_ZERO(&context->MasterFdSet);
    FD_SET(fd, &context->MasterFdSet);

	return LWS_ERR_OK;

}

Err_t CloseEndpoint(TcpEndpoint_t* endpoint) {

    if(!endpoint) {
        return LWS_ERR_FAIL;
    }

    OnEndpointDisconnect(endpoint);

    linked_list_Remove(&endpoint->server->endpoints, (void*) endpoint);

	int fd = GET_FD(endpoint->super);

	TcpContext_t* context = (TcpContext_t*) endpoint->server->context;
    if(FD_ISSET(fd, &context->MasterFdSet)) {
        FD_CLR(fd,  &context->MasterFdSet);
    }

#if BUILD_TARGET_LINUX || BUILD_TARGET_ESP32
	// SHUT_RDWR - Stop both reception and transmission.
    if(shutdown(fd, SHUT_RDWR)) { 
		LWS_LOGE(CloseEndpoint, "shutdown(%d, SHUT_RDWR) failed with errno=%d.", fd, errno);
    }
#endif

    if(close(fd)) {
		LWS_LOGE(CloseEndpoint, "close(%d) failed with errno=%d.", fd, errno);
    }

    if (fd == context->maxFd)
    {
        while (FD_ISSET(context->maxFd, &context->MasterFdSet) == false)
            context->maxFd -= 1;
    }

	free(endpoint->super);
    free(endpoint);

    return LWS_ERR_OK;
}

static bool TcpEndpointFdTest(void* item, void* userData) {
    int fd = *((int*) userData);
    return *((int*)((TcpEndpoint_t*) item)->super) == fd;
}

TcpEndpoint_t* GetTcpEndpointFromFileDescriptor(TcpServer_t* server, const int fd) {
    
    if(!server || *((int*)server->super) == fd) {
        return NULL;
    }

    return linked_list_Search(&server->endpoints, TcpEndpointFdTest, (void*) &fd);
}


Err_t HandleTcpServerFileDescriptor(TcpServer_t* server) {
    SOCKET new_sd;
    do {
		int fd = GET_FD(server->super);
        new_sd = accept(fd, NULL, NULL);

        if (new_sd == INVALID_SOCKET) {
            int err = GetErrorNo();
            if (err != SOCKET_WOULDBLOCK) {
                if(err == SOCKET_ENFILE) {
					LWS_LOGE(HandleTcpServerFileDescriptor, "accept(%d) failed. (%d) Too many open connections.", fd, errno);
                } else {
                    LWS_LOGE(HandleTcpServerFileDescriptor, "accept(%d) failed. errno=%d\n", fd, err);
                }
                return LWS_ERR_FAIL;
            }
            break;
        }
#if  BUILD_TARGET_WINDOWS
        int enable = 1;
        if(ioctlsocket(new_sd, FIONBIO, &enable) == SOCKET_ERROR) {
            closesocket(new_sd);
            return TCP_IOCTL_FAIL;
        }
#endif
        OnEndpointConnect(server, new_sd);
    } while (new_sd != SOCKET_WOULDBLOCK);

    return LWS_ERR_OK;
}

Err_t HandleTcpEndpointFileDescriptor(TcpEndpoint_t* endpoint) {
    int ret;
    char buffer[1024];
    do {
	    memset(buffer, 0, 1024);
		ret = tcp_server_receive_raw((void*)endpoint, (unsigned char *) buffer, sizeof(buffer));
		if(ret < 0) {
			if(ret == -LWS_ERR_WOULDBLOCK) {
				break;
			} else {
				LWS_LOGE(HandleTcpEndpointFileDescriptor, "tcp_server_receive_raw() ret=%d.", ret);
				return CloseEndpoint(endpoint);
			}
		} else if(ret == 0) {
			return CloseEndpoint(endpoint);
		} else {
			return OnEndpointMessage(endpoint, (unsigned char*) buffer, ret);
		}
    } while (true);

    return LWS_ERR_OK;
}

int tcp_server_receive_raw(void *tcpEndpoint, unsigned char *buf, size_t len) {
	int ret;
    int fd = GET_FD(((TcpEndpoint_t *) tcpEndpoint)->super);

    if( fd < 0 )
        return( -LWS_ERR_FAIL );

    ret = (int) recv( fd, buf, len, MSG_DONTWAIT );

	if (ret == SOCKET_ERROR) {   
		int err = GetErrorNo();
		if (err == SOCKET_WOULDBLOCK) {
			return( -LWS_ERR_WOULDBLOCK );
		} else {
			if(err == SOCKET_ECONNRESET) {
				LWS_LOGE(tcp_server_receive_raw, "recv(%d) failed. Connection reset by Peer.", fd);
				return( -LWS_ERR_CONNECTION_RESET );
			}

			LWS_LOGE(tcp_server_receive_raw, "recv(%d) failed. errno=%d", fd, err);
			return -LWS_ERR_FAIL;
		}
	}

    return( ret );
}



int tcp_server_send_raw(void *tcpEndpoint, const unsigned char *buf, size_t len) {
	int ret;
    int fd = GET_FD(((TcpEndpoint_t *) tcpEndpoint)->super);

    if( fd < 0 )
        return( -LWS_ERR_FAIL );

    ret = (int) send( fd, buf, len, 0 );

	if (ret == SOCKET_ERROR) {   
		int err = GetErrorNo();
		if (err == SOCKET_WOULDBLOCK) {
			return( -LWS_ERR_WOULDBLOCK );
		} else {
			if(err == SOCKET_ECONNRESET) {
				LWS_LOGE(tcp_server_send_raw, "send(%d) failed. Connection reset by Peer.", fd);
				return( -LWS_ERR_CONNECTION_RESET );
			}

			LWS_LOGE(tcp_server_send_raw, "send(%d) failed. errno=%d", fd, err);
			return -LWS_ERR_FAIL;
		}
	}

    return( ret );
}
