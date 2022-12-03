#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include "server.h"

#define MAX_TCP_CLIENTS 5

#define GET_FD(super) *((int*) super)


#if BUILD_TARGET_LINUX || BUILD_TARGET_ESP32
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define GetErrorNo() errno

#define SOCKET_FORMAT "%d"
#define SOCKET_WOULDBLOCK EWOULDBLOCK
#define SOCKET_ENFILE ENFILE
#define SOCKET_ECONNRESET ECONNRESET

typedef int SOCKET;

#elif BUILD_TARGET_WINDOWS
#include <winsock2.h>

#define close closesocket
#define GetErrorNo() WSAGetLastError()

#define SOCKET_FORMAT "%lu"
#define SOCKET_WOULDBLOCK WSAEWOULDBLOCK
#define SOCKET_ENFILE WSAEMFILE
#define SOCKET_ECONNRESET WSAECONNRESET

#endif


typedef Endpoint_t TcpEndpoint_t;

typedef Server_t TcpServer_t;

typedef bool (*PreReadCallback)(Endpoint_t*);

/**
 * @brief Configuration for a TCP Server
 */ 
typedef struct {
	/**
	 * @brief Handler for a new WS endpoint connection
	 */
    ConnectCallback onConnect;

	/**
	 * @brief Handler for a new WS endpoint disconnection
	 */
    DisconnectCallback onDisconnect;

	/**
	 * @brief Handler for a new WS endpoint message
	 */
    MessageCallback onMessage;

	/**
	 * @brief Handler for a WS server error
	 */
    ServerErrorCallback onServerError;

	/**
	 * @brief Handler for a WS endpoint error
	 */
    EndpointErrorCallback onEndpointError;

	/**
	 * @brief Handler when a client is ready with a message.
	 */	
	PreReadCallback beforeRead;
} TcpServerConfig_t;

/**
 * @brief Context information for a TCP Server
 */ 
typedef struct {
	/**
	 * @brief max fd for the TCP endpoints
	 */	
	int maxFd;

	/**
	 * @brief FdSet for the connection TCP connections
	 */	
	fd_set MasterFdSet;

	/**
	 * @brief Handler when a client is ready with a message.
	 */	
	PreReadCallback beforeRead;
} TcpContext_t;

/**
 * @brief Initialise TCP Server. Allocate resources.
 * 
 * @param tcpConfig TcpServerConfig instance
 * 
 * @return TcpServer_t* Instance of TcpServer. NULL otherwise.
 */
TcpServer_t* tcp_server_Init(TcpServerConfig_t* tcpConfig);

/**
 * @brief Deinitialise TCP Server. Free up resources.
 * @param tcpServer Pointer to TcpServer instance
 * 
 * @return TCP_OK on success.
 * 
 */
Err_t tcp_server_DeInit(TcpServer_t* tcpServer);

/**
 * @brief Bind the Tcp Server to the given port
 * 
 * @param server TCPServer instance
 * @param port Port number to which to bind to
 * 
 * @return TCP_OK on success.
 * 
 */ 
Err_t tcp_server_Bind(TcpServer_t* server, int port);

/**
 * @brief Send Message to TCP Client
 * 
 * @param endpoint Receipent TCP Client
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return TCP_OK on success.
 * 
 */ 
Err_t tcp_server_SendMessage(TcpEndpoint_t* endpoint, unsigned char* buffer, size_t length);

/**
 * @brief Broadcast Message to all TCP Client
 * 
 * @param server TCP Server
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return TCP_OK on success.
 * 
 */ 
Err_t tcp_server_BroadcastMessage(TcpServer_t* server, unsigned char* buffer, size_t length);

/**
 * @brief Tick Function for TCP Server.
 *        Call this function repeatedly for the TCP Server to process its' events.
 * 
 * @param server TCPServer instance
 * 
 * @return TCP_OK on success.
 * 
 */ 
Err_t tcp_server_Tick(TcpServer_t* server);

/**
 * @brief Close connection TCP Endpoint.
 * 
 * @param endpoint TCPEndpoint instance
 * 
 * @return TCP_OK on success.
 * 
 */ 
Err_t tcp_server_CloseConnection(TcpEndpoint_t* endpoint);

/**
 * @brief Send to TCP Endpoint stream
 * 
 * @param tcpEndpoint TCPEndpoint instance
 * @param buf Buffer
 * @param len Length of the buffer
 * 
 * @return TCP_OK on success.
 * 
 */ 
int tcp_server_send_raw(void *tcpEndpoint, const unsigned char *buf, size_t len);

/**
 * @brief Receive from TCP Endpoint stream.
 * 
 * @param tcpEndpoint TCPEndpoint instance
 * @param buf Buffer
 * @param len Length of the buffer
 *  
 * @return TCP_OK on success.
 * 
 */ 
int tcp_server_receive_raw(void *tcpEndpoint, unsigned char *buf, size_t len);

#endif // TCP_SERVER_H
