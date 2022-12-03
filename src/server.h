#ifndef SERVER_H
#define SERVER_H

#include "stddef.h"
#include "linked_list.h"


/**
 * @brief An endpoint represents a connection client
 */
struct __endpoint_t;

/**
 * @brief An endpoint represents a connection client
 */
typedef struct __endpoint_t Endpoint_t;

/**
 * @brief A server listens to incoming connections
 */
struct __server_t;

/**
 * @brief An endpoint represents a connection client
 */
typedef struct __server_t Server_t;

typedef void (*ConnectCallback)(Endpoint_t*);
typedef void (*DisconnectCallback)(Endpoint_t*);
typedef void (*MessageCallback)(Endpoint_t*, void* message, size_t size);
typedef void (*ServerErrorCallback)(Server_t*, const unsigned char* message, size_t size);
typedef void (*EndpointErrorCallback)(Endpoint_t*, const unsigned char* message, size_t size);

/**
 * @brief Error connections
 */
typedef enum __err_t {
	/**
	 * @brief Success
	 */
	LWS_ERR_OK = 0,

	/**
	 * @brief Generic Failure
	 */
	LWS_ERR_FAIL = 1,

	/**
	 * @brief Peer has reset the connection
	 */
	LWS_ERR_CONNECTION_RESET = 2,

	/**
	 * @brief Returned by a non blocking socket.
	 */
	LWS_ERR_WOULDBLOCK,

	/**
	 * @brief The parameters passed are not valid
	 */
	LWS_ERR_PARAMETERS_INVALID,

	/**
	 * @brief Cannot fit the data in the buffer
	 */
	LWS_ERR_BUFFER_TOO_SMALL,

	/**
	 * @brief Invalid Request
	 */
	LWS_ERR_INVALID_REQUEST,

	/**
	 * @brief Invalid response
	 */
	LWS_ERR_INVALID_RESPONSE
} Err_t;

/**
 * @brief A server listens to incoming connections
 */
struct __server_t {

	/**
	 * @brief Reference to the protocol above 
	 */ 
	void* sub;

	/**
	 * @brief Reference to the underlying protocol 
	 */ 
	void* super;

	/** 
	 * @brief Reference to the protocol specific context
	 */ 
	void* context;

	/**
	 * @brief Reference to all the connected endpoints
	 */ 
	LinkedListRef* endpoints;

	/**
	 * @brief Handler for new connections
	 */
	ConnectCallback onConnect;

	/**
	 * @brief Handler for dropped connections
	 */
	DisconnectCallback onDisconnect;

	/**
	 * @brief Handler for incoming message 
	 */
	MessageCallback onMessage;

	/**
	 * @brief Handler for server errors
	 */  
	ServerErrorCallback onServerError;

	/**
	 * @brief Handler for endpoint errors
	 */  
	EndpointErrorCallback onEndpointError;

};

/**
 * @brief An endpoint represents a connection client
 */
struct __endpoint_t {

	/**
	 * @brief Reference to the protocol above 
	 */ 
	void* sub;

	/**
	 * @brief Reference to the underlying protocol 
	 */ 
	void* super;

	/** 
	 * @brief Reference to the protocol specific context
	 */ 
	void* context;

	/**
	 * @brief Reference to the connected server
	 */
	Server_t* server;

};

/**
 * @brief Container for a message
 */
typedef struct __message_t {
	/** 
	 * @brief Reference to the data
	 */ 
	void* data;

	/** 
	 * @brief Size of the data
	 */ 
	size_t size;
} Message_t;

#define ON_ENDPOINT_ERROR(client, message) 															\
do { 																								\
	if(client && client->server && client->server->onEndpointError) { 								\
        client->server->onEndpointError(client, (const unsigned char *) message, sizeof(message));	\
    }																								\
} while(0)

#define ON_SERVER_ERROR(server, message) 															\
do { 																								\
	if(server && server->onServerError) {															\
        server->onServerError(server, (const unsigned char *) message, sizeof(message));			\
    }																								\
} while(0)

#define PRINT_LOGS 0
#define LOG_LEVEL 1

#if defined(PRINT_LOGS) && PRINT_LOGS == 1

#define LOG_RED 		"\033[0;31m"
#define LOG_YELLOW 		"\033[0;33m"
#define LOG_GREEN		"\033[0;32m"
#define LOG_BLUE		"\033[0;34m"
#define LOG_CYAN		"\033[0;36m"

#define LOG_RESET 		"\033[0m"

#define LWS_LOGE(TAG, FORMAT, ...) fprintf(stderr, "[%s:%d:%s] " LOG_RED    FORMAT LOG_RESET "\n", __FILE__, __LINE__, #TAG, ##__VA_ARGS__)
#define LWS_LOGW(TAG, FORMAT, ...) fprintf(stderr, "[%s:%d:%s] " LOG_YELLOW FORMAT LOG_RESET "\n", __FILE__, __LINE__, #TAG, ##__VA_ARGS__)
#define LWS_LOGI(TAG, FORMAT, ...) fprintf(stdout, "[%s:%d:%s] " LOG_GREEN  FORMAT LOG_RESET "\n", __FILE__, __LINE__, #TAG, ##__VA_ARGS__)
#define LWS_LOGD(TAG, FORMAT, ...) fprintf(stdout, "[%s:%d:%s] " LOG_BLUE   FORMAT LOG_RESET "\n", __FILE__, __LINE__, #TAG, ##__VA_ARGS__)
#define LWS_LOGV(TAG, FORMAT, ...) fprintf(stdout, "[%s:%d:%s] " LOG_CYAN   FORMAT LOG_RESET "\n", __FILE__, __LINE__, #TAG, ##__VA_ARGS__)
#else 
#define LWS_LOGE(TAG, FORMAT, ...)
#define LWS_LOGW(TAG, FORMAT, ...)
#define LWS_LOGI(TAG, FORMAT, ...)
#define LWS_LOGD(TAG, FORMAT, ...)
#define LWS_LOGV(TAG, FORMAT, ...)
#endif

#endif // SERVER_H
