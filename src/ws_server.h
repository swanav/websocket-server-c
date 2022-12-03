/**
 * 
 *     FRAME FORMAT FOR A WEBSOCKET PACKET ON TOP OF TCP/IP
 * 
 *       0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-------+-+-------------+-------------------------------+
 *   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 *   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 *   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 *   | |1|2|3|       |K|             |                               |
 *   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 *   |     Extended payload length continued, if payload len == 127  |
 *   + - - - - - - - - - - - - - - - +-------------------------------+
 *   |                               |Masking-key, if MASK set to 1  |
 *   +-------------------------------+-------------------------------+
 *   | Masking-key (continued)       |          Payload Data         |
 *   +-------------------------------- - - - - - - - - - - - - - - - +
 *   :                     Payload Data continued ...                :
 *   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *   |                     Payload Data continued ...                |
 *   +---------------------------------------------------------------+
 * 
 * 
 */

#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include "linked_list.h"
#include "server.h"
#include "tcp_server.h"
#include "tls_server.h"

#define MAX_WS_PAYLOAD_SIZE 256

#if MAX_WS_PAYLOAD_SIZE < 126
#define MAX_WS_HEADER_SIZE 2
#elif MAX_WS_PAYLOAD_SIZE < 65535
#define MAX_WS_HEADER_SIZE 4
#else
#define MAX_WS_HEADER_SIZE 10
#endif


#define WS_FIN(x)       ( x & 0x07 )
#define WS_MASK(x)      ( x & 0x07 )
#define WS_OPCODE(x)    ( x & 0x0F )


/**
  *  @brief Websocket Opcode 
  */
typedef enum __ws_opcode_t {
    /**
      * @brief Denotes a continuation frame
      */
    OP_CONTINUE = 0x00,
    
    /**
      * @brief Denotes a text frame
      */
    OP_TEXT,
    
    /**
      * @brief Denotes a binary frame
      */
    OP_BINARY,
    
    /**
      * @brief Denotes a connection close
      */
    OP_CONNECTION_CLOSE = 0x08,
    
    /**
      * @brief Denotes a ping
      */
    OP_PING,
    
    /**
      * @brief Denotes a pong
      */
    OP_PONG
} WsOpCode_t;


/**
 * @brief Websocket Connection Close Reason
 */
typedef enum __ws_close_reason_t {

    /** 
     * @brief 1000 indicates a normal closure, meaning that the purpose for
     * which the connection was established has been fulfilled. 
     */
    WS_CLOSE_OK = 1000,

    /**
     * @brief 1001 indicates that an endpoint is "going away", such as a server
     * going down or a browser having navigated away from a page.
     */
    WS_CLOSE_NAVIGATE_AWAY = 1001,

    /**
     * @brief 1002 indicates that an endpoint is terminating the connection due
     * to a protocol error.
     */
    WS_CLOSE_PROTOCOL_ERROR = 1002,
    
    /**
     * @brief 1003 indicates that an endpoint is terminating the connection
     * because it has received a type of data it cannot accept (e.g., an
     * endpoint that understands only text data MAY send this if it
     * receives a binary message).
     */
    WS_CLOSE_UNKNOWN_FORMAT = 1003,
    
    /**
     * @brief Reserved. The specific meaning might be defined in the future.
     */
    __WS_CLOSE_RESERVED = 1004,
    
    /**
     * @brief 1005 is a reserved value and MUST NOT be set as a status code in a
     * Close control frame by an endpoint.  It is designated for use in
     * applications expecting a status code to indicate that no status
     * code was actually present.
     */
    __WS_CLOSE_OK = 1005,
    
    /**
     * @brief 1006 is a reserved value and MUST NOT be set as a status code in a
     * Close control frame by an endpoint.  It is designated for use in
     * applications expecting a status code to indicate that the
     * connection was closed abnormally, e.g., without sending or
     * receiving a Close control frame.
     */
    __WS_CLOSE_FAIL = 1006,
    
    /**
     * @brief 1007 indicates that an endpoint is terminating the connection
     * because it has received data within a message that was not
     * consistent with the type of the message (e.g., non-UTF-8 [RFC3629]
     * data within a text message).
     */
    WS_CLOSE_INVALID_FORMAT = 1007,
    
    /**
     * @brief 1008 indicates that an endpoint is terminating the connection
     * because it has received a message that violates its policy.  This
     * is a generic status code that can be returned when there is no
     * other more suitable status code (e.g., 1003 or 1009) or if there
     * is a need to hide specific details about the policy.
     */
    WS_CLOSE_POLICY_VIOLATION = 1008,
    
    /**
     * @brief 1009 indicates that an endpoint is terminating the connection
     * because it has received a message that is too big for it to
     * process.
     */
    WS_CLOSE_MESSAGE_TOO_BIG = 1009,
    
    /**
     * @brief 1010 indicates that an endpoint (client) is terminating the
     * connection because it has expected the server to negotiate one or
     * more extension, but the server didn't return them in the response
     * message of the WebSocket handshake.  The list of extensions that
     * are needed SHOULD appear in the /reason/ part of the Close frame.
     * Note that this status code is not used by the server, because it
     * can fail the WebSocket handshake instead.
     */
    WS_CLOSE_UNKNOWN_EXTENSION = 1010,
    
    /**
     * @brief 1011 indicates that a server is terminating the connection because
     * it encountered an unexpected condition that prevented it from
     * fulfilling the request.
     */
    WS_CLOSE_UNEXPECTED = 1011,
    
    /**
     * @brief 1015 is a reserved value and MUST NOT be set as a status code in a
     * Close control frame by an endpoint.  It is designated for use in
     * applications expecting a status code to indicate that the
     * connection was closed due to a failure to perform a TLS handshake
     * (e.g., the server certificate can't be verified).
     */
    __WS_CLOSE_TLS_FAILED = 1015
} WsCloseReason_t;


typedef Endpoint_t WsEndpoint_t;
typedef Server_t WsServer_t;

/**
 * @brief Container for WS Message
 */
typedef struct __ws_message_t {
    /**
	  * @brief Opcode of the WS message
	  */
	WsOpCode_t opcode;
   
   	/**
	  * @brief Buffer (Binary or String)
	  */ 
	unsigned char* buffer;
   	
	/** 
	  * @brief Length of buffer
	  */
    size_t length;

} WsMessage_t;

/**
 * @brief Server Config for a WS Server
 */
typedef struct __ws_server_config_t {
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
} WsServerConfig_t;


/**
 * @brief Initialise WS Server. Allocate resources.
 * 
 * @param config WsServerConfig instance
 * @param certs Certificate Data for WSS server. NULL for WS Server
 *
 * @return WsServer_t* Instance of WsServer. NULL otherwise.
 */
WsServer_t* ws_server_Init(WsServerConfig_t* config, CertificateData* certs);


/**
 * @brief Deinitialise WS Server. Free up resources.
 * @param server Pointer to WsServer instance
 * 
 * @return WS_OK on success.
 * 
 */
Err_t ws_server_DeInit(WsServer_t* server);


/**
 * @brief Bind the WS Server to the given port
 * 
 * @param server WsServer instance
 * @param port Port number to which to bind to
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_Bind(WsServer_t* server, int port);

/**
 * @brief Send a message over websocket
 * 
 * @param endpoint Instance to Ws endpoint
 * @param opcode Opcode
 * @param buffer Buffer to send 
 * @param length Length of buffer
 * 
 * @return WS_OK on success
 */
Err_t ws_server_SendMessage(WsEndpoint_t* endpoint, WsOpCode_t opcode, unsigned char* buffer, size_t length);

/**
 * @brief Send a message to all clients connected to websocket server
 * 
 * @param server Instance to Ws server
 * @param opcode Opcode
 * @param buffer Buffer to send 
 * @param length Length of buffer
 * 
 * @return WS_OK on success
 */
Err_t ws_server_BroadcastMessage(WsServer_t* server, WsOpCode_t opcode, unsigned char* buffer, size_t length);

/**
 * @brief Send Text Message to WS endpoint
 * 
 * @param endpoint Receipent WS endpoint
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_SendTextMessage(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length);

/**
 * @brief Broadcast Text Message to all WS endpoints connected to Server
 * 
 * @param server WS Server
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_BroadcastTextMessage(WsServer_t* server, unsigned char* buffer, size_t length);
/**
 * @brief Send Binary Message to WS endpoint
 * 
 * @param endpoint Receipent WS endpoint
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_SendBinaryMessage(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length);

/**
 * @brief Broadcast Binary Message to all WS Clients connected to Server
 * 
 * @param server WS Server
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_BroadcastBinaryMessage(WsServer_t* server, unsigned char* buffer, size_t length);

/**
 * @brief Send a ping to the endpoint
 * 
 * @param endpoint Receipent WS endpoint
 * @param buffer Buffer to expect in pong response
 * @param length Length of buffer
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_SendPing(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length);


/**
 * @brief Send Binary Message to WS endpoint
 * 
 * @param endpoint Receipent WS endpoint
 * @param buffer Buffer to respond with according to the ping response
 * @param length Length of buffer
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_SendPong(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length);

/**
 * @brief Send Close Message to WS endpoint
 * 
 * @param endpoint Receipent WS endpoint
 * @param reason Reason for closing the connection
 * 
 * @return ERR_OK on success.
 * 
 */ 
Err_t ws_server_SendCloseMessage(WsEndpoint_t* endpoint, WsCloseReason_t reason);


/**
 * @brief Tick Function for WS Server.
 *        Call this function repeatedly for the WS Server to process its' events.
 * 
 * @param server WsServer instance
 * 
 * @return WS_OK on success.
 * 
 */ 
Err_t ws_server_Tick(WsServer_t* server);

/**
 * @brief Close connection WS Endpoint.
 * 
 * @param endpoint WsEndpoint_t instance
 * 
 * @return LWS_ERR_OK on success.
 * 
 */ 
Err_t ws_server_CloseConnection(WsEndpoint_t* endpoint);

#endif // WEBSOCKET_SERVER_H
