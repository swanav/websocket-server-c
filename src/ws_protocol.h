#ifndef WEBSOCKET_PROTOCOL_H
#define WEBSOCKET_PROTOCOL_H

#include "server.h"
#include "ws_server.h"

#define WS_FRAME_MIN_FLAG_LENGTH 2

#define FLAG_OFFSET              0
#define OPCODE_OFFSET            0
#define FLAG_OPCODE_OFFSET       0

#define MASK_OFFSET              1
#define LENGTH_OFFSET            1
#define LENGTH_IS_TWO_BYTE       0x7E
#define LENGTH_IS_EIGHT_BYTE     0x7F

#define LENGTH_ONE_BYTE_LIMIT 0x7D
#define LENGTH_TWO_BYTE_LIMIT 0xFFFF

#define MASK_LENGTH              4
#define WS_MIN_CLIENT_FRAME_LENGTH WS_FRAME_MIN_FLAG_LENGTH + MASK_LENGTH
#define WS_MIN_SERVER_FRAME_LENGTH WS_FRAME_MIN_FLAG_LENGTH

#define FIN(flags)  ((flags >> 7) & 0x01)
#define MASK(flags) ((flags >> 7) & 0x01)
#define OPCODE(flags) (flags & 0x0F)

#define IS_LAST_FRAME(flags)          ((flags >> 7) & 0x01)
#define IS_CONTINUATION_FRAME(flags)  (OPCODE(flags) == OP_CONTINUE)
#define IS_CONTROL_FRAME(flags)       ((OPCODE(flags) == OP_PING) || \
                                       (OPCODE(flags) == OP_PONG) || \
                                       (OPCODE(flags) == OP_CONNECTION_CLOSE))

#define WEBSOCKET_HANDSHAKE_MAGIC_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/**
 * @brief Transport protocol used for the Websocket Server
 */
typedef enum {

	/**
	 * @brief TCP
	 */
	WS_TRANSPORT_TCP,

	/**
	 * @brief TLS
	 */
	WS_TRANSPORT_TLS
} WsTransport_t ;

/**
 * @brief Context information for a websocket connection
 */
typedef struct {

	/**
	 * @brief Transport protocol for WS connection
	 */
	WsTransport_t transport:1;

	/**
	 * @brief WS Handshake completed?
	 */
	bool handshakeComplete:1;

	/**
	 * @brief Opcode of defragmented message
	 */
	WsOpCode_t defragmentedOpcode;

	/**
	 * @brief Length of defragmented message
	 */
	uint64_t defragmentedLength;

	/**
	 * @brief Defragmented message
	 */
	unsigned char* defragmentedMessage;
	
} WsContext_t;

/**
 * @brief Metadata to contain the websocket request parsing details
 */
struct __websocket_request_parser_meta {
	/**
	 * @brief Sec-Websocket-Key
	 */
	const char* SecWebsocketKey;

	/**
	 * @brief Length of Sec-Websocket-Key
	 */
	size_t SecWebsocketKeyLength;

	/**
	 * @brief Previous header
	 */
	const char* lastHeader;

	/**
	 * @brief Length of the Previous header
	 */
	size_t lastHeaderLength;
};

#define WS_SERVER_TRANSPORT(server) ( (WsContext_t*) server->context)->transport

int64_t ws_server_GetDataLength(unsigned char* buffer, size_t len, unsigned char* dataLengthOffset);

int ws_PrepareFrame(unsigned char* output, int outputSize, int fin, int opcode, const unsigned char* data, size_t length);

Err_t ParseHttpWebsocketUpgradeRequest(struct __websocket_request_parser_meta* parserMeta, 
		unsigned char* input, int inputLength);

Err_t PrepareHttpWebsocketUpgradeResponse(struct __websocket_request_parser_meta* parserMeta, 
		unsigned char* response, size_t responseSize, int* responseLength);

void onTransportEndpointConnect(Endpoint_t* client);
void onTransportEndpointDisconnect(Endpoint_t* client);
void onTransportServerError(Server_t* server, const unsigned char* payload, size_t length);
void onTransportEndpointError(Endpoint_t* client, const unsigned char* payload, size_t length);
void onTransportEndpointMessage(Endpoint_t* client, void* payload, size_t length);
#endif // WEBSOCKET_PROTOCOL_H
