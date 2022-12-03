#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <ctype.h>

#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "llhttp.h"

#include "string_utils.h"

#include "ws_protocol.h"
#include "ws_server.h"


int64_t ws_server_GetDataLength(unsigned char* buffer, size_t len, unsigned char* dataLengthOffset) {
    
    int64_t outputSize = 0;

    if(len < 2 || !dataLengthOffset) {
        return -LWS_ERR_FAIL;
    } 
    
    outputSize = (buffer[1] & 0x7F);
    if(outputSize > 0x7F) {
        return -LWS_ERR_FAIL;
    }
    
    uint8_t length_bytes = 0;
    if(outputSize >= 0x7E) {
        length_bytes = (outputSize==0x7E) ? 2 : 8;
        outputSize = 0;
        for(int i = 0; i < length_bytes; i++) {
            outputSize |= (outputSize << 8) | buffer[2+i];
        }
    }
    *dataLengthOffset = length_bytes;
    return outputSize;
}

/**
 * @brief Get Pointer to Mask from the buffer based on Websocket Frame Format
 * 
 * @param buffer            Complete Websocket Frame
 * @param len               Length of the Frame buffer
 * @param dataLengthOffset  Number of bytes used to store the length of the payload data
 * 
 * @returns pointer to mask from the buffer, NULL on error
 * 
 */ 
static unsigned char* ws_server_GetMask(unsigned char* buffer, size_t len, uint32_t dataLengthOffset) {
    if(len < WS_FRAME_MIN_FLAG_LENGTH + dataLengthOffset + MASK_LENGTH) {
        return NULL;
    }

    if(!MASK(buffer[MASK_OFFSET])) {
				LWS_LOGE(ws_server_GetMask, "Input not masked\n");
        return NULL;
    }    

    return buffer + ( WS_FRAME_MIN_FLAG_LENGTH + dataLengthOffset ) * sizeof(unsigned char);
} 

/**
 * @brief Unmask Payload Received from Client
 * @param message Pointer to start of masked payload
 * @param length  Length of payload
 * @param mask    Pointer to char with 4-byte mask 
 * 
 * @returns WS_OK on success, WS_FAIL on failure
 */
static Err_t ws_server_unmaskMessage(unsigned char* message, size_t length, unsigned char* mask) {

    if(!message || !mask) {
        return LWS_ERR_FAIL;
    }

    for(size_t i = 0; i < length; i++) {
        message[i] = message[i] ^ mask[(i) % 4];
    }

    return LWS_ERR_OK;    
}

int handle_on_header_field(llhttp_t* parser, const char *header, size_t length) {
	struct __websocket_request_parser_meta* meta = parser->data;
	meta->lastHeader = header;
	meta->lastHeaderLength = length;
	return 0;
}

int handle_on_header_value(llhttp_t* parser, const char *value, size_t length) {
	struct __websocket_request_parser_meta* meta = parser->data;
	// fprintf(stdout, "[#] %.*s: %.*s\r\n", (int) meta->lastHeaderLength, meta->lastHeader, (int) length, value);

	/*
    4.  The request MUST contain a |Host| header field whose value
        contains /host/ plus optionally ":" followed by /port/ (when not
        using the default port).
	*/
	if ( !strncmp("Host", meta->lastHeader, meta->lastHeaderLength) ) {
		// Additional validation for Host
		return 0;
	}

	/*    
	5. The request MUST contain an |Upgrade| header field whose value
		MUST include the "websocket" keyword. 
	*/
	if ( !strncmp("Upgrade", meta->lastHeader, meta->lastHeaderLength) ) {
		if ( strncmp("websocket", value, length) ) {
		llhttp_set_error_reason(parser, "Upgrade must be websocket");
			return -1;
		}
	}

	/*
	6. The request MUST contain a |Connection| header field whose value
		MUST include the "Upgrade" token. 
	*/
	if ( !strncmp("Connection", meta->lastHeader, meta->lastHeaderLength) ) {
		if ( strncmp("Upgrade", value, length) ) {
			llhttp_set_error_reason(parser, "Connection must be Upgrade");
			return -1;
		}
	}

	/*
	7.   The request MUST include a header field with the name
        |Sec-WebSocket-Key|.  The value of this header field MUST be a
        nonce consisting of a randomly selected 16-byte value that has
        been base64-encoded (see Section 4 of [RFC4648]).  The nonce
        MUST be selected randomly for each connection.

        NOTE: As an example, if the randomly selected value was the
        sequence of bytes 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09
        0x0a 0x0b 0x0c 0x0d 0x0e 0x0f 0x10, the value of the header
        field would be "AQIDBAUGBwgJCgsMDQ4PEC=="
	*/
	if ( !strncmp("Sec-WebSocket-Key", meta->lastHeader, meta->lastHeaderLength) ) {
		meta->SecWebsocketKey = value;
		meta->SecWebsocketKeyLength = length;
		return 0;
	}

	/*
	9.   The request MUST include a header field with the name
        |Sec-WebSocket-Version|.  The value of this header field MUST be
        13.

        NOTE: Although draft versions of this document (-09, -10, -11,
        and -12) were posted (they were mostly comprised of editorial
        changes and clarifications and not changes to the wire
        protocol), values 9, 10, 11, and 12 were not used as valid
        values for Sec-WebSocket-Version.  These values were reserved in
        the IANA registry but were not and will not be used.
	*/
	if ( !strncmp("Sec-WebSocket-Version", meta->lastHeader, meta->lastHeaderLength) ) {
		if ( atoi(value) != 13 ) {
			llhttp_set_error_reason(parser, "Sec-WebSocket-Version must be 13");
			return -1;
		}
	}

	return 0;
}


Err_t ParseHttpWebsocketUpgradeRequest(struct __websocket_request_parser_meta* parserMeta, unsigned char* input, int inputLength) {
	llhttp_t parser;
	llhttp_settings_t settings;
	Err_t ret = LWS_ERR_FAIL;

	llhttp_settings_init(&settings);
	settings.on_header_field = handle_on_header_field;
	settings.on_header_value = handle_on_header_value;
	llhttp_init(&parser, HTTP_REQUEST, &settings);

	parser.data = (void*) parserMeta;

	enum llhttp_errno err = llhttp_execute(&parser, (const char*) input, inputLength);
	/*
	   1.   The handshake MUST be a valid HTTP request as specified by
        [RFC2616].
	*/
	if(err == HPE_PAUSED_UPGRADE) {
	/*
	   2.   The method of the request MUST be GET, and the HTTP version MUST
        be at least 1.1.
	*/	
		if(parser.method == HTTP_GET && parser.http_major == 1 && parser.http_minor >=1 && parserMeta->SecWebsocketKeyLength == 24) {
			// fprintf(stdout, "======\nValid Upgrade request. %d bytes, Sec-Websocket-Key: %.*s\n=======\n", 
			// 	(int) parserMeta->SecWebsocketKeyLength, (int) parserMeta->SecWebsocketKeyLength, parserMeta->SecWebsocketKey);
			ret = LWS_ERR_OK;
		}
	} else {
		// fprintf(stderr, "Parsing failed: %s %s\n", llhttp_errno_name(err), parser.reason);
		ret = LWS_ERR_FAIL;
	}

	err = llhttp_finish(&parser);

	return ret;
}

bool websocket_handshake_IsComplete(WsEndpoint_t* endpoint) {
	return ((WsContext_t*) endpoint->context)->handshakeComplete;
}

Err_t PrepareHttpWebsocketUpgradeResponse(struct __websocket_request_parser_meta* parserMeta, 
		unsigned char* response, size_t responseSize, int* responseLength) {
	Err_t ret = LWS_ERR_OK;
	char toHash[64] = { 0 };
    unsigned char hashedOutput[20] = { 0 }, finalOutput[30] = { 0 };
    size_t olen = 0;

	unsigned char responseFormat[] = 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n";
	
	snprintf(toHash, sizeof(toHash), "%.*s%s", (int) parserMeta->SecWebsocketKeyLength, parserMeta->SecWebsocketKey, WEBSOCKET_HANDSHAKE_MAGIC_KEY);

    if(mbedtls_sha1((unsigned char*) toHash, strlen(toHash), hashedOutput)) {
		return LWS_ERR_FAIL;
	}

    if(mbedtls_base64_encode(finalOutput, sizeof(finalOutput), &olen, hashedOutput, sizeof(hashedOutput))) {
        return LWS_ERR_FAIL;
    }
  
    snprintf((char*) response, responseSize, (const char*) responseFormat, finalOutput);
	*responseLength = strlen((char*) response);

	return ret;
}

Err_t websocket_handshake(WsEndpoint_t* endpoint, unsigned char* input, int inputLength) {

	Err_t ret = LWS_ERR_OK;
	unsigned char response[200];
	int responseLength = 0;
	struct __websocket_request_parser_meta parserMeta = { 0 };

	if(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, inputLength) != LWS_ERR_OK) {
		// Handle Error
		ret = LWS_ERR_INVALID_REQUEST;
	}

	if(ret == LWS_ERR_OK && PrepareHttpWebsocketUpgradeResponse(&parserMeta, response, sizeof(response), &responseLength) != LWS_ERR_OK) {
		// Handle Error
		ret = LWS_ERR_INVALID_RESPONSE;
	}

	if(ret == LWS_ERR_OK) {

		if(WS_SERVER_TRANSPORT(endpoint->server) == WS_TRANSPORT_TLS) {
			tls_server_SendMessage((TlsEndpoint_t*) endpoint->super, response, responseLength);
		} else {
			tcp_server_SendMessage((TcpEndpoint_t*) endpoint->super, response, responseLength);
		}

		((WsContext_t*) endpoint->context)->handshakeComplete = true;

	} else {

		/*
			If the server, while reading the handshake, finds that the client did
			not send a handshake that matches the description below (note that as
			per [RFC2616], the order of the header fields is not important),
			including but not limited to any violations of the ABNF grammar
			specified for the components of the handshake, the server MUST stop
			processing the client's handshake and return an HTTP response with an
			appropriate error code (such as 400 Bad Request).
		*/

		const unsigned char ErrorResponse[] = "HTTP/1.1 400 Bad Request\r\n\r\n";

		if(WS_SERVER_TRANSPORT(endpoint->server) == WS_TRANSPORT_TLS) {
			tls_server_SendMessage((TlsEndpoint_t*) endpoint->super, (unsigned char*) ErrorResponse, sizeof(ErrorResponse));
		} else {
			tcp_server_SendMessage((TcpEndpoint_t*) endpoint->super, (unsigned char*) ErrorResponse, sizeof(ErrorResponse));
		}
		((WsContext_t*) endpoint->context)->handshakeComplete = false;
	}


    return ret;
}


/**
 * @brief Writes the header for a websocket frame
 * 
 * @param output     output buffer to write to
 * @param outputSize size of the output buffer
 * @param fin        last frame for a message
 * @param opcode     opcode as per the Websocket spec
 * @param length     length of the application payload, for encoding in the header
 * 
 * @returns length of bytes written to buffer, -1 on failure
 */ 
static int ws_AppendHeader(unsigned char* output, size_t outputSize, int fin, WsOpCode_t opcode, size_t length) {
    int len;

    output[FLAG_OPCODE_OFFSET] = (fin << 7) | WS_OPCODE(opcode);

    if (length <= LENGTH_ONE_BYTE_LIMIT) {
        if(outputSize <= 2 + length) {
            return -LWS_ERR_FAIL;
        }
        output[LENGTH_OFFSET] = (unsigned char) length;
        return 2; 
    } else if (length < LENGTH_TWO_BYTE_LIMIT) {
        if(outputSize < 4 + length) {
            return -LWS_ERR_FAIL;
        }
        uint16_t tmp = htons((uint16_t) length);
        output[LENGTH_OFFSET] = LENGTH_IS_TWO_BYTE; // Indicates the data is in the next 2 bytes
        memcpy(&output[2], &tmp, sizeof(tmp));
        return 4;
    } else {
        if(outputSize < 10 + length) {
            return -LWS_ERR_FAIL;
        }
        uint32_t tmp;
        output[LENGTH_OFFSET] = LENGTH_IS_EIGHT_BYTE; // Indicates the data is in the next 8 bytes
        tmp = htonl((uint32_t)((uint64_t) length >> 32));
        memcpy(&output[2], &tmp, sizeof(tmp));
        tmp = htonl((uint32_t)(length & 0xFFFFFFFF));
        memcpy(&output[6], &tmp, sizeof(tmp));
        return 10;
    }

    return len;
}

/**
 * @brief Writes the header for a websocket frame
 * 
 * @param output     output buffer to write to
 * @param outputSize size of the output buffer
 * @param data       last frame for a message
 * @param length     length of the application payload, for encoding in the header
 * 
 * @returns length of bytes written to buffer, -1 on failure
 */ 
static int ws_AppendPayload(unsigned char* output, size_t outputSize, const unsigned char *data, size_t length) {
    if(outputSize < length) {
        return -LWS_ERR_FAIL;
    }
    memcpy(output, data, length);
    return length;
}

/**
 * @brief Prepares a Websocket frame for sending data over TCP
 * 
 * @param output     output buffer to write to
 * @param outputSize size of the output buffer
 * @param fin        if this is the last fragment, the first fragment may be the last fragment too
 * @param opcode     opcode
 * @param data       last frame for a message
 * @param length     length of the application payload, for encoding in the header
 * 
 * @returns length of bytes written to buffer, -1 on failure
 */ 
int ws_PrepareFrame(unsigned char* output, int outputSize, int fin, int opcode, const unsigned char* data, size_t length) {
    int len = 0;
    len = ws_AppendHeader(output, outputSize, fin, opcode, length);
    if(len < 0) {
        return -LWS_ERR_FAIL;
    }
    len += ws_AppendPayload(output + len, outputSize - len, data, length);
    if(len < 0) {
        return -LWS_ERR_FAIL;
    }
    return len;
}

static Err_t ws_HandleMessage(WsEndpoint_t* wsEndpoint, unsigned char* buffer, size_t length) {

	if(!wsEndpoint || !buffer || length < WS_MIN_CLIENT_FRAME_LENGTH) {
		return LWS_ERR_PARAMETERS_INVALID;
	}

	WsContext_t* context = (WsContext_t*) wsEndpoint->context;
	size_t offset = 0;

	do {

		int newLength = 0;
		unsigned char* mask;
		unsigned char dataLengthOffset = 0;
		WsOpCode_t opcode = OPCODE(buffer[offset + 0]);

		newLength = ws_server_GetDataLength(buffer + offset, length, &dataLengthOffset);
		mask = ws_server_GetMask(buffer + offset, length - offset, dataLengthOffset);

		if(!mask) {
			LWS_LOGE(ws_HandleMessage, "Messages from Client MUST be masked\n");
			ws_server_SendCloseMessage(wsEndpoint, WS_CLOSE_PROTOCOL_ERROR);
			ws_server_CloseConnection(wsEndpoint);
			return LWS_ERR_PARAMETERS_INVALID;
		}

		bool fin = FIN(buffer[offset + 0]);

		unsigned char* payload = buffer + offset + ( WS_MIN_CLIENT_FRAME_LENGTH + dataLengthOffset ); 
		ws_server_unmaskMessage( 
			payload, 
			newLength, 
			mask
		);

		if(opcode != OP_TEXT && opcode != OP_BINARY && opcode != OP_CONTINUE) {
			// This is a control frame
			if(!fin || opcode == OP_CONNECTION_CLOSE) {
				ws_server_CloseConnection(wsEndpoint);
				return opcode == OP_CONNECTION_CLOSE? LWS_ERR_OK : LWS_ERR_FAIL;
			} 
			if(opcode == OP_PING) {
				LWS_LOGI(ws_HandleMessage, "Received Ping\n");
				ws_server_SendPong(wsEndpoint, payload, newLength);
			} else if (opcode == OP_PONG) {
				LWS_LOGI(ws_HandleMessage, "Received Pong\n");
			}

		} else {

			// This is a data frame. Either text or binary

			if(opcode == OP_TEXT || opcode == OP_BINARY) {
				context->defragmentedOpcode = opcode;
				if(context->defragmentedLength == 0) {
					//No memory has been allocated to `context->defragmentedMessage` pointer
					context->defragmentedMessage = malloc( (newLength + 1) * sizeof(unsigned char) );
				} else {
					// This is the case if a memory has been allocated previously but not freed because the previous message was not complete.
					// In this case the callback is never called for that message and neither is the memory freed afterwards.
					context->defragmentedLength = 0;
					context->defragmentedMessage = realloc(context->defragmentedMessage, (context->defragmentedLength + newLength + 1) * sizeof(unsigned char) );
				}
			} else {
				// Continue reallocating memory for incoming payload
				context->defragmentedMessage = realloc(context->defragmentedMessage, (context->defragmentedLength + newLength + 1) * sizeof(unsigned char) );
			}


			memcpy(context->defragmentedMessage + context->defragmentedLength, payload, newLength);
			context->defragmentedMessage[context->defragmentedLength + newLength] = 0;
			context->defragmentedLength += newLength;

			if(fin) {
				WsMessage_t message = {
					.opcode = context->defragmentedOpcode,
					.buffer = context->defragmentedMessage,
					.length = context->defragmentedLength,
				};
				if(wsEndpoint->server->onMessage) {
					wsEndpoint->server->onMessage(wsEndpoint, (void*) &message, sizeof(WsMessage_t));
				}

				free(context->defragmentedMessage);
				context->defragmentedMessage = NULL;
				context->defragmentedLength = 0;
				context->defragmentedOpcode = OP_CONTINUE;
			}
		}

		offset += (newLength + WS_MIN_CLIENT_FRAME_LENGTH + dataLengthOffset);
	} while(offset < length);
	return LWS_ERR_OK;	
}

void onTransportEndpointConnect(Endpoint_t* endpoint) {
    WsEndpoint_t* wsEndpoint = malloc(sizeof(Endpoint_t));
    memset(wsEndpoint, 0, sizeof(Endpoint_t));
	LWS_LOGI(onTransportEndpointConnect, "Transport endpoint connected");

    endpoint->sub = wsEndpoint;
    wsEndpoint->super = endpoint;
    if(endpoint->server->sub) {
        wsEndpoint->server = endpoint->server->sub;
    }


    WsServer_t* wsServer = (WsServer_t*) wsEndpoint->server;

	WsContext_t* context = (WsContext_t*) malloc(sizeof(WsContext_t));
	memset(context, 0, sizeof(WsContext_t));

	context->transport = ((WsContext_t*) wsServer->context)->transport;
	context->handshakeComplete = 0;
	
	wsEndpoint->context = context;
    
	linked_list_Insert(&wsServer->endpoints, (void*) wsEndpoint);
    
}

static void FreeWsContext(WsContext_t* context) {
	if ((context)->defragmentedLength != 0) {
		free(context->defragmentedMessage);
	}
	free(context);
}

void onTransportEndpointDisconnect(Endpoint_t* endpoint) {
    if(endpoint->sub) {
        WsEndpoint_t* wsEndpoint = (WsEndpoint_t*) endpoint->sub;
        if(wsEndpoint->server->onDisconnect) {
            wsEndpoint->server->onDisconnect(wsEndpoint);
        }
        linked_list_Remove(&wsEndpoint->server->endpoints, (void*) wsEndpoint);
		FreeWsContext((WsContext_t*) wsEndpoint->context);
		free(wsEndpoint);
    }
}

void onTransportServerError(Server_t* server, const unsigned char* payload, size_t length) {
    if(server->sub) {
        (( WsServer_t* ) server->sub)->onServerError(server->sub, payload, length);
    }
}

void onTransportEndpointError(Endpoint_t* endpoint, const unsigned char* payload, size_t length) {
    if(endpoint->sub) {
        (( WsServer_t* ) endpoint->server->sub)->onEndpointError(endpoint->sub, payload, length);
    }
}

void onTransportEndpointMessage(Endpoint_t* endpoint, void* payload, size_t length) {
	unsigned char* buffer = (unsigned char*) payload;
    WsEndpoint_t* wsEndpoint = (WsEndpoint_t*) endpoint->sub;
    if(wsEndpoint) { 
        if(! websocket_handshake_IsComplete(wsEndpoint)) {    
        // Websocket Handshake Received
            if(websocket_handshake(wsEndpoint, buffer, length) == LWS_ERR_OK) {
				// If websocket handshake is successfull. 
				// Notify the application of a new websocket connection.
				LWS_LOGD(onTransportEndpointConnect, "Handshake complete.");
                if(wsEndpoint->server) {
                    if(wsEndpoint->server->onConnect) {
                        wsEndpoint->server->onConnect(wsEndpoint);
                    } else if(wsEndpoint->server->onServerError) {
						LWS_LOGW(onTransportEndpointConnect, "No onConnect Callback.");
					}
                }
            } else {
				// If websocket handshake fails. Close the connection
				LWS_LOGW(onTransportEndpointConnect, "Handshake failed. Closing transport.");
				if(WS_SERVER_TRANSPORT(wsEndpoint->server) == WS_TRANSPORT_TLS) {
					tls_server_CloseConnection((TlsEndpoint_t*) endpoint);
				} else {
					tcp_server_CloseConnection((TcpEndpoint_t*) endpoint);
				}
			}
        } else {
        	// Websocket Message Received
                // This a data frame. Not a control Frame
				LWS_LOGV(onTransportEndpointConnect, "Message received. Parsing...");
				if(ws_HandleMessage(wsEndpoint, buffer, length) != LWS_ERR_OK) {
					LWS_LOGE(onTransportEndpointConnect, "ws_HandleMessage() failed. Error handling message.");
				}
        }
    }
}
