#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "server.h"
#include "ws_server.h"
#include "ws_protocol.h"
#include "tcp_server.h"
#include "tls_server.h"

static WsServer_t* CreateWsServer(WsServerConfig_t* config) {

    WsServer_t* wsServer = (WsServer_t*) malloc(sizeof(WsServer_t));
    memset(wsServer, 0, sizeof(WsServer_t));

    TcpServerConfig_t tcpConfig = { 0 };
    tcpConfig.onConnect = onTransportEndpointConnect;
    tcpConfig.onDisconnect = onTransportEndpointDisconnect;
    tcpConfig.onServerError = onTransportServerError;
    tcpConfig.onEndpointError = onTransportEndpointError;
    tcpConfig.onMessage = onTransportEndpointMessage;

    TcpServer_t* tcpServer = tcp_server_Init(&tcpConfig);
    tcpServer->sub = wsServer;
    wsServer->super = tcpServer;

	WsContext_t* context = (WsContext_t*) malloc(sizeof(WsContext_t));
	memset(context, 0, sizeof(WsContext_t));

	context->transport = WS_TRANSPORT_TCP;

	wsServer->context = context;


	// Attach Application Callbacks
    if(config->onConnect) {
        wsServer->onConnect = config->onConnect;
    }

    if(config->onDisconnect) {
        wsServer->onDisconnect = config->onDisconnect;
    }

    if(config->onEndpointError) {
        wsServer->onEndpointError = config->onEndpointError;
    }

    if(config->onServerError) {
        wsServer->onServerError = config->onServerError;
    }

    if(config->onMessage) {
        wsServer->onMessage = config->onMessage;
    }

    return wsServer;
}

static WsServer_t* CreateWssServer(WsServerConfig_t* config, CertificateData* certs) {

	WsServer_t* wsServer = (WsServer_t*) malloc(sizeof(WsServer_t));
    memset(wsServer, 0, sizeof(WsServer_t));

	TlsServerConfig_t tlsConfig = { 0 };
    tlsConfig.onConnect = onTransportEndpointConnect;
    tlsConfig.onDisconnect = onTransportEndpointDisconnect;
    tlsConfig.onServerError = onTransportServerError;
    tlsConfig.onEndpointError = onTransportEndpointError;
    tlsConfig.onMessage = onTransportEndpointMessage;
    
	TlsServer_t* tlsServer = tls_server_Init(&tlsConfig, certs);
    tlsServer->sub = wsServer;
    wsServer->super = tlsServer;

	WsContext_t* context = (WsContext_t*) malloc(sizeof(WsContext_t));
	memset(context, 0, sizeof(WsContext_t));
	context->transport = WS_TRANSPORT_TLS;

	wsServer->context = context;

    if(config->onConnect) {
        wsServer->onConnect = config->onConnect;
    }

    if(config->onDisconnect) {
        wsServer->onDisconnect = config->onDisconnect;
    }

    if(config->onEndpointError) {
        wsServer->onEndpointError = config->onEndpointError;
    }

    if(config->onServerError) {
        wsServer->onServerError = config->onServerError;
    }

    if(config->onMessage) {
        wsServer->onMessage = config->onMessage;
    }

    return wsServer;
}

WsServer_t* ws_server_Init(WsServerConfig_t* config, CertificateData* certs) {
	if(certs) {
		return CreateWssServer(config, certs);
	} else {
		return CreateWsServer(config);
	}
}

static void freeEndpoints(void* endpoint) {
	free(((WsEndpoint_t*) endpoint)->context);
    free(endpoint);
}

Err_t ws_server_DeInit(WsServer_t* server) {
	if(!server || !server->context) {
		return LWS_ERR_FAIL;
	}
	
	if(WS_SERVER_TRANSPORT(server) == WS_TRANSPORT_TLS) {
		tls_server_DeInit(server->super);
	} else {
		tcp_server_DeInit(server->super);
	}

    if(server->endpoints) {
        linked_list_Drop(&server->endpoints, freeEndpoints);
    }

	free(server->context);
    free(server);

	return LWS_ERR_FAIL;

}

Err_t ws_server_Bind(WsServer_t* server, int port) {
	if(!server || !server->context) {
		return LWS_ERR_FAIL;
	}

	if(WS_SERVER_TRANSPORT(server) == WS_TRANSPORT_TLS) {
		return tls_server_Bind(server->super, port);
	} else {
		return tcp_server_Bind(server->super, port);
	}

}

Err_t ws_server_SendMessage(WsEndpoint_t* endpoint, WsOpCode_t opcode, unsigned char* buffer, size_t length) {
    if(!endpoint) {
        return LWS_ERR_FAIL;
    }

    if(opcode == OP_PING || opcode == OP_PONG) {

    } else if(!buffer || length == 0) {
        return LWS_ERR_FAIL;
    }

    Err_t ret = LWS_ERR_OK;
    unsigned char payload[MAX_WS_HEADER_SIZE + MAX_WS_PAYLOAD_SIZE];
    int sLength = 0, payloadLength;
    unsigned char fullChunks = length / MAX_WS_PAYLOAD_SIZE;
    unsigned char lastChunkLength = length % MAX_WS_PAYLOAD_SIZE;
    unsigned char i = 0;
    unsigned char* bufferAddress;
    int fin = 0;

    for(i = 0; i <= fullChunks; i++) {
        sLength = MAX_WS_PAYLOAD_SIZE;
        if(i == fullChunks) {
            sLength = lastChunkLength;
            fin = 1;
        }
        bufferAddress = buffer + (i * fullChunks * MAX_WS_PAYLOAD_SIZE);
        payloadLength = ws_PrepareFrame(payload, sizeof(payload), fin, opcode, (const unsigned char*) bufferAddress, sLength);
        if(payloadLength < 0) {
            ret = LWS_ERR_FAIL;
            break;
        }
        opcode = OP_CONTINUE;
		if(WS_SERVER_TRANSPORT(endpoint->server) == WS_TRANSPORT_TLS) {
			ret = tls_server_SendMessage(endpoint->super, payload, payloadLength);
		} else {
			ret = tcp_server_SendMessage(endpoint->super, payload, payloadLength);
		}
    }
    return ret;
}


static void WsSendMessageCallback(int index, void* endpoint, void* userData) {
	(void) index;
    WsMessage_t* message = (WsMessage_t*) userData;
    ws_server_SendMessage((WsEndpoint_t*) endpoint, message->opcode, message->buffer, message->length);
}

Err_t ws_server_BroadcastMessage(WsServer_t* server, WsOpCode_t opcode, unsigned char* buffer, size_t length) {

    if(!server || !buffer || length == 0) {
        return LWS_ERR_FAIL;
    }

    WsMessage_t message = {
        .opcode = opcode,
        .buffer = buffer,
        .length = length
    };

    linked_list_Iterate(&server->endpoints, WsSendMessageCallback, (void*) &message);

    return LWS_ERR_OK;
}

Err_t ws_server_SendTextMessage(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length) {
	return ws_server_SendMessage(endpoint, OP_TEXT, buffer, length);
}

Err_t ws_server_BroadcastTextMessage(WsServer_t* server, unsigned char* buffer, size_t length) {
	return ws_server_BroadcastMessage(server, OP_TEXT, buffer, length);
}

Err_t ws_server_SendBinaryMessage(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length) {
	return ws_server_SendMessage(endpoint, OP_BINARY, buffer, length);
}

Err_t ws_server_BroadcastBinaryMessage(WsServer_t* server, unsigned char* buffer, size_t length) {
	return ws_server_BroadcastMessage(server, OP_BINARY, buffer, length);
}

Err_t ws_server_SendPing(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length) {
	return ws_server_SendMessage(endpoint, OP_PING, buffer, length);
}

Err_t ws_server_SendPong(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length) {
	return ws_server_SendMessage(endpoint, OP_PONG, buffer, length);
}

Err_t ws_server_SendCloseMessage(WsEndpoint_t* endpoint, WsCloseReason_t reason) {
	(void) endpoint;
	(void) reason;
	// return ws_server_SendMessage(endpoint, OP_CONNECTION_CLOSE, reason, length);
	return LWS_ERR_FAIL;
}

Err_t ws_server_Tick(WsServer_t* server) {
	if(!server || !server->super) {
		return LWS_ERR_FAIL;
	}

	if(WS_SERVER_TRANSPORT(server) == WS_TRANSPORT_TLS) {
		return tls_server_Tick(server->super);
	} else {
		return tcp_server_Tick(server->super);
	}
}

Err_t ws_server_CloseConnection(WsEndpoint_t* endpoint) {
	ws_server_SendCloseMessage(endpoint, WS_CLOSE_OK);
	if(WS_SERVER_TRANSPORT(endpoint->server) == WS_TRANSPORT_TLS) {
		return tls_server_CloseConnection(endpoint->super);
	} else {
		return tcp_server_CloseConnection(endpoint->super);
	}
}
