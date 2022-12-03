#include "ws_server.h"

#include <stdio.h>
#include <signal.h>

#include "tls_keys.h"

#define PORT 4434

static int exitServer = 0;

void sig_handler(int signo) {
    if (signo == SIGINT) {
        exitServer = 1;
    }
}

static void onConnect(Endpoint_t* client) {
    // A new client is connected
    if(client) {
        printf("WS Client connected: %p\n", client);
        // Send a ping to the client
        if(ws_server_SendPing((WsEndpoint_t*) client, NULL, 0) != LWS_ERR_OK) {
            printf("Could not send ping\n");
        }
    }
}

static void onMessage(Endpoint_t* client, void* payload, size_t size) {
    // A new message has been received from a client.
	(void) size;
    WsMessage_t* message = (WsMessage_t*) payload;
	if(message->opcode == OP_TEXT) {
        printf("Echoing Text Message: %.*s\n", (int) message->length, message->buffer);
    } else {
        printf("Echoing Binary Message: ");
        for(size_t i = 0; i < message->length; i++) {
            printf("%02X ", message->buffer[i]);
        }
        printf("\n");
    }
    // Echo the message back to the client.
    ws_server_SendMessage((WsEndpoint_t*)client, message->opcode, message->buffer, message->length);
}

static void onDisconnect(Endpoint_t* client) {
    // A client has been disconnected from the peer end.
    if(client) {
        printf("WS Client disconnected: %p\n", client);
    }
}

static void onServerError(Server_t* server, const unsigned char* payload, size_t size) {
	(void) server;
    // Encountered an error in WS Server
    fprintf(stderr, "WS SERVER ERROR: %.*s\n", (int) size, payload);
}

static void onEndpointError(Endpoint_t* client, const unsigned char* payload, size_t size) {
    (void) client;
	// Encountered an error in WS Client
    fprintf(stderr, "WS CLIENT ERROR: %.*s\n", (int) size, payload);
}

int main() {

    if (signal(SIGINT, sig_handler) == SIG_ERR)
      fprintf(stderr, "===\ncan't catch SIGINT\n===\n");

	static const unsigned char certificate[] = SERVER_CERTIFICATE;
    static const unsigned char privateKey[] = SERVER_PRIVATE_KEY;
    static const unsigned char rootCa[] = SERVER_ROOTCA;

    WsServerConfig_t server_config = { 0 };
    server_config.onConnect = onConnect;
    server_config.onDisconnect = onDisconnect;
    server_config.onMessage = onMessage;
    server_config.onServerError = onServerError;
    server_config.onEndpointError = onEndpointError;

	CertificateData certs = { 0 };
	certs.rootCa = rootCa;
    certs.certificate = certificate;
    certs.privateKey = privateKey;


    WsServer_t* server = ws_server_Init(&server_config, &certs);
    if(!server) {
        fprintf(stderr, "Exited WS Server!\n");
        return 1;
    }

    ws_server_Bind(server, PORT);

    printf("Websocket Secure Echo Server listening on Port: %d\n", PORT);

    while(1) {
        if(ws_server_Tick(server) != LWS_ERR_OK || exitServer) {
            break;
        }
    }

    ws_server_DeInit(server);

    fprintf(stderr, "Exited WS Server!\n");

    return 0;
}
