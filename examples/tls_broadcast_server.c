#include "tls_server.h"
#include "tls_keys.h"

#include <stdio.h>
#include <signal.h>

#define PORT 4433

static int exitServer = 0;

void sig_handler(int signo) {
    if (signo == SIGINT) {
        exitServer = 1;
    }
}

static void onConnect(TlsEndpoint_t* client) {
    // A new client is connected
    if(client) {
        printf("TLS Client connected: %p\n", client);
    }
}

static void onMessage(TlsEndpoint_t* client, void* payload, size_t size) {
    // A new message has been received from a client.
	unsigned char* buffer = (unsigned char*) payload;
    printf("Broadcasting Message: \nString: %.*s\nBinary: ", (int) size, (unsigned char*) buffer);
    for(size_t i = 0; i < size; i++) {
        printf("%02X ", (unsigned char) buffer[i]);
    }
    printf("\n");
    // Echo the message back to the client.
    tls_server_BroadcastMessage(client->server, buffer, size);
}

static void onDisconnect(TlsEndpoint_t* client) {
    // A client has been disconnected from the peer end.
    if(client) {
        printf("TLS Client disconnected: %p\n", client);
    }
}

static void onServerError(TlsServer_t* server, const unsigned char* payload, size_t size) {
	(void) server;
    // Encountered an error in TLS Server
    fprintf(stderr, "TLS SERVER ERROR: %.*s\n", (int) size, payload);
}

static void onEndpointError(TlsEndpoint_t* client, const unsigned char* payload, size_t size) {
	(void) client;
    // Encountered an error in TLS Client
    fprintf(stderr, "TLS CLIENT ERROR: %.*s\n", (int) size, payload);
}

int main() {

    if (signal(SIGINT, sig_handler) == SIG_ERR)
      fprintf(stderr, "===\ncan't catch SIGINT\n===\n");

    static const unsigned char certificate[] = SERVER_CERTIFICATE;
    static const unsigned char privateKey[] = SERVER_PRIVATE_KEY;
    static const unsigned char rootCa[] = SERVER_ROOTCA;

    TlsServerConfig_t server_config = { 0 };
    server_config.onConnect = onConnect;
    server_config.onDisconnect = onDisconnect;
    server_config.onMessage = onMessage;
    server_config.onServerError = onServerError;
    server_config.onEndpointError = onEndpointError;

	CertificateData certs;
    certs.rootCa = rootCa;
    certs.certificate = certificate;
    certs.privateKey = privateKey;

    TlsServer_t* server = tls_server_Init(&server_config, &certs);
    if(!server) {
        fprintf(stderr, "Exited TLS Server!\n");
        return 1;
    }

    tls_server_Bind(server, PORT);

    printf("TLS Server listening on Port: %d\n", PORT);

    while(1) {
        if(tls_server_Tick(server) != LWS_ERR_OK || exitServer) {
            break;
        }
    }

    tls_server_DeInit(server);

    fprintf(stderr, "Exited TLS Server!\n");

    return 0;
}
