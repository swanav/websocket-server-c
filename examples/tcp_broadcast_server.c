#include "tcp_server.h"

#include <stdio.h>
#include <signal.h>


#define PORT 8080

static int exitServer = 0;

void sig_handler(int signo) {
    if (signo == SIGINT) {
        exitServer = 1;
    }
}

static void onConnect(Endpoint_t* endpoint) {
    // A new client is connected
    if(endpoint) {
        printf("Client connected: %d to Server: %d\n", *((int*)endpoint->super), *((int*) endpoint->server->super));
    }
}

static void onMessage(Endpoint_t* endpoint, void* payload, size_t size) {
    // A new message has been received from a client.
    printf("Echo Message: %.*s\n", (int) size, (unsigned char*) payload);
    // Echo the message back to the client.
    tcp_server_SendMessage(endpoint, (unsigned char*)payload, size);
}

static void onDisconnect(Endpoint_t* endpoint) {
    // A client has been disconnected from the peer end.
    if(endpoint) {
        printf("Client disconnected: %d\n", *((int*)endpoint->super));
    }
}

static void onServerError(Server_t* server, const unsigned char* payload, size_t size) {
	(void) server;
    // Encountered an error in TCP Server
    fprintf(stderr, "%s ERROR: %.*s\n", __func__, (int) size, payload);
}


static void onEndpointError(Endpoint_t* endpoint, const unsigned char* payload, size_t size) {
    (void) endpoint;
	// Encountered an error in TCP Client
    fprintf(stderr, "%s ERROR: %.*s\n", __func__, (int) size, payload);
}

int main() {

    if (signal(SIGINT, sig_handler) == SIG_ERR)
      fprintf(stderr, "===\ncan't catch SIGINT\n===\n");

    TcpServerConfig_t server_config = { 0 };
    server_config.onConnect = onConnect;
    server_config.onDisconnect = onDisconnect;
    server_config.onMessage = onMessage;
    server_config.onServerError = onServerError;
    server_config.onEndpointError = onEndpointError;
	
    TcpServer_t* server = tcp_server_Init(&server_config);
    if(!server) {
        fprintf(stderr, "Exited TCP Server!\n");
        return 1;
    }

    tcp_server_Bind(server, PORT);

	printf("TCP Broadcast Server listening on Port: %d\n", PORT);

    while(1) {
        if(tcp_server_Tick(server) != LWS_ERR_OK || exitServer) {
            break;
        }
    }

    tcp_server_DeInit(server);

    fprintf(stderr, "Exited TCP Server!\n");

    return 0;
}
