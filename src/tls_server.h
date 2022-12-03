#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include <stdint.h>
#include <stddef.h>

#include "server.h"
#include "tcp_server.h"
#include "linked_list.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/**
 * @brief TlsServer_t
 */
typedef Server_t TlsServer_t;

/**
 * @brief TlsEndpoint_t
 */
typedef Endpoint_t TlsEndpoint_t;

/**
 * @brief Container for a TLS message. 
 */
typedef struct __tls_message_t {

	/**
	 * @brief Buffer containing decrypted TLS message
	 */
	unsigned char* buffer;

	/**
	 * @brief Length of the buffer
	 */
	size_t length;
} TlsMessage_t;

/**
 * @brief Certificate Data a TLS server. 
 */
typedef struct __certificate_data_t {

	/**
	 * @brief Server Certificate 
	 */
    const unsigned char* certificate;

	/**
	 * @brief Server Private Key 
	 */
    const unsigned char* privateKey;

	/**
	 * @brief Root CA Certificate 
	 */
    const unsigned char* rootCa;
} CertificateData;

/**
 * @brief Client Context for a TLS connection. 
 */
typedef struct __tls_client_context_t {
	/**
	 * @brief mbedtls context for tls endpoint connection
	 */
    mbedtls_ssl_context ssl;
} TlsClientContext_t;

/**
 * @brief Server Context for a TLS server. 
 */
typedef struct __tls_server_context_t {

	/**
	 * @brief mbedtls context for tls server config
	 */
    mbedtls_ssl_config conf;

	/**
	 * @brief mbedtls context for certificate information
	 */
    mbedtls_x509_crt srvcert;

	/**
	 * @brief mbedtls context for private key information
	 */
    mbedtls_pk_context pkey;

	/**
	 * @brief mbedtls context for entropy
	 */
    mbedtls_entropy_context entropy;

	/**
	 * @brief mbedtls context for ctr_drbg
	 */
    mbedtls_ctr_drbg_context ctr_drbg;

	/**
	 * @brief Certificates for the TLS Server
	 */
	CertificateData certificates;
} TlsServerContext_t;

/**
 * @brief Server Config for a TLS server. 
 */
typedef struct __tls_server_config_t {

	/**
	 * @brief Handler for a new TLS endpoint connection
	 */
    ConnectCallback onConnect;

	/**
	 * @brief Handler for a new TLS endpoint disconnection
	 */
    DisconnectCallback onDisconnect;

	/**
	 * @brief Handler for a new TLS endpoint message
	 */
    MessageCallback onMessage;

	/**
	 * @brief Handler for a TLS server error
	 */
    ServerErrorCallback onServerError;

	/**
	 * @brief Handler for a TLS endpoint error
	 */
    EndpointErrorCallback onEndpointError;
} TlsServerConfig_t;


/**
 * @brief Initialise TLS Server. Allocate resources.
 * 
 * @param config TlsServerConfig instance
 * @param certificateData Certificate Data for WSS server.
 * 
 * @return TlsServer_t* Instance of TlsServer. NULL otherwise.
 */
TlsServer_t* tls_server_Init(TlsServerConfig_t* config, CertificateData* certificateData);

/**
 * @brief Deinitialise TLS Server. Free up resources.
 * @param server Pointer to TlsServer instance
 * 
 * @return TLS_OK on success.
 * 
 */
Err_t tls_server_DeInit(TlsServer_t* server);

/**
 * @brief Bind the TLS Server to the given port
 * 
 * @param server TlsServer instance
 * @param port Port number to which to bind to
 * 
 * @return TLS_OK on success.
 * 
 */ 
Err_t tls_server_Bind(TlsServer_t* server, int port);

/**
 * @brief Send a message over websocket
 * 
 * @param endpoint Instance to TlsEndpoint_t 
 * @param buffer Buffer to send 
 * @param length Length of buffer
 * 
 * @return TLS_OK on success
 */
Err_t tls_server_SendMessage(TlsEndpoint_t* endpoint, unsigned char* buffer, size_t length);

/**
 * @brief Send a message to all clients connected to websocket server
 * 
 * @param server Instance to TlsEndpoint_t 
 * @param buffer Buffer to send 
 * @param length Length of buffer
 * 
 * @return TLS_OK on success
 */
Err_t tls_server_BroadcastMessage(TlsServer_t* server, unsigned char* buffer, size_t length);

/**
 * @brief Send Text Message to TLS Client
 * 
 * @param client Receipent TLS Client
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return TLS_OK on success.
 * 
 */ 
Err_t tls_server_SendTextMessage(TlsEndpoint_t* client, unsigned char* buffer, size_t length);

/**
 * @brief Broadcast Text Message to all TLS Clients connected to Server
 * 
 * @param server TLS Server
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return TLS_OK on success.
 * 
 */ 
Err_t tls_server_BroadcastTextMessage(TlsServer_t* server, unsigned char* buffer, size_t length);
/**
 * @brief Send Binary Message to TLS Client
 * 
 * @param client Receipent TLS Client
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return TLS_OK on success.
 * 
 */ 
Err_t tls_server_SendBinaryMessage(TlsEndpoint_t* client, unsigned char* buffer, size_t length);

/**
 * @brief Broadcast Binary Message to all TLS Clients connected to Server
 * 
 * @param server TLS Server
 * @param buffer Buffer to send
 * @param length Length of buffer
 * 
 * @return TLS_OK on success.
 * 
 */ 
Err_t tls_server_BroadcastBinaryMessage(TlsServer_t* server, unsigned char* buffer, size_t length);

/**
 * @brief Tick Function for TLS Server.
 *        Call this function repeatedly for the TLS Server to process its' events.
 * 
 * @param server TlsServer instance
 * 
 * @return TLS_OK on success.
 * 
 */ 
Err_t tls_server_Tick(TlsServer_t* server);

/**
 * @brief Close connection TLS Endpoint.
 * 
 * @param endpoint TLSEndpoint instance
 * 
 * @return LWS_ERR_OK on success.
 * 
 */ 
Err_t tls_server_CloseConnection(TlsEndpoint_t* endpoint);

#endif // TLS_SERVER_H
