#include "tls_server.h"
#include "server.h"

#include "linked_list.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "mbedtls/error.h"

static const int tls_cipher_list[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
    0,
};

int tcp_server_send(void *tcpEndpoint, const unsigned char *buf, size_t len) {
	int ret = tcp_server_send_raw(tcpEndpoint, buf, len);
	if(ret == -LWS_ERR_WOULDBLOCK) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	return ret;
}

int tcp_server_receive(void *tcpEndpoint, unsigned char *buf, size_t len) {
	int ret = tcp_server_receive_raw(tcpEndpoint, buf, len);
	if(ret == -LWS_ERR_WOULDBLOCK) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	return ret;
}

Err_t tls_server_SendMessage(TlsEndpoint_t* endpoint, unsigned char* payload, size_t size) {
	mbedtls_ssl_context *ssl = &(((TlsClientContext_t*)endpoint->context)->ssl);

	int written = 0, lenLeft = (int) size;
	while (lenLeft != 0) {
		written = mbedtls_ssl_write(ssl, (const unsigned char*) payload + written, size - written);
		if(written < 0) {
			return LWS_ERR_FAIL;
		}
		lenLeft -= written;
	}
	return LWS_ERR_OK;
}

static void TlsSendMessageCallback(int index, void* endpoint, void* userData) {
	(void) index;
    TlsMessage_t* message = (TlsMessage_t*) userData;
    tls_server_SendMessage((TlsEndpoint_t*) endpoint, message->buffer, message->length);
}

Err_t tls_server_BroadcastMessage(TlsServer_t* server, unsigned char* buffer, size_t length) {

    if(!server || !buffer || length == 0) {
        return LWS_ERR_FAIL;
    }

    TlsMessage_t message = {
        .buffer = buffer,
        .length = length
    };

    linked_list_Iterate(&server->endpoints, TlsSendMessageCallback, (void*) &message);

    return LWS_ERR_OK;
}

TlsClientContext_t* tls_context_InitClientContext(TlsEndpoint_t* tlsClient) {
	TlsClientContext_t* context = (TlsClientContext_t*) malloc(sizeof(TlsClientContext_t));
	memset(context, 0, sizeof(TlsClientContext_t));
    mbedtls_ssl_init( &(context->ssl) );

	if(mbedtls_ssl_setup( &(context->ssl), &(((TlsServerContext_t*)tlsClient->server->context)->conf)) != 0) {
		return NULL;
	}

	mbedtls_ssl_set_bio( &(context->ssl) , tlsClient->super, tcp_server_send, tcp_server_receive, NULL );

	return context;
}

Err_t tls_context_DeInitClientContext(TlsClientContext_t* context) {

    mbedtls_ssl_free( &(context->ssl) );

    free(context);

    return LWS_ERR_OK;
}

TlsServerContext_t* tls_context_InitServerContext(CertificateData* certificateData) {

    int ret;

    TlsServerContext_t* context = (TlsServerContext_t*) malloc(sizeof(TlsServerContext_t));
    memset(context, 0, sizeof(TlsServerContext_t));

    mbedtls_ssl_config_init( &(context->conf) );
    mbedtls_x509_crt_init( &(context->srvcert) );
    mbedtls_pk_init( &(context->pkey) );
    mbedtls_entropy_init( &(context->entropy) );
    mbedtls_ctr_drbg_init( &(context->ctr_drbg) );

	context->certificates.certificate = certificateData->certificate;
	context->certificates.privateKey = certificateData->privateKey;
	context->certificates.rootCa = certificateData->rootCa;
	

    if((ret = mbedtls_ctr_drbg_seed( &(context->ctr_drbg),  mbedtls_entropy_func, &(context->entropy), NULL, 0))) {
        LWS_LOGE(tls_context_InitServerContext, " failed! mbedtls_ctr_drbg_seed returned %d", ret );
        return NULL;
    }

	if(mbedtls_ssl_config_defaults( &(context->conf), MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT )) {
		LWS_LOGE(tls_context_InitServerContext, " failed to init ssl config!");
		return NULL;
	}

	mbedtls_ssl_conf_rng( &(context->conf), mbedtls_ctr_drbg_random, &(context->ctr_drbg) );

    mbedtls_ssl_conf_ca_chain( &(context->conf), (context->srvcert.next), NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &(context->conf), &(context->srvcert), &(context->pkey) ) ) != 0 )
    {
        LWS_LOGE(tls_context_InitServerContext, " failed! mbedtls_ssl_conf_own_cert returned %d.", ret );
        return NULL;
    }
	// Support TLS 1.2 and above
	mbedtls_ssl_conf_min_version(&(context->conf), MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
	// mbedtls_ssl_conf_rng(&(context->conf), mg_ssl_if_mbed_random, NULL);
	mbedtls_ssl_conf_ciphersuites(&(context->conf), tls_cipher_list);

    return context;
}


Err_t tls_context_useCertificateKey(TlsServerContext_t *context,
                                         const unsigned char* certificateBuffer, size_t certLength,
										 const unsigned char* caBuffer, size_t caLength,
										 const unsigned char* privateKeyBuffer, size_t keyLength) {
  if (privateKeyBuffer == NULL) privateKeyBuffer = certificateBuffer;
  if (certificateBuffer == NULL || certificateBuffer[0] == '\0' || privateKeyBuffer == NULL || privateKeyBuffer[0] == '\0') {
    return LWS_ERR_OK;
  }
  if (mbedtls_x509_crt_parse(&(context->srvcert), certificateBuffer, certLength) != 0) {
    LWS_LOGE(tls_context_useCertificateKey, "Invalid SSL cert");
    return LWS_ERR_FAIL;
  }

  if (mbedtls_x509_crt_parse(&(context->srvcert), caBuffer, caLength) != 0) {
    LWS_LOGE(tls_context_useCertificateKey, "Invalid CA cert");
    return LWS_ERR_FAIL;
  }

  if (mbedtls_pk_parse_key(&(context->pkey), privateKeyBuffer, keyLength, NULL, 0, mbedtls_ctr_drbg_random, &(context->ctr_drbg)) != 0) {
    LWS_LOGE(tls_context_useCertificateKey, "Invalid SSL key");
    return LWS_ERR_FAIL;
  }
  if (mbedtls_ssl_conf_own_cert(&(context->conf), &(context->srvcert), &(context->pkey)) != 0) {
    LWS_LOGE(tls_context_useCertificateKey, "Invalid SSL key or cert");
    return LWS_ERR_FAIL;
  }
  return LWS_ERR_OK;
}

Err_t tls_context_DeInitServerContext(TlsServerContext_t* context) {

    mbedtls_ctr_drbg_free( &(context->ctr_drbg) );
    mbedtls_entropy_free( &(context->entropy) );
    mbedtls_pk_free( &(context->pkey) );
    mbedtls_x509_crt_free( &(context->srvcert) );
    mbedtls_ssl_config_free( &(context->conf) );

    free(context);

    return LWS_ERR_OK;
}

static void onTcpClientConnect(TcpEndpoint_t* endpoint) {
    TlsEndpoint_t* tlsClient = malloc(sizeof(TlsEndpoint_t));
    memset(tlsClient, 0, sizeof(TlsEndpoint_t));

    endpoint->sub = tlsClient;
    tlsClient->super = endpoint;
    if(endpoint->server->sub) {
        tlsClient->server = endpoint->server->sub;
    }
	tlsClient->context = tls_context_InitClientContext(tlsClient);
    TlsServer_t* tlsServer = (TlsServer_t*) tlsClient->server;
    linked_list_Insert(&tlsServer->endpoints, (void*) tlsClient);
	int ret;
	mbedtls_ssl_context *ssl = &(((TlsClientContext_t*)tlsClient->context)->ssl);
	while( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            LWS_LOGW(onTcpClientConnect, "failed: mbedtls_ssl_handshake returned -0x%04x\n", -ret );
			tcp_server_CloseConnection(endpoint);
            return;
        }
    }
	LWS_LOGI( onTcpClientConnect, "SSL Handshake complete. TLS Client connected." );
	if(tlsClient->server->onConnect) {
		tlsClient->server->onConnect(tlsClient);
	}
}

static void onTcpClientDisconnect(TcpEndpoint_t* endpoint) {
    if(endpoint->sub) {
		LWS_LOGD( onTcpClientDisconnect, "TCP Client disconnected." );
        TlsEndpoint_t* tlsClient = (TlsEndpoint_t*) endpoint->sub;
        if(tlsClient->server->onDisconnect) {
            tlsClient->server->onDisconnect(tlsClient);
        }
        linked_list_Remove(&tlsClient->server->endpoints, (void*) tlsClient);
		tls_context_DeInitClientContext(tlsClient->context);
        free(tlsClient);
    }
}

static void onTcpServerError(TcpServer_t* server, const unsigned char* payload, size_t length) {
    if(server->sub) {
        (( TlsServer_t* ) server->sub)->onServerError(server->sub, payload, length);
    }
}

static void onTcpEndpointError(TcpEndpoint_t* endpoint, const unsigned char* payload, size_t length) {
    if(endpoint->sub) {
        (( TlsServer_t* ) endpoint->server->sub)->onEndpointError(endpoint->sub, payload, length);
    }
}

static bool onTcpClientReadReady(TcpEndpoint_t* endpoint) {
	TlsEndpoint_t* tlsClient = (TlsEndpoint_t*) endpoint->sub;
	mbedtls_ssl_context *ssl = &(((TlsClientContext_t*) tlsClient->context)->ssl);

	unsigned char buf[2048];
	memset(buf, 0, sizeof(buf));
	int len = mbedtls_ssl_read(ssl, buf, sizeof(buf));  // ) > 0) {

	if( len == MBEDTLS_ERR_SSL_WANT_READ || len == MBEDTLS_ERR_SSL_WANT_WRITE )
		return true;

	if( len <= 0 )
	{
		switch( len )
		{
			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
				LWS_LOGI(onTcpClientReadReady, "  [ #%d ]  connection was closed gracefully\n", GET_FD(endpoint->super) );
				break;
			case -LWS_ERR_CONNECTION_RESET:
				LWS_LOGI(onTcpClientReadReady, "  [ #%d ]  connection was reset by peer\n", GET_FD(endpoint->super) );
				break;
			default:
				LWS_LOGI(onTcpClientReadReady, "  [ #%d ]  mbedtls_ssl_read returned -0x%04x\n", GET_FD(endpoint->super), -len );
		}
		return false;
	}

	if(tlsClient->server && tlsClient->server->onMessage) {
		tlsClient->server->onMessage(tlsClient, buf, len);
	}

	return true;
}

/*===================================  TCP Callback Methods  =============================================*/


/*========================================================================================================*/
/*                                         TLS Init Methods                                               */
/*========================================================================================================*/
TlsServer_t* tls_server_Init(TlsServerConfig_t* config, CertificateData* certificateData) {

	// Initialise the TLS Server Reference
    TlsServer_t* tlsServer = (TlsServer_t*) malloc(sizeof(TlsServer_t));
    memset(tlsServer, 0, sizeof(TlsServer_t));

	// Set callback methods for the TCP Server
    TcpServerConfig_t tcpConfig = { 0 };
    tcpConfig.onConnect = onTcpClientConnect;
    tcpConfig.onDisconnect = onTcpClientDisconnect;
    tcpConfig.onServerError = onTcpServerError;
    tcpConfig.onEndpointError = onTcpEndpointError;
    tcpConfig.beforeRead =  onTcpClientReadReady;

	// Initialise the underlying TCP Server
    TcpServer_t* tcpServer = tcp_server_Init(&tcpConfig);
    tcpServer->sub = tlsServer;
    tlsServer->super = tcpServer;

    tlsServer->context = tls_context_InitServerContext(certificateData);

	tls_context_useCertificateKey(tlsServer->context, 
					certificateData->certificate, strlen((const char*) certificateData->certificate)+1, 
					certificateData->rootCa, strlen((const char*) certificateData->rootCa)+1, 
					certificateData->privateKey, strlen((const char*) certificateData->privateKey)+1);

    if(config->onConnect) {
        tlsServer->onConnect = config->onConnect;
    }

    if(config->onDisconnect) {
        tlsServer->onDisconnect = config->onDisconnect;
    }

    if(config->onEndpointError) {
        tlsServer->onEndpointError = config->onEndpointError;
    }

    if(config->onServerError) {
        tlsServer->onServerError = config->onServerError;
    }

    if(config->onMessage) {
        tlsServer->onMessage = config->onMessage;
    }


    return tlsServer;
}

static void freeEndpoints(void* endpoint) {
    free(endpoint);
}


Err_t tls_server_DeInit(TlsServer_t* server) {

    tcp_server_DeInit(server->super);
    if(server->endpoints) {
        linked_list_Drop(&server->endpoints, freeEndpoints);
    }

    tls_context_DeInitServerContext(server->context);
    free(server);
    return LWS_ERR_OK;
}

Err_t tls_server_Bind(TlsServer_t* server, int port) {
    return tcp_server_Bind(server->super, port);
}

Err_t tls_server_Tick(TlsServer_t* server) {
    return tcp_server_Tick(server->super);
}

Err_t tls_server_CloseConnection(TlsEndpoint_t* endpoint) {
	return tcp_server_CloseConnection((TcpEndpoint_t*) endpoint->super);
}

/*=======================================  TLS Init Methods    ===========================================*/
