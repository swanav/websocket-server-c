# WebSocket Server

A lightweight WebSocket Server library in C, written from the ground up to implement [RFC6455](https://datatracker.ietf.org/doc/html/rfc6455), using BSD sockets API. This library can handle multiple clients in a single thread using I/O Multiplexing.

> Compatible with ESP32 (primary development target), Linux, Mac, and Windows.

> You may want to limit the number of concurrent clients in an embedded device due to memory constraints.

---
## Usage

Examples to create TCP, TLS, WS, WSS libraries can be found in the `examples` directory.

---
## API Documentation

### ***WebSocket Server***


- `typedef void (*ConnectCallback)(Endpoint_t*);`
- `typedef void (*DisconnectCallback)(Endpoint_t*);`
- `typedef void (*MessageCallback)(Endpoint_t*, void* message, size_t size);`
- `typedef void (*ServerErrorCallback)(Server_t*, const unsigned char* message, size_t size);`
- `typedef void (*EndpointErrorCallback)(Endpoint_t*, const unsigned char* message, size_t size);`

```c
struct WsServerConfig_t {
    ConnectCallback onConnect; // Handler for a new WebSocket endpoint connection
    DisconnectCallback onDisconnect; // Handler for a WebSocket endpoint disconnection
    MessageCallback onMessage; // Handler for a WebSocket endpoint message
    ServerErrorCallback onServerError; // Handler for a WebSocket server error
    EndpointErrorCallback onEndpointError; // Handler for a WebSocket endpoint error
};
```
#### **Create a WebSocket Server**

```c
WsServer_t* ws_server_Init(WsServerConfig_t* config, CertificateData* certs);
```
Initialize the WebSocket server and allocate resources.

- **param** config: Instance of WsServerConfig_t with event handlers.
- **param** certs: Certificate data for WSS server. Pass NULL for WS server.
- **returns** an instance of WsServer_t on success, or NULL otherwise.
---
#### **Dispose the WebSocket Server**
```c
Err_t ws_server_DeInit(WsServer_t* server);
```
Deinitialize the WebSocket server and free up resources.

- **param** server: Pointer to WsServer_t instance.
- **returns** WS_OK on success.
---
#### **Bind the server to a port**
```c
Err_t ws_server_Bind(WsServer_t* server, int port);
```
Bind the WebSocket server to the given port.

- **param** server: WsServer_t instance.
- **param** port: Port number to bind to.
- **returns** WS_OK on success.
---
#### **Send text message to a client**
```c
Err_t ws_server_SendTextMessage(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length);
```
Send a text message to a WebSocket endpoint.

- **param** endpoint: Recipient WsEndpoint_t.
- **param** buffer: Buffer to send.
- **param** length: Length of buffer.
- **returns** WS_OK on success.
---
#### **Broadcast text message to all clients**
```c
Err_t ws_server_BroadcastTextMessage(WsServer_t* server, unsigned char* buffer, size_t length);
```
Broadcast a text message to all WebSocket endpoints connected to the server.

- **param** server: WebSocket server.
- **param** buffer: Buffer to send.
- **param** length: Length of buffer.
- **returns** WS_OK on success.
---
#### **Send binary message to a client**
```c
Err_t ws_server_SendBinaryMessage(WsEndpoint_t* endpoint, unsigned char* buffer, size_t length);
```
Send a binary message to a WebSocket endpoint.

- **param** endpoint: Recipient WsEndpoint_t.
- **param** buffer: Buffer to send.
- **param** length: Length of buffer.
- **returns** WS_OK on success.
---
#### **Broadcast binary message to all clients**
```c
Err_t ws_server_BroadcastBinaryMessage(WsServer_t* server, unsigned char* buffer, size_t length);
```
Broadcast a binary message to all WebSocket clients connected to the server.

- **param** server: WebSocket server.
- **param** buffer: Buffer to send.
- **param** length: Length of buffer.
- **returns** WS_OK on success.
---

#### **Send Disconnect message to client**
```c
Err_t ws_server_SendCloseMessage(WsEndpoint_t* endpoint, WsCloseReason_t reason);
```
Send a close message to a WebSocket endpoint.

- **param** endpoint: Recipient WsEndpoint_t.
- **param** reason: Reason for closing the connection.
- **returns** WS_OK on success.
---
#### **Tick Function**
```c
Err_t ws_server_Tick(WsServer_t* server);
```
Tick function for the WebSocket server. Call this function repeatedly for the server to process its events.

- **param** server: WsServer_t instance.
- **returns** WS_OK on success.
---
#### **Drop a Connection**
```c
Err_t ws_server_CloseConnection(WsEndpoint_t* endpoint);
```
Close the connection to a WebSocket endpoint.

- **param** endpoint: WsEndpoint_t instance.
- **returns** LWS_ERR_OK on success.

### ***Utilities***

#### **Left Trim**

```c
char* string_ltrim(char* s);
```
Trim whitespace from the beginning of the string

- **param** s Pointer to string with whitespace
- **returns** Pointer to trimmed string, NULL if s is NULL

---

#### **Right Trim**

```c
char* string_rtrim(char* s);
```
Trim whitespace from the end of the string

- **param** s Pointer to string with whitespace
- **returns** Pointer to trimmed string, NULL if s is NULL

---

#### **Trim**

```c
char* string_trim(char* s);
```
Trim whitespace from the both ends of the string

- **param** s Pointer to string with whitespace
- **returns** Pointer to trimmed string, NULL if s is NULL
