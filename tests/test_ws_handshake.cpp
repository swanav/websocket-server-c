#include <stdio.h>
#include <stdlib.h>

#include "gtest/gtest.h"

extern "C" {
	#include "ws_protocol.h"
}

/*=============================================================================================*/
/*                              Test Name: HAPPY FLOW SCENARIO                                 */
/*=============================================================================================*/
TEST(Websocket_Handshake, MustRespondToAProperWebsocketHandshakeRequest) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"GET / HTTP/1.1\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Sec-WebSocket-Key: N3E5Lyd5CZS6LSkOg+Z3hg==\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: websocket\r\n"
	"Host: localhost:8080\r\n"
	"\r\n";
	char output[320];
	int outputLength = 0;

	EXPECT_EQ(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);

	EXPECT_TRUE(!strncmp("N3E5Lyd5CZS6LSkOg+Z3hg==", parserMeta.SecWebsocketKey, parserMeta.SecWebsocketKeyLength));

	EXPECT_EQ(PrepareHttpWebsocketUpgradeResponse(&parserMeta, (unsigned char*) output, sizeof(output), &outputLength), LWS_ERR_OK);


	char expectedResponse[] = 
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: EvIxQLcAvnNY0HkUpk5CNuXcOKA=\r\n"
		"\r\n";

	EXPECT_TRUE(!strncmp(output, expectedResponse, outputLength));
}

/*==============================================================================================*/
/*                              Test Criterion 1                                 				*/
/*																								*/
/*	   1.   The handshake MUST be a valid HTTP request as specified by [RFC2616].               */											
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustBeAValidHttpRequest) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"GET /"
	"Sec-WebSocket-Version: 13"
	"Sec-WebSocket-Key: N3E5Lyd5CZS6LSkOg+Z3hg=="
	"Connection: Upgrade"
	"Upgrade: websocket"
	"Host: localhost:8080";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);
}

/*==============================================================================================*/
/*                              Test Criterion 2                                 				*/
/*																								*/
/*	   2.   The method of the request MUST be GET, and the HTTP version MUST  be at least 1.1.  */											
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustBeAGetRequestAndHttpGreaterThan1v1) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"POST / HTTP/1.0\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Sec-WebSocket-Key: N3E5Lyd5CZS6LSkOg+Z3hg==\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: websocket\r\n"
	"Host: localhost:8080\r\n"
	"\r\n";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);

}


/*==============================================================================================*/
/*                              Test Criterion 3                                 				*/
/*																								*/
/*	   4. The request MUST contain a |Host| header field whose value contains /host/ plus 		*/
/*		  optionally ":" followed by /port/ (when not using the default port). 					*/
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustContainAHostHeaderField) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"POST / HTTP/1.0\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Sec-WebSocket-Key: N3E5Lyd5CZS6LSkOg+Z3hg==\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: websocket\r\n"
	"\r\n";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);
}

/*==============================================================================================*/
/*                              Test Criterion 4                                 				*/
/*																								*/
/*	   5. The request MUST contain an |Upgrade| header field whose value MUST include the 		*/
/*		  "websocket" keyword. 																	*/
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustContainUpgradeHeaderFieldWithValueEqualToWebsocket) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"GET / HTTP/1.1\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Sec-WebSocket-Key: N3E5Lyd5CZS6LSkOg+Z3hg==\r\n"
	"Connection: Upgrade\r\n"
	"Host: localhost:8080\r\n"
	"\r\n";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);
}

/*==============================================================================================*/
/*                              Test Criterion 5                                 				*/
/*																								*/
/*	   6. The request MUST contain a |Connection| header field whose value MUST include the		*/ 
/*		"Upgrade" token.				 														*/
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustContainConnectionHeaderFieldWithValueEqualToUpgrade) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"GET / HTTP/1.1\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Sec-WebSocket-Key: N3E5Lyd5CZS6LSkOg+Z3hg==\r\n"
	"Upgrade: websocket\r\n"
	"Host: localhost:8080\r\n"
	"\r\n";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);

}

/*==============================================================================================*/
/*                              Test Criterion 6                                 				*/
/*	   																							*/
/*	7.    The request MUST include a header field with the name |Sec-WebSocket-Key|.  The value */
/*		  of this header field MUST be a nonce consisting of a randomly selected 16-byte value  */
/*		  that has been base64-encoded (see Section 4 of [RFC4648]).  The nonce MUST be			*/ 
/*		  selected randomly for each connection.												*/
/*																								*/
/*        NOTE: As an example, if the randomly selected value was the sequence of bytes 		*/
/*		  0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f 0x10, the  */
/*		  value of the header field would be "AQIDBAUGBwgJCgsMDQ4PEC=="							*/
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustContainSecWebsocketKeyHeaderFieldWithA16ByteNonce) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"GET / HTTP/1.1\r\n"
	"Sec-WebSocket-Version: 13\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: websocket\r\n"
	"Host: localhost:8080\r\n"
	"\r\n";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);

}


/*==============================================================================================*/
/*                              Test Criterion 7                                 				*/
/*	   																							*/
/*	9.   The request MUST include a header field with the name |Sec-WebSocket-Version|.  The	*/ 
/*	     value of this header field MUST be 13.													*/
/*																								*/
/*       NOTE: Although draft versions of this document (-09, -10, -11, and -12) were posted 	*/
/*		 (they were mostly comprised of editorial changes and clarifications and not changes to */
/*		 the wire protocol), values 9, 10, 11, and 12 were not used as valid values for 		*/
/*		 Sec-WebSocket-Version.  These values were reserved in the IANA registry but were not	*/
/*		 and will not be used.																	*/
/*																								*/
/*==============================================================================================*/
TEST(Websocket_Handshake, MustContainSecWebsocketVersionHeaderFieldWithValueEqualTo13) {
	struct __websocket_request_parser_meta parserMeta = { 0 };

	unsigned char input[] = 
	"GET / HTTP/1.1\r\n"
	"Sec-WebSocket-Version: 12\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: websocket\r\n"
	"Host: localhost:8080\r\n"
	"\r\n";

	EXPECT_NE(ParseHttpWebsocketUpgradeRequest(&parserMeta, input, sizeof(input)), LWS_ERR_OK);

}