#include <stdio.h>
#include <stdlib.h>

#include "gtest/gtest.h"

extern "C" {
	#include "ws_protocol.h"
}

TEST(ws_server_GetDataLength, ShouldFailOnEmptyBuffer) {
	unsigned char frame[] = {};
	size_t len = sizeof(frame);
	unsigned char offset = 0;

	int64_t outputSize = ws_server_GetDataLength(frame, len, &offset);

	EXPECT_EQ(outputSize, -LWS_ERR_FAIL);

}

// TEST(ws_server_GetDataLength, ShouldFailIfBufferInsufficient) {
// 	unsigned char frame[] = { 0x00, 0xFF };
// 	size_t len = sizeof(frame);
// 	unsigned char offset = 0;

// 	int64_t outputSize = ws_server_GetDataLength(frame, len, &offset);

// 	printf("%ld\n", outputSize);

// 	EXPECT_EQ(outputSize, -LWS_ERR_FAIL);

// }