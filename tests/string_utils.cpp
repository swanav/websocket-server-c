#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "gtest/gtest.h"

extern "C" {
	#include "string_utils.h"
}

#define TEST_STRING_LTRIM(x, y) \
    do {    \
        char str[] = x;    \
        printf("|%s|\n", string_ltrim(str));   \
		EXPECT_STREQ(string_ltrim(str), y);   \
    } while(0)

#define TEST_STRING_RTRIM(x, y) \
    do {    \
        char str[] = x;    \
        printf("|%s|\n", string_rtrim(str));   \
        EXPECT_STREQ(string_rtrim(str), y);     \
    } while(0)


#define TEST_STRING_TRIM(x, y) \
    do {    \
        char str[] = x;    \
        printf("|%s|\n", string_trim(str));   \
        EXPECT_STREQ(string_trim(str), y);     \
    } while(0)

TEST(StringTrim, StringWithoutWhitespace) {

    TEST_STRING_LTRIM("Hello", "Hello");
    TEST_STRING_RTRIM("Hello", "Hello");
    TEST_STRING_TRIM("Hello", "Hello");

}

TEST(StringTrim, StringWithLeadingWhitespace) {

    TEST_STRING_LTRIM(" Hello", "Hello");
    TEST_STRING_RTRIM(" Hello", " Hello");
    TEST_STRING_TRIM(" Hello", "Hello");

}

TEST(StringTrim, StringWithTrailingWhitespace) {

    TEST_STRING_LTRIM("Hello ", "Hello ");
    TEST_STRING_RTRIM("Hello ", "Hello");
    TEST_STRING_TRIM("Hello ", "Hello");

}

TEST(StringTrim, StringWithOnlyWhitespace) {
	TEST_STRING_LTRIM("  ", "");
    TEST_STRING_RTRIM("  ", "");
    TEST_STRING_TRIM("  ", "");
}

TEST(StringTrim, StringWithNoContent) {
	TEST_STRING_LTRIM("", "");
    TEST_STRING_RTRIM("", "");
    TEST_STRING_TRIM("", "");
}

TEST(StringTrim, StringWithWhitespaceInBetween) {
	TEST_STRING_LTRIM("Hello     World", "Hello     World");
    TEST_STRING_RTRIM("Hello     World", "Hello     World");
    TEST_STRING_TRIM("Hello     World", "Hello     World");
}

TEST(StringTrim, StringWithLeadingAndTrailingWhitespace) {
    TEST_STRING_LTRIM("  Hello World  ", "Hello World  ");
    TEST_STRING_RTRIM("  Hello World  ", "  Hello World");
    TEST_STRING_TRIM("  Hello World  ", "Hello World");
}

TEST(StringTrim, StringWithLeadingWhitespaceAndTrailingNewLine) {
    TEST_STRING_LTRIM("  x7V4CxnJOJiXA3uPCNAcug==\r\n", "x7V4CxnJOJiXA3uPCNAcug==\r\n");
    TEST_STRING_RTRIM("  x7V4CxnJOJiXA3uPCNAcug==\r\n", "  x7V4CxnJOJiXA3uPCNAcug==");
    TEST_STRING_TRIM("  x7V4CxnJOJiXA3uPCNAcug==\r\n", "x7V4CxnJOJiXA3uPCNAcug==");
}
