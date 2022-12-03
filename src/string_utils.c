#include <ctype.h>
#include <string.h>

#include "string_utils.h"

char* string_ltrim(char* s) {
    if(!s) return NULL;
    while(isspace(*s)) s++;
    return s;
}

char* string_rtrim(char* s) {
    if(!s) return NULL;
    char* back = s + strlen(s);
    // Peek at the previous character.
    // Go back if previous character is also a space
    while(back != s && isspace(back[-1])) back--;
    *back = '\0';
    return s;
}

char* string_trim(char* s) {
    if(!s) return NULL;
    return string_rtrim(string_ltrim(s)); 
}
