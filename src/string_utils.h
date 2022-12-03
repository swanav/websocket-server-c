#ifndef STRING_UTILS_H
#define STRING_UTILS_H

/**
 * @brief Trim left whitespace from the string
 * 
 * @param s Pointer to string with whitespace
 * 
 * @return Pointer to trimmed string, NULL if s is NULL
 * 
 */ 
char* string_ltrim(char* s);

/**
 * @brief Trim left whitespace from the string
 * 
 * @param s Pointer to string with whitespace
 * 
 * @return Pointer to trimmed string, NULL if s is NULL
 * 
 */ 
char* string_rtrim(char* s);

/**
 * @brief Trim whitespace from the string
 * 
 * @param s Pointer to string with whitespace
 * 
 * @return Pointer to trimmed string, NULL if s is NULL
 * 
 */ 
char* string_trim(char* s);

#endif // STRING_UTILS_H
