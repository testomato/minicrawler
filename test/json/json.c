#include "json.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* Naming convention:
   All functions and structures start with JSON.
   All externally visible functions and structures having leading caps.
   All internal-only functions and structures are lower case.
*/

/* JSON Structure Support */

static struct JSON_Value* JSON_value_new(enum JSON_Value_Type type) {
    struct JSON_Value* pResult= (struct JSON_Value*)malloc(sizeof(struct JSON_Value));
    if (!pResult) {
        return 0;
    }
    pResult->type= type;
    pResult->string_value= 0;
    pResult->next_value= 0;
    return pResult;
}

struct JSON_Value* JSON_Value_New_String(const char* stringData) {
    struct JSON_Value* pResult= JSON_value_new(JSON_VALUE_TYPE_STRING);
    pResult->string_value= strdup(stringData);
    return pResult;
}

struct JSON_Value* JSON_Value_New_Number(double numberValue) {
    struct JSON_Value* pResult= JSON_value_new(JSON_VALUE_TYPE_NUMBER);
    pResult->number_value= numberValue;
    return pResult;
}

struct JSON_Value* JSON_Value_New_Object() {
    return JSON_value_new(JSON_VALUE_TYPE_OBJECT);
}

struct JSON_Value* JSON_Value_New_Array() {
    return JSON_value_new(JSON_VALUE_TYPE_ARRAY);
}
struct JSON_Value* JSON_Value_New_True() {
    return JSON_value_new(JSON_VALUE_TYPE_TRUE);
}

struct JSON_Value* JSON_Value_New_False() {
    return JSON_value_new(JSON_VALUE_TYPE_FALSE);
}

struct JSON_Value* JSON_Value_New_Null() {
    return JSON_value_new(JSON_VALUE_TYPE_NULL);
}

void JSON_Value_Free(struct JSON_Value* pValue) {
    if (!pValue) {
        return;
    }
    if (pValue->type == JSON_VALUE_TYPE_ERROR) {
        free((struct JSON_Error*)pValue);
        return;
    }
    else if (pValue->type == JSON_VALUE_TYPE_OBJECT || pValue->type == JSON_VALUE_TYPE_ARRAY) {
        struct JSON_Value *pChildObject= pValue->compound_value;
        while (pChildObject) {
            struct JSON_Value *pNext= pChildObject->next_value;
            JSON_Value_Free(pChildObject);
            pChildObject= pNext;
        }
    }
    else if (pValue->type == JSON_VALUE_TYPE_STRING && pValue->string_value) {
        free((void*)pValue->string_value);
        pValue->string_value= 0;
    }
    free(pValue);
}


/* JSON Decoding */

struct JSON_decoder_state {
    const char *currentChar;
    int currentLine;
};
static struct JSON_Value* JSON_decode_value(struct JSON_decoder_state *pState);

static struct JSON_Value* JSON_error_new(struct JSON_decoder_state *pState, const char *message) {
    struct JSON_Error* pResult= (struct JSON_Error*)malloc(sizeof(struct JSON_Error));
    if (!pResult) {
        return 0;
    }
    pResult->type= JSON_VALUE_TYPE_ERROR;
    pResult->line_number= pState->currentLine;
    pResult->message= message;
    return (struct JSON_Value*)pResult;
}

static char JSON_next_char(struct JSON_decoder_state *pState) {
    if (*pState->currentChar != '\0') {
        ++pState->currentChar;
    }
    return *pState->currentChar;
}

static char JSON_skip_ws(struct JSON_decoder_state *pState) {
    const char *p= pState->currentChar;
    while (*p != '\0' && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\f' || *p == '\n')) {
        if (*p == '\n') {
            ++pState->currentLine;
        }
        ++p;
    }
    pState->currentChar= p;
    return *p;
}

static struct JSON_Value* JSON_decode_number(struct JSON_decoder_state *pState) {
    struct JSON_Value *result= 0;
    struct JSON_Value *errorResult= 0;

    double sign= +1;
    double whole_part= 0;
    double fractional_part= 0;
    int fractional_digit= 1;
    double fractional_scale= 0.1;
    double exponent_sign= +1;
    double exponent_part= 0;
    char ch= 0;

    if (*pState->currentChar == '-') {
        sign= -1;
        JSON_next_char(pState);
    }

    if (*pState->currentChar == '0') {
        JSON_next_char(pState);
        goto expect_decimal;
    }

expect_digit:
    switch (*pState->currentChar) {
        case '0': whole_part= whole_part*10; break;
        case '1': whole_part= whole_part*10+1; break;
        case '2': whole_part= whole_part*10+2; break;
        case '3': whole_part= whole_part*10+3; break;
        case '4': whole_part= whole_part*10+4; break;
        case '5': whole_part= whole_part*10+5; break;
        case '6': whole_part= whole_part*10+6; break;
        case '7': whole_part= whole_part*10+7; break;
        case '8': whole_part= whole_part*10+8; break;
        case '9': whole_part= whole_part*10+9; break;
        default:
            if (whole_part == 0) {
                errorResult= JSON_error_new(pState, "Expected a digit.");
                goto error;
            } else {
                goto expect_decimal;
            }
    }
    JSON_next_char(pState);
    goto expect_digit;


expect_decimal:
    if (*pState->currentChar != '.') {
        goto expect_exponent;
    }

expect_fractional_digit:
    fractional_scale= pow(10, -fractional_digit);
    switch (JSON_next_char(pState)) {
        case '0': break;
        case '1': fractional_part+= 1*fractional_scale; break;
        case '2': fractional_part+= 2*fractional_scale; break;
        case '3': fractional_part+= 3*fractional_scale; break;
        case '4': fractional_part+= 4*fractional_scale; break;
        case '5': fractional_part+= 5*fractional_scale; break;
        case '6': fractional_part+= 6*fractional_scale; break;
        case '7': fractional_part+= 7*fractional_scale; break;
        case '8': fractional_part+= 8*fractional_scale; break;
        case '9': fractional_part+= 9*fractional_scale; break;
        default:
            goto done;
    }
    ++fractional_digit;
    goto expect_fractional_digit;

expect_exponent:
    ch= *pState->currentChar;
    if (ch != 'e' && ch != 'E') {
        goto done;
    }
    ch= JSON_next_char(pState);
    if (ch == '+') {
        exponent_sign= +1;
        JSON_next_char(pState);
    } else if (ch == '-') {
        exponent_sign= -1;
        JSON_next_char(pState);
    }

expect_exponent_digit:
    switch (*pState->currentChar) {
        case '0': exponent_part= exponent_part*10; break;
        case '1': exponent_part= exponent_part*10+1; break;
        case '2': exponent_part= exponent_part*10+2; break;
        case '3': exponent_part= exponent_part*10+3; break;
        case '4': exponent_part= exponent_part*10+4; break;
        case '5': exponent_part= exponent_part*10+5; break;
        case '6': exponent_part= exponent_part*10+6; break;
        case '7': exponent_part= exponent_part*10+7; break;
        case '8': exponent_part= exponent_part*10+8; break;
        case '9': exponent_part= exponent_part*10+9; break;
        default:
            goto done;
    }
    JSON_next_char(pState);
    goto expect_exponent_digit;

done:
    result= JSON_Value_New_Number(sign * (whole_part + fractional_part));
    if (exponent_part != 0) {
        result->number_value= result->number_value * pow(10, exponent_sign * exponent_part);
    }
    return result;

error:
    JSON_Value_Free(result);
    return errorResult;
}

static int JSON_decode4Hex(const char *pHexString) {
    int result= 0;
    char ch= 0;
    int i= 0;
    for (i=0;i<4;++i) {
        result= result<<8;
        ch= pHexString[i];
        switch (ch) {
            case '0': break;
            case '1': result+= 1; break;
            case '2': result+= 2; break;
            case '3': result+= 3; break;
            case '4': result+= 4; break;
            case '5': result+= 5; break;
            case '6': result+= 6; break;
            case '7': result+= 7; break;
            case '8': result+= 8; break;
            case '9': result+= 9; break;
            case 'a': case 'A': result+= 10; break;
            case 'b': case 'B': result+= 11; break;
            case 'c': case 'C': result+= 12; break;
            case 'd': case 'D': result+= 13; break;
            case 'e': case 'E': result+= 14; break;
            case 'f': case 'F': result+= 15; break;
            default: break;
        }
    }
    return result;
}

static void decodeStringEscaping(char *pOut, const char *pStart, const char *pEnd) {
    const char *pSrc= pStart;
    char *pDest= pOut;
    int unicodeValue= 0;

    while (pSrc < pEnd) {
        if (*pSrc != '\\') {
            *pDest++ = *pSrc++;
            continue;
        }
        pSrc++;
        switch (*pSrc) {
            case '\"': *pDest++= '\"'; break;
            case '\\': *pDest++= '\\'; break;
            case '/':  *pDest++= '/';  break;
            case 'b':  *pDest++= '\b'; break;
            case 'f':  *pDest++= '\f'; break;
            case 'n':  *pDest++= '\n'; break;
            case 'r':  *pDest++= '\r'; break;
            case 't':  *pDest++= '\t'; break;
            case 'u':
                unicodeValue= JSON_decode4Hex(pSrc+1);
                pSrc+= 5;
                if (unicodeValue <= 0x7F) {
                    *pDest++= (char)unicodeValue;
                } else if (unicodeValue <= 0x7FF) {
                    *pDest++= (0xC0 | (unicodeValue >> 6));
                    *pDest++= (0x80 | (unicodeValue & 0x3F));
                } else {
                    *pDest++= (0xE0 | (unicodeValue >> 12));
                    *pDest++= (0x80 | ((unicodeValue >> 6) & 0x3F));
                    *pDest++= (0x80 | (unicodeValue & 0x3F));
                }
                break;
            default:
                // Ignore invalid escape codes.
                break;
        }
    }
    *pDest= '\0';
}

struct JSON_Value *JSON_decode_string(struct JSON_decoder_state *pState) {
    struct JSON_Value *result= 0;
    struct JSON_Value *errorResult= 0;
    int lineCount= 0;
    const char *stringValueStart= 0;
    size_t stringLength= 0;

    if (JSON_skip_ws(pState) != '\"') {
        errorResult= JSON_error_new(pState, "Expected opening '\"'.");
        goto error;
    }

    ++pState->currentChar;
    stringValueStart= pState->currentChar;

    for (;;) {
        if (*pState->currentChar == '\"') {
            result= JSON_value_new(JSON_VALUE_TYPE_STRING);
            result->string_value= (char*)malloc((stringLength+1)*sizeof(char));
            decodeStringEscaping((char*)result->string_value, stringValueStart, pState->currentChar);
            pState->currentLine+= lineCount;
            JSON_next_char(pState);
            return result;
        }
        if (*pState->currentChar == '\0') {
            errorResult= JSON_error_new(pState, "Unterminated string.");
            goto error;
        }
        if (*pState->currentChar == '\\') {
            ++pState->currentChar;
            if (*pState->currentChar == '\0') {
                errorResult= JSON_error_new(pState, "Unterminated string.");
                goto error;
            }
            else if (*pState->currentChar == 'u') {
                // 4 hex digits....
                if (pState->currentChar[1] == '\0' || pState->currentChar[2] == '\0' || pState->currentChar[3] == '\0' || pState->currentChar[4] == '\0') {
                    errorResult= JSON_error_new(pState, "Unterminated string.");
                    goto error;
                }
                pState->currentChar+= 5;
                stringLength+= 3; // We encode to UTF-8 and the longest 16 bit unicode char is 3 bytes.
                continue;
            }
            // All other escape codes are a single character.
        }
        ++stringLength;
        ++pState->currentChar;
    }

error:
    JSON_Value_Free(result);
    return errorResult;
}

struct JSON_Value *JSON_decode_object(struct JSON_decoder_state *pState) {
    struct JSON_Value *result= 0;
    struct JSON_Value *errorResult= 0;
    struct JSON_Value *pKey= 0;
    struct JSON_Value *pValue= 0;
    struct JSON_Value **pNextPtr= 0;

    if (JSON_skip_ws(pState) != '{') {
        errorResult= JSON_error_new(pState, "Expected '{'.");
        goto error;
    }
    JSON_next_char(pState);
    JSON_skip_ws(pState);

    // Allocate an object in result!
    result= JSON_Value_New_Object();
    pNextPtr= &result->compound_value;
    *pNextPtr= 0;

    if (*pState->currentChar == '}') {
        goto done;
    }

decode_pair:
    pKey= JSON_decode_string(pState);
    if (pKey->type != JSON_VALUE_TYPE_STRING) {
        errorResult= pKey;
        pKey= 0;
        goto error;
    }

    if (JSON_skip_ws(pState) != ':') {
        errorResult= JSON_error_new(pState, "Expected ':'.");
        goto error;
    }
    JSON_next_char(pState);

    pValue= JSON_decode_value(pState);
    if (pValue->type == JSON_VALUE_TYPE_ERROR) {
        errorResult= pValue;
        pValue= 0;
        goto error;
    }

    *pNextPtr= pKey;
    pNextPtr= &((*pNextPtr)->next_value);
    *pNextPtr= pValue;
    pNextPtr= &((*pNextPtr)->next_value);
    pKey= 0;
    pValue= 0;

    // Check for , or }
    switch (JSON_skip_ws(pState)) {
        case ',':
            JSON_next_char(pState);
            goto decode_pair;
        case '}':
            goto done;
        default:
            errorResult= JSON_error_new(pState, "Expected '}'.");
            goto error;
    }

done:
    JSON_next_char(pState);
    return result;

error:
    JSON_Value_Free(result);
    JSON_Value_Free(pKey);
    JSON_Value_Free(pValue);
    return errorResult;
}

static struct JSON_Value* JSON_decode_array(struct JSON_decoder_state *pState) {
    struct JSON_Value *result= 0;
    struct JSON_Value *errorResult= 0;
    struct JSON_Value *pValue= 0;
    struct JSON_Value **pNextPtr= 0;

    if (JSON_skip_ws(pState) != '[') {
        errorResult= JSON_error_new(pState, "Expected '['.");
        goto error;
    }
    JSON_next_char(pState);

    // Allocate an object in result!
    result= JSON_Value_New_Array();
    pNextPtr= &result->compound_value;
    *pNextPtr= 0;

    if (JSON_skip_ws(pState) == ']') {
        goto done;
    }

decode_element:
    pValue= JSON_decode_value(pState);
    if (pValue->type == JSON_VALUE_TYPE_ERROR) {
        errorResult= pValue;
        pValue= 0;
        goto error;
    }

    *pNextPtr= pValue;
    pNextPtr= &((*pNextPtr)->next_value);
    pValue= 0;

    // Check for , or ]
    switch (JSON_skip_ws(pState)) {
        case ',':
            JSON_next_char(pState);
            goto decode_element;
        case ']':
            goto done;
        default:
            errorResult= JSON_error_new(pState, "Expected ']'.");
            goto error;
    }

done:
    JSON_next_char(pState);
    return result;

error:
    JSON_Value_Free(result);
    JSON_Value_Free(pValue);
    return errorResult;
}

static struct JSON_Value* JSON_decode_true(struct JSON_decoder_state *pState) {
    JSON_skip_ws(pState);
    if (pState->currentChar[0] != 't' ||
        pState->currentChar[1] != 'r' ||
        pState->currentChar[2] != 'u' ||
        pState->currentChar[3] != 'e') {
        return JSON_error_new(pState, "Expected 'true'.");
    } else {
        pState->currentChar+= 4;
        return JSON_Value_New_True();
    }
}

static struct JSON_Value* JSON_decode_false(struct JSON_decoder_state *pState) {
    JSON_skip_ws(pState);
    if (pState->currentChar[0] != 'f' ||
        pState->currentChar[1] != 'a' ||
        pState->currentChar[2] != 'l' ||
        pState->currentChar[3] != 's' ||
        pState->currentChar[4] != 'e') {
        return JSON_error_new(pState, "Expected 'false'.");
    } else {
        pState->currentChar+= 5;
        return JSON_Value_New_False();
    }
}

static struct JSON_Value* JSON_decode_null(struct JSON_decoder_state *pState) {
    JSON_skip_ws(pState);
    if (pState->currentChar[0] != 'n' ||
        pState->currentChar[1] != 'u' ||
        pState->currentChar[2] != 'l' ||
        pState->currentChar[3] != 'l') {
        return JSON_error_new(pState, "Expected 'null'.");
    } else {
        pState->currentChar+= 4;
        return JSON_Value_New_Null();
    }
}


static struct JSON_Value* JSON_decode_value(struct JSON_decoder_state *pState) {
    switch (JSON_skip_ws(pState)) {
        case '\"':
            return JSON_decode_string(pState);
        case '{':
            return JSON_decode_object(pState);
        case '[':
            return JSON_decode_array(pState);
        case 't':
            return JSON_decode_true(pState);
        case 'f':
            return JSON_decode_false(pState);
        case 'n':
            return JSON_decode_null(pState);
        default:
            return JSON_decode_number(pState);
    }
}

struct JSON_Value *JSON_Decode(const char *jsonData) {
    struct JSON_decoder_state state;
    state.currentChar= jsonData;
    state.currentLine= 1;
    return JSON_decode_object(&state);
}



/* JSON Encoding */

struct JSON_encoder_state {
    char *dataBlock;
    size_t dataBlockSize;
    size_t writePosition;
    size_t allocSize;
};
static void JSON_encode_value(struct JSON_encoder_state *pState, struct JSON_Value *pValue);

static void JSON_encode_write_char(struct JSON_encoder_state *pState, char ch) {
    if (pState->writePosition == pState->dataBlockSize) {
        pState->dataBlockSize+= pState->allocSize;
        pState->dataBlock= (char*)realloc(pState->dataBlock, pState->dataBlockSize * sizeof(char));
    }
    pState->dataBlock[pState->writePosition++]= ch;
}

static void JSON_encode_write_string(struct JSON_encoder_state *pState, const char *s) {
    size_t len= strlen(s);
    if (len == 0) {
        return;
    }
    size_t writeEnd= pState->writePosition+len;
    if (writeEnd >= pState->dataBlockSize) {
        size_t blockCount= (writeEnd - pState->dataBlockSize)/pState->allocSize + 1;
        pState->dataBlockSize+= blockCount * pState->allocSize;
        pState->dataBlock= (char*)realloc(pState->dataBlock, pState->dataBlockSize * sizeof(char));
    }
    memcpy(pState->dataBlock+pState->writePosition, s, len);
    pState->writePosition+= len;
}

static void JSON_encode_string(struct JSON_encoder_state *pState, struct JSON_Value *pValue) {
    JSON_encode_write_char(pState, '\"');
    const char *pCh= pValue->string_value;
    for (;*pCh!='\0';++pCh) {
        switch (*pCh) {
            case '\"': JSON_encode_write_string(pState, "\\\""); break;
            case '\\': JSON_encode_write_string(pState, "\\\\"); break;
            case '/':  JSON_encode_write_string(pState, "\\/"); break;
            case '\b': JSON_encode_write_string(pState, "\\b"); break;
            case '\f': JSON_encode_write_string(pState, "\\f"); break;
            case '\n': JSON_encode_write_string(pState, "\\n"); break;
            case '\r': JSON_encode_write_string(pState, "\\r"); break;
            case '\t': JSON_encode_write_string(pState, "\\t"); break;
            default:
                if (*pCh <= 0x1f) {
                    JSON_encode_write_string(pState, "\\u00");
                    if (*pCh & 0x10) {
                        JSON_encode_write_char(pState, '1');
                    } else {
                        JSON_encode_write_char(pState, '0');
                    }
                    switch (*pCh & 0xF) {
                        case 0x0: JSON_encode_write_char(pState, '0'); break;
                        case 0x1: JSON_encode_write_char(pState, '1'); break;
                        case 0x2: JSON_encode_write_char(pState, '2'); break;
                        case 0x3: JSON_encode_write_char(pState, '3'); break;
                        case 0x4: JSON_encode_write_char(pState, '4'); break;
                        case 0x5: JSON_encode_write_char(pState, '5'); break;
                        case 0x6: JSON_encode_write_char(pState, '6'); break;
                        case 0x7: JSON_encode_write_char(pState, '7'); break;
                        case 0x8: JSON_encode_write_char(pState, '8'); break;
                        case 0x9: JSON_encode_write_char(pState, '9'); break;
                        case 0xA: JSON_encode_write_char(pState, 'A'); break;
                        case 0xB: JSON_encode_write_char(pState, 'B'); break;
                        case 0xC: JSON_encode_write_char(pState, 'C'); break;
                        case 0xD: JSON_encode_write_char(pState, 'D'); break;
                        case 0xE: JSON_encode_write_char(pState, 'E'); break;
                        case 0xF: JSON_encode_write_char(pState, 'F'); break;
                    }
                }
                JSON_encode_write_char(pState, *pCh);
                break;
        }
    }
    JSON_encode_write_char(pState, '\"');
}

#include <stdio.h>
static void JSON_encode_number(struct JSON_encoder_state *pState, struct JSON_Value *pValue) {
    if (pValue->number_value != pValue->number_value) {
        JSON_encode_write_string(pState, "0");
        return;
    }
    char numberBuffer[64];
    sprintf(numberBuffer, "%.16g", pValue->number_value);
    JSON_encode_write_string(pState, numberBuffer);
}

static void JSON_encode_object(struct JSON_encoder_state *pState, struct JSON_Value *pValue) {
    JSON_encode_write_char(pState, '{');
    struct JSON_Value *pItem= pValue->compound_value;
    while(pItem != NULL) {
        JSON_encode_value(pState, pItem);
        JSON_encode_write_char(pState,':');
        JSON_encode_value(pState, pItem->next_value);
        pItem= pItem->next_value->next_value;
        if (pItem != NULL) {
            JSON_encode_write_char(pState, ',');
        }
    }
    JSON_encode_write_char(pState, '}');
}

static void JSON_encode_array(struct JSON_encoder_state *pState, struct JSON_Value *pValue) {
    JSON_encode_write_char(pState, '[');
    struct JSON_Value *pItem= pValue->compound_value;
    while(pItem != NULL) {
        JSON_encode_value(pState, pItem);
        pItem= pItem->next_value;
        if (pItem != NULL) {
            JSON_encode_write_char(pState, ',');
        }
    }
    JSON_encode_write_char(pState, ']');
}

static void JSON_encode_value(struct JSON_encoder_state *pState, struct JSON_Value *pValue) {
    switch(pValue->type) {
        case JSON_VALUE_TYPE_NULL:
            JSON_encode_write_string(pState, "null"); break;
        case JSON_VALUE_TYPE_TRUE:
            JSON_encode_write_string(pState, "true"); break;
        case JSON_VALUE_TYPE_FALSE:
            JSON_encode_write_string(pState, "false"); break;
        case JSON_VALUE_TYPE_STRING:
            JSON_encode_string(pState, pValue); break;
        case JSON_VALUE_TYPE_NUMBER:
            JSON_encode_number(pState, pValue); break;
        case JSON_VALUE_TYPE_OBJECT:
            JSON_encode_object(pState, pValue); break;
        case JSON_VALUE_TYPE_ARRAY:
            JSON_encode_array(pState, pValue); break;
        default: break;
    }
}

const char* JSON_Encode(struct JSON_Value *pValue, unsigned long allocSize, unsigned long *length) {
    if (length) {
        *length= 0;
    }
    size_t alloc_size_t= (size_t)allocSize;
    if (alloc_size_t == 0) {
        alloc_size_t= 1024;
    }
    struct JSON_encoder_state state;
    state.dataBlock= (char*)malloc(alloc_size_t * sizeof(char));
    state.dataBlockSize= alloc_size_t;
    state.writePosition= 0;
    state.allocSize= alloc_size_t;
    JSON_encode_value(&state, pValue);
    JSON_encode_write_char(&state, '\0');
    if (length) {
        *length= state.writePosition;
    }
    return state.dataBlock;
}
