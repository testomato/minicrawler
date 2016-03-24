#ifndef INCLUDED_JSON_H
#define INCLUDED_JSON_H

enum JSON_Value_Type {
    JSON_VALUE_TYPE_STRING = 1,
    JSON_VALUE_TYPE_NUMBER,
    JSON_VALUE_TYPE_OBJECT,
    JSON_VALUE_TYPE_ARRAY,
    JSON_VALUE_TYPE_TRUE,
    JSON_VALUE_TYPE_FALSE,
    JSON_VALUE_TYPE_NULL,
    JSON_VALUE_TYPE_ERROR
};

struct JSON_Value {
    enum JSON_Value_Type type;
    union {
        const char *string_value;
        double number_value;
        struct JSON_Value *compound_value;
    };
    struct JSON_Value *next_value;
};

struct JSON_Error {
    enum JSON_Value_Type type;
    int line_number;
    const char *message;
};

struct JSON_Value* JSON_Decode(const char* jsonData);
const char* JSON_Encode(struct JSON_Value* pValue, unsigned long allocSize, unsigned long *length);

struct JSON_Value* JSON_Value_New_String(const char* stringData);
struct JSON_Value* JSON_Value_New_Number(double numberValue);
struct JSON_Value* JSON_Value_New_Object();
struct JSON_Value* JSON_Value_New_Array();
struct JSON_Value* JSON_Value_New_True();
struct JSON_Value* JSON_Value_New_False();
struct JSON_Value* JSON_Value_New_Null();
void JSON_Value_Free(struct JSON_Value* pValue);

#endif
