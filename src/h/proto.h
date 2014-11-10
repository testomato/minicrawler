#include <openssl/ssl.h>

#include "struct.h"

extern int debug;
#define debugf(...)   {if(debug) fprintf(stderr, __VA_ARGS__);}

SSL_CTX *mossad(void);
void free_mossad(void);

int get_time_int(void);
unsigned get_time_slot(const unsigned char key[16]);
int test_free_channel(const unsigned char u_ip[16], const unsigned milis, const int force);
int converthtml2text(char *s, int len);
void conv_charset(struct surl *u);
char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len);
char *consume_entity(char *s, const char *end, int *code);
char *put_code(char *dst, const unsigned dst_len, const int code);
int urlencode(char *src);
int gunzip(char *out, int *outlen, char *in, int inlen);
