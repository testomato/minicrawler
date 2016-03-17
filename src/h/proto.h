#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#include "config.h"
#include "struct.h"

extern int debug;
#define debugf(...)   {if(debug) fprintf(stderr, __VA_ARGS__);}

#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>

SSL_CTX *mossad(void);
void free_mossad(void);
#endif

void init_birth(void);
int get_time_int(void);
unsigned get_time_slot(const unsigned char key[16]);
int test_free_channel(const unsigned char u_ip[16], const unsigned milis, const int force);
#ifndef HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif
int converthtml2text(char *s, int len);
int conv_charset(mcrawler_url *u);
char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len);
char *consume_entity(char *s, const char *end, int *code);
char *put_code(char *dst, const unsigned dst_len, const int code);
int urlencode(char *src);
int gunzip(unsigned char *out, int *outlen, unsigned char *in, int inlen);
void *rpl_malloc(size_t n);
int base64_len(int);
void base64(char *, const void *, int);
char *store_cookie_domain(const struct nv *attr, mcrawler_cookie *cookie);
time_t parse_cookie_date(char *date);
