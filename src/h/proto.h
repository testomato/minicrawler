#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#include "config.h"
#include "struct.h"

extern int debug;
#define debugf(...)   {if(debug) fprintf(stderr, __VA_ARGS__);}

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>
// cert.c
int create_ssl(mcrawler_url *);
void free_mossad(void);
#endif

// time.c
long long get_uptime(void);
void init_birth(void);
int get_time_int(void);
unsigned get_time_slot(const unsigned char key[16]);
int test_free_channel(const unsigned char u_ip[16], const int milis, const int force);
#ifndef HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif

// crawler.c
mcrawler_url_func get_url_callbacks();
void reset_url(mcrawler_url *u);

// converthtml2text.c
int converthtml2text(char *s, int len);

// conv.c
int conv_charset(mcrawler_url *u);
char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len);
char *consume_entity(char *s, const char *end, int *code);
char *put_code(char *dst, const unsigned dst_len, const int code);

// inflate.c
int gunzip(unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen);

// malloc.c
void *rpl_malloc(size_t n);

// base64.c
int base64_len(int);
void base64(char *, const void *, int);

// cookie.c
char *store_cookie_domain(const struct nv *attr, mcrawler_cookie *cookie);
time_t parse_cookie_date(char *date);
size_t cookies_header_max_size(mcrawler_url *u);
void set_cookies_header(mcrawler_url *u, char *buf, size_t *p_len);
void remove_expired_cookies(mcrawler_url *u);
void setcookie(mcrawler_url *u, char *str);

// auth.c
void basicauth(mcrawler_url *u, struct challenge *ch);
void digestauth(mcrawler_url *u, struct challenge *ch);
void parse_single_challenge(mcrawler_url *u, char **pp, struct challenge *ch);
void parse_authchallenge(mcrawler_url *u, char *challenge);

// http1.c
typedef void (*header_callback)(const char *name, char *value, void *);
unsigned char *find_head_end(unsigned char *s, const size_t len);
int parsehead(const unsigned char *s, const size_t len, int *status, header_callback header_callback, void *data, int index);
int eatchunk(mcrawler_url *u);

// http2.c
int http2_session_send(mcrawler_url *u);

// memory.c
void free_addr(mcrawler_addr *);

// buf.c
unsigned char *buf_p(mcrawler_url *);
size_t buf_len(mcrawler_url *);
void buf_set_len(mcrawler_url *, size_t);
void buf_get(mcrawler_url *, const size_t min_sz, unsigned char **data, size_t *len);
#define buf_write_lit(u, string) {buf_write(u, (const unsigned char*)string, (sizeof(string)-1));}
size_t buf_write(mcrawler_url *, const unsigned char *data, size_t len);
void buf_inc(mcrawler_url *, size_t len);
void buf_del(mcrawler_url *, size_t dellen);
void buf_free(mcrawler_url *);

