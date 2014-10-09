#include <assert.h>

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

extern struct surl *url;
extern struct ssettings settings;

#define debugf(...)   {if(settings.debug) fprintf(stderr, __VA_ARGS__);}

SSL_CTX *mossad(void);
void free_mossad(void);

int get_time_int(void);
unsigned get_time_slot(const unsigned char key[16]);
int test_free_channel(const unsigned char u_ip[16], const unsigned milis, const int force);
void go(void);
int converthtml2text(char *s, int len);
void conv_charset(struct surl *u);
char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len);
char *consume_entity(char *s, const char *end, int *code);
char *put_code(char *dst, const unsigned dst_len, const int code);
int urlencode(char *src);
void init_url(struct surl *u, const char *url, const int index, struct cookie *cookies, const int cookiecnt);
int gunzip(char *out, int *outlen, char *in, int inlen);

static inline int safe_size_to_int(const size_t sz) {
	assert((int)sz == sz && (int)sz >= 0);
	return (int)sz;
}
#define I_SIZEOF(__X) ( safe_size_to_int(sizeof(__X)) )
#define I_LENGTHOF(__X) ( sizeof(__X) > 0 ? safe_size_to_int(sizeof(__X)) - 1 : 0 )

static inline size_t write_all(const int fd, const char *buf, const size_t len) {
	size_t written = 0;
	do {
		const ssize_t r = write(fd, &buf[written], len - written);
		if (r <= 0) {
			return written;
		}
		written += (size_t)r;
	} while(written < len);

	return written;
}

static inline char *safe_cpy(char *dst, const char *src, const size_t sz) {
	size_t i = 0;
	for (; i < sz - 1 && src[i]; ++i) {
		dst[i] = src[i];
	}
	dst[i++] = 0;
	return &dst[i];
}

#ifdef __APPLE__

#include <stddef.h>

void *memmem(const void *big, size_t big_len, const void *little, size_t little_len);

static inline void *mempcpy(void *dest, const void *src, size_t n) {
	if (!n)
		return dest;
	char *d = (char*)dest;
	const char *s = (const char*)src;
	do {
		*d++ = *s++;
	} while (--n);
	return d;
}

static inline const char *strchrnul(const char *s, int c) {
	for (;; ++s) {
		if (0 == c || c == *s) {
			return s;
		}
	}
}

#endif
