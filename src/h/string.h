#include "config.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>

static inline int safe_size_to_int(const size_t sz) {
	assert((int)sz == sz && (int)sz >= 0);
	return (int)sz;
}
#define I_SIZEOF(__X) ( safe_size_to_int(sizeof(__X)) )
#define I_LENGTHOF(__X) ( sizeof(__X) > 0 ? safe_size_to_int(sizeof(__X)) - 1 : 0 )
#define SAFE_STRCPY(__D, __S) ( safe_strncpy(__D, __S, I_SIZEOF(__D), I_SIZEOF(__D)) )
#define SAFE_STRNCPY(__D, __S, __SZ) ( safe_strncpy(__D, __S, I_SIZEOF(__D), __SZ) )

static inline size_t write_all(const int fd, const unsigned char *buf, const size_t len) {
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

static inline char *safe_strncpy(char *dst, const char *src, const size_t dz, const size_t sz) {
	size_t i = 0;
	for (; i < dz - 1 && i < sz && src[i]; ++i) {
		dst[i] = src[i];
	}
	dst[i++] = 0;
	return &dst[i];
}

/** neci kod na str_replace (pod free licenci)
 */
static inline char *str_replace( char *dest,  const char *string, const char *substr, const char *replacement ) {
	char *tok = NULL;

	tok = strstr( string, substr );
	if( tok == NULL ) return strcpy( dest, string );
	memcpy( dest, string, tok - string );
	memcpy( dest + (tok - string), replacement, strlen( replacement ) );
	memcpy( dest + (tok - string) + strlen( replacement ), tok + strlen( substr ), strlen( string ) - strlen( substr ) - ( tok - string ) );
	memset( dest + strlen( string ) - strlen( substr ) + strlen( replacement ), 0, 1 );
	return dest;
}

/** kopirovani, ktere se ukonci i koncem radku
 */
static inline void *mempcpy_term(void *to, const void *from, const size_t size) {
	int i = 0;
	unsigned char *t = (unsigned char*)to;
	const unsigned char *f = (const unsigned char*)from;
	for(;*f != '\r' && *f != '\n';i++) {
		if (i < size)
			*t++ = *f++;
	}
	return t;
}

static inline void trim(char *str) {
	int len = strlen(str);
	char *p = str;
	while (len > 0 && (str[len-1] == ' ' || str[len-1] == '\t')) str[--len] = '\0';
	while (*p != '\0' && (*p == ' ' || *p == '\t')) p++;
	if (str != p)
		memmove(str, p, len+1 - (p-str));
}

#ifndef HAVE_MEMPCPY
static inline void *mempcpy(void *dest, const void *src, size_t n) {
	if (!n)
		return dest;
	unsigned char *d = (unsigned char*)dest;
	const unsigned char *s = (const unsigned char*)src;
	do {
		*d++ = *s++;
	} while (--n);
	return d;
}
#endif

#ifndef HAVE_STRCHRNUL
static inline char *strchrnul(const char *s, int c) {
	for (;; ++s) {
		if (0 == *s || c == *s) {
			return (char *) s;
		}
	}
}
#endif
