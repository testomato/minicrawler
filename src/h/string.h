#include <string.h>
#include <assert.h>
#include <unistd.h>

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

/** strcpy, ktere se ukonci i koncem radku
 */
static inline int strcpy_term(char *to, char *from, const size_t size) {
	int i = 0;
	for(;*from && *from != '\r' && *from != '\n';i++) {
		if (i < size)
			*to++ = *from++;
		else return 0;
	}
	if (i < size)
		*to = 0;
	else return 0;
	return 1;
}

static inline void trim(char *str) {
	int len = strlen(str);
	char *p = str;
	while (len > 0 && (str[len-1] == ' ' || str[len-1] == '\t')) str[--len] = '\0';
	while (*p != '\0' && (*p == ' ' || *p == '\t')) p++;
	if (str != p)
		memmove(str, p, len+1 - (p-str));
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

static inline char *strchrnul(const char *s, int c) {
	for (;; ++s) {
		if (0 == *s || c == *s) {
			return (char *) s;
		}
	}
}

#endif
