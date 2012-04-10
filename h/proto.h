

extern struct surl url[];
extern struct ssettings settings;

int get_time_int(void);
unsigned get_time_slot(const unsigned key);
int test_free_channel(const unsigned u_ip, const unsigned milis, const int force);
void go(void);
int converthtml2text(char *s, int len);
void conv_charset(struct surl *u);
char *detect_charset_from_html(char *s, const unsigned len, unsigned *charset_len);
char *consume_entity(char *s, const char *end, int *code);
char *put_code(char *dst, const unsigned dst_len, const int code);

#ifdef __APPLE__
#include <stddef.h>
static inline void *mempcpy(void *dest, const void *src, size_t n)
{
	if (!n)
		return dest;
	char *d = (char*)dest;
	const char *s = (const char*)src;
	do {
		*d++ = *s++;
	} while (--n);
	return d;
}
#endif
