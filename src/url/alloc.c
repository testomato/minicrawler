#include <string.h>
#include <stdlib.h>

static inline unsigned int next_power2(unsigned int v) {
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

void append_c(char **p_buf, size_t *buf_sz, int *pos, const char c) {
	if (*pos + 1 + 1 > *buf_sz) {
		*buf_sz = next_power2(*pos + 1 + 1);
		*p_buf = realloc(*p_buf, *buf_sz);
	}
	(*p_buf)[(*pos)++] = c;
	(*p_buf)[*pos] = 0;
}

void append_s(char **p_buf, size_t *buf_sz, int *pos, const char *s) {
	size_t len = strlen(s);
	if (*pos + len + 1 > *buf_sz) {
		*buf_sz = next_power2(*pos + len + 1);
		*p_buf = realloc(*p_buf, *buf_sz);
	}
	strcpy(*p_buf + *pos, s);
	*pos += len;
}
