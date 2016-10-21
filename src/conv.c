#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <iconv.h>

#include "h/proto.h"


/**
 * Convert body of the page from u->charset to
 *   UCS4. Use dst as a destination buffer.
 */
static int convertor(const char *from_charset, const char *to_charset, char *src, size_t src_left, char **dst, size_t *dst_left)
{

	const iconv_t desc = iconv_open(to_charset, from_charset);
	if (desc == (iconv_t)-1)
		return 1;  // FIXME: Some log?
	for (;;) {
		const size_t iconv_ret = iconv(desc, &src, &src_left, dst, dst_left);
		if (!*dst_left || !src_left || iconv_ret != (size_t)-1)
			break;
	}
	const int close_ret = iconv_close(desc);
	if (close_ret == -1)
		return 1;  // FIXME: Some log?
	return 0;
}


/**
 * Convert body of the page from u->charset to
 *   UCS4.
 */
int conv_charset(mcrawler_url *u)
{
	assert(u->charset && *u->charset);

	char *buf, *buf_start;
	size_t len, resp_len = buf_len(u) - u->headlen;
	const char *from_charset = !strcasecmp(u->charset, "unknown") ? "UTF-8" : u->charset;

	buf_get(u, 4*resp_len, (unsigned char**)&buf, &len); // 4times -> max size after conversion
	buf_start = buf;
	if (convertor(from_charset, "UCS4//IGNORE", (char *)buf_p(u) + u->headlen, resp_len, &buf, &len)) {
		return 1;
	}
	memmove(buf_p(u) + u->headlen, buf_start, buf - buf_start);
	buf_set_len(u, u->headlen + buf - buf_start);

	resp_len = buf_len(u) - u->headlen;
	buf_get(u, 4*resp_len, (unsigned char**)&buf, &len); // 4times -> max size after conversion
	buf_start = buf;
	if (convertor("UCS4", "UTF-8//IGNORE", (char *)buf_p(u) + u->headlen, resp_len, &buf, &len)) {
		return 1;
	}
	memmove(buf_p(u) + u->headlen, buf_start, buf - buf_start);
	buf_set_len(u, u->headlen + buf - buf_start);

	return 0;
}

/**
 * Convert one UNICODE char to UTF-8 char.
 *   Usefull for entities.
 */
char *put_code(char *dst, const unsigned dst_len, const int code)
{
	char src[2] = { code & 0xFF, (code >> 8) & 0XFF, };
	const iconv_t desc = iconv_open("utf-8", "unicode");
	if (desc == (iconv_t)-1)
		return NULL;  // FIXME: Some log?
	char *dst_end = dst, *src_end = src;
	size_t dst_left = dst_len, src_left = sizeof(src);
	const size_t iconv_ret = iconv(desc, &src_end, &src_left, &dst_end, &dst_left);
	const int close_ret = iconv_close(desc);
	if (close_ret == -1)
		return NULL;  // FIXME: Some log?
	if (iconv_ret == (size_t)-1)
		return NULL;  // FIXME: Some log?
	return dst_end;
}
