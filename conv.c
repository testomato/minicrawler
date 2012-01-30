#include <iconv.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

static int convertor(struct surl *u, char *dst, const size_t dst_size)
{
	const iconv_t desc = iconv_open("utf-8", u->charset);
	if (desc == (iconv_t)-1)
		return 1;  // FIXME: Some log?
	char *dst_end = dst, *src_end = &u->buf[u->headlen];
	size_t dst_left = dst_size, src_left = u->bufp - u->headlen;
	for (;;) {
		const size_t iconv_ret = iconv(desc, &src_end, &src_left, &dst_end, &dst_left);
		if (!dst_left || !src_left || iconv_ret != (size_t)-1)
			break;
		++src_end;
		--src_left;
	}
	const int close_ret = iconv_close(desc);
	if (close_ret == -1)
		return 1;  // FIXME: Some log?
	memcpy(&u->buf[u->headlen], dst, dst_end - dst);
	u->bufp = dst_end - dst + u->headlen;
	return 0;
}

void conv_charset(struct surl *u)
{
	if (!*u->charset || !strcasecmp(u->charset, "utf8") || !strcasecmp(u->charset, "utf-8"))
		return;
	const size_t dst_size = BUFSIZE - u->headlen;
	char *dst = malloc(dst_size);
	if (!dst || convertor(u, dst, dst_size)) {
		u->conv_errno = errno;
		u->bufp = u->headlen;  // discard whole input in case of error
	}
	free(dst);
}

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
