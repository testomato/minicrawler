#include <iconv.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

static void convertor(struct surl *u, char *dst, const size_t dst_size)
{
	const iconv_t desc = iconv_open("utf-8", u->charset);
	if (desc == (iconv_t)-1)
		return;  // FIXME: Some log?
	char *dst_end = dst, *src_end = &u->buf[u->headlen];
	size_t dst_left = dst_size, src_left = u->bufp - u->headlen;
	const size_t iconv_ret = iconv(desc, &src_end, &src_left, &dst_end, &dst_left);
	if (iconv_ret == (size_t)-1)
		return;  // FIXME: Some log?
	const int close_ret = iconv_close(desc);
	if (close_ret == -1)
		return;  // FIXME: Some log?
	memcpy(&u->buf[u->headlen], dst, dst_end - dst);
	u->bufp = dst_end - dst + u->headlen;
}

void conv_charset(struct surl *u)
{
	if (!*u->charset || !strcasecmp(u->charset, "utf8") || !strcasecmp(u->charset, "utf-8"))
		return;

	const size_t dst_size = BUFSIZE - u->headlen;
	char *dst = malloc(dst_size);
	if (!dst)
		return;  // FIXME: Some log?
	convertor(u, dst, dst_size);
	free(dst);
}
