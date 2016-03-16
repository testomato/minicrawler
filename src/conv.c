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
static int convertor(mcrawler_url *u, char *dst, const size_t dst_size)
{
	const char *from_charset = !strcasecmp(u->charset, "unknown") ? "utf-8" : u->charset;

        char unibuf[(u->bufp - u->headlen)*4]; // FIXME: Really *4 ?
        const iconv_t uni_desc = iconv_open("UCS4//IGNORE", from_charset);
        if (uni_desc == (iconv_t)-1)
            return 1;  // FIXME: Some log?
        char *uni_dst = unibuf;
        size_t uni_dst_left = sizeof(unibuf);
	char *src_end = (char *)&u->buf[u->headlen];
	size_t src_left = u->bufp - u->headlen;
	for (;;) {
		const size_t iconv_ret = iconv(uni_desc, &src_end, &src_left, &uni_dst, &uni_dst_left);
		if (!uni_dst_left || !src_left || iconv_ret != (size_t)-1)
			break;
		++src_end;
		--src_left;
	}
	const int uni_close_ret = iconv_close(uni_desc);
	if (uni_close_ret == -1)
		return 1;  // FIXME: Some log?
	const iconv_t desc = iconv_open("utf-8//IGNORE", "UCS4");
	if (desc == (iconv_t)-1)
		return 1;  // FIXME: Some log?
	char *dst_end = dst, *uni_src = unibuf;
	size_t dst_left = dst_size, uni_src_left = sizeof(unibuf) - uni_dst_left;
	for (;;) {
		const size_t iconv_ret = iconv(desc, &uni_src, &uni_src_left, &dst_end, &dst_left);
		if (!dst_left || !uni_src_left || iconv_ret != (size_t)-1)
			break;
//		uni_src+=4;
//		uni_src_left-=4;
		++uni_src;
		--uni_src_left;
	}
	const int close_ret = iconv_close(desc);
	if (close_ret == -1)
		return 1;  // FIXME: Some log?
	memcpy(&u->buf[u->headlen], dst, dst_end - dst);
	u->bufp = dst_end - dst + u->headlen;
	return 0;
}


/**
 * Convert body of the page from u->charset to
 *   UCS4.
 */
int conv_charset(mcrawler_url *u)
{
	assert(u->charset && *u->charset);
	const size_t dst_size = BUFSIZE - u->headlen;
	char *dst = malloc(dst_size);
	if (!dst || convertor(u, dst, dst_size)) {
		free(dst);
		return 1;
	}
	free(dst);
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

/**
 * Percent-encode chars, that are not allowed in url
 */
int urlencode(char *src)
{
	char buf[MAXURLSIZE + 1];
	unsigned char c, *str;
	int bp = 0, escape_sq_br = 0, slash_cnt = 0, question_mark_cnt = 0, hash_cnt = 0;

	str = (unsigned char*)src;
	while ((c = *str++) != '\0') {
		if (c == '/') {
			slash_cnt++;
		}
		if (c == '?') {
			question_mark_cnt++;
		}
		if (c == '#') {
			hash_cnt++;
		}
		if (slash_cnt == 3 || question_mark_cnt == 1 || hash_cnt == 1) {
			// hranaté závorky nemůžeme escapovat v authority
			escape_sq_br = 1;
		}
		if (c <= 0x20 ||
				c == 0x22 ||
				(hash_cnt > 1 && c == 0x23) ||
				c == 0x3C ||
				c == 0x3E ||
				c == 0x5C ||
				c == 0x5E ||
				(escape_sq_br && (c == 0x5B || c == 0x5D)) ||
				c == 0x60 ||
				(c >= 0x7B && c <= 0x7D) ||
				c >= 0x7F
		   ) {
			if (bp + 3 > MAXURLSIZE) {
				return 0;
			}
			sprintf(buf + bp, "%%%2.2X", c);
			bp += 3;
		} else {
			if (bp + 1 > MAXURLSIZE) {
				return 0;
			}
			buf[bp++] = c;
		}
	}
	if (bp > MAXURLSIZE) {
		return 0;
	}
	buf[bp] = 0;
	strcpy(src, buf);
	return 1;
}
