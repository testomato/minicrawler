#include <zlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int gunzip(unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, char **errmsg) {
	int ret;
	z_stream strm;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	ret = inflateInit2(&strm, 16 + MAX_WBITS);
	if (ret != Z_OK) {
		return ret;
	}

	strm.avail_in = inlen;
	strm.next_in = in;
	strm.avail_out = *outlen;
	strm.next_out = out;

	ret = inflate(&strm, Z_FINISH);
	switch (ret) {
		case Z_STREAM_END:
			ret = 0;
			break;
		case Z_NEED_DICT:
			*errmsg = strdup("a preset dictionary is needed for decompression");
			ret = Z_DATA_ERROR;
			break;
		case Z_ERRNO:
			*errmsg = strdup(strerror(errno));
			break;
		case Z_STREAM_ERROR: // -2
			// stream structure was inconsistent (for example next_in or
			// next_out was Z_NULL, or the state was inadvertently written over
			// by the application)
			break;
		case Z_DATA_ERROR:
			*errmsg = malloc(sizeof("currupted response ()")+strlen(strm.msg));
			sprintf(*errmsg, "currupted response (%s)", strm.msg);
			break;
		case Z_MEM_ERROR:
			*errmsg = strdup("out of memory");
			break;
		case Z_BUF_ERROR:
			// there was not enough room in the output buffer
			ret = 0;
			break;
		case Z_VERSION_ERROR: // -6
			break;
	}

	(void)inflateEnd(&strm);
	*outlen = strm.total_out;
	return ret;
}
