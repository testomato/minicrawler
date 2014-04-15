#include <zlib.h>

int gunzip(char *out, int *outlen, char *in, int inlen) {
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
		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;     /* and fall through */
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			(void)inflateEnd(&strm);
			return ret;
	}

	(void)inflateEnd(&strm);
	*outlen = strm.total_out;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}
