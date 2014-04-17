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
			ret = Z_DATA_ERROR;
			break;
		case Z_BUF_ERROR: // tahle chyba nam nevadi, bud mame maly output buffer, nebo nevim
			ret = Z_STREAM_END;
			break;
	}

	(void)inflateEnd(&strm);
	*outlen = strm.total_out;
	return ret == Z_STREAM_END ? Z_OK : ret;
}
