#include <zlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "h/config.h"
#include "h/proto.h"

#define ERR_PREFIX "Gzip decompression error: "

// Decompression-bomb guard: cap the inflated output at GZIP_MAX_RATIO times the
// compressed size, but always allow at least GZIP_MIN_OUTPUT so small legitimate
// responses are never truncated. This is independent of maxpagesize so a few-KB
// gzip response cannot be made to pin a full maxpagesize buffer.
#define GZIP_MAX_RATIO 100
#define GZIP_MIN_OUTPUT (1UL << 20) // 1 MiB

int gunzip_buf(mcrawler_url *u) {
    int             rc;
    size_t          len, resp_len, consumed, produced, max_output;
    z_stream        strm;
    unsigned char  *buf, *body_start, *prev_buf;

    resp_len = buf_len(u) - u->headlen;
    consumed = 0;
    produced = 0;

    // compute the cap in 64-bit and clamp so the multiply cannot overflow size_t
    // (would wrap the cap to a tiny value on 32-bit builds with a large maxpagesize)
    unsigned long long cap = (unsigned long long)resp_len * GZIP_MAX_RATIO;
    if (cap < GZIP_MIN_OUTPUT) cap = GZIP_MIN_OUTPUT;
    if (cap > (unsigned long long)((size_t)-1)) cap = (unsigned long long)((size_t)-1);
    max_output = (size_t)cap;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = resp_len;
    strm.next_in = Z_NULL;

    rc = inflateInit2(&strm, 16 + MAX_WBITS); // we support only gzip
    if (rc != Z_OK) {
        switch (rc) {
            case Z_MEM_ERROR:
                strcpy(u->error_msg, ERR_PREFIX "out of memory in init");
                break;
            case Z_VERSION_ERROR:
                strcpy(u->error_msg, ERR_PREFIX "incompatible zlib version");
                break;
            case Z_STREAM_ERROR: // -2
                // parameters are invalid, such as a null pointer to the
                // structure. msg is set to null if there is no error message.
                sprintf(u->error_msg, ERR_PREFIX "in init (%d)", rc);
        }
        return rc;
    }

    buf_get(u, 9*resp_len, &buf, &len); // 9times -> approx size after ungzip

    while (1) {
        body_start = buf_p(u) + u->headlen;

        strm.next_in = body_start;
        strm.avail_out = len - produced;
        strm.next_out = buf + produced;

        rc = inflate(&strm, Z_FINISH);
        switch (rc) {
            case Z_OK:
            case Z_STREAM_END:
                rc = 0;
                goto done;
                break;
            case Z_NEED_DICT:
                strcpy(u->error_msg,
                       ERR_PREFIX "a preset dictionary is needed for decompression");
                goto done;
                break;
            case Z_ERRNO:
                sprintf(u->error_msg, ERR_PREFIX "%.200m");
                goto done;
                break;
            case Z_DATA_ERROR:
                sprintf(u->error_msg, ERR_PREFIX "currupted response (%.200s)", strm.msg);
                goto done;
                break;
            case Z_MEM_ERROR:
                strcpy(u->error_msg, ERR_PREFIX "out of memory");
                goto done;
                break;
            case Z_STREAM_ERROR: // -2
                // stream structure was inconsistent (for example next_in or
                // next_out was Z_NULL, or the state was inadvertently written over
                // by the application)
            case Z_VERSION_ERROR: // -6
                sprintf(u->error_msg, ERR_PREFIX "%d", rc);
                goto done;
                break;
            case Z_BUF_ERROR:
                if (strm.avail_out > 0) {
                    debugf("[%d] gzip decompress: no progress possible (avail_in=%ld, avail_out=%ld)\n", u->index, strm.avail_in, strm.avail_out);
                    rc = 0;
                    goto done;
                }

                // decompression-bomb guard: refuse to keep expanding past the cap
                if (strm.total_out > max_output) {
                    debugf("[%d] gzip decompress: output exceeded limit of %zd bytes (input %zd)\n", u->index, max_output, resp_len);
                    strcpy(u->error_msg, ERR_PREFIX "decompressed size limit exceeded");
                    rc = Z_DATA_ERROR;
                    goto done;
                }

                // there was not enough room in the output buffer
                consumed = strm.next_in - body_start;
                produced = strm.next_out - buf;

                if (consumed == 0) {
                    debugf("[%d] gzip decompress: run out of output space\n", u->index);
                    rc = 0;
                    goto done;
                }

                memmove(body_start, strm.next_in, strm.avail_in);
                buf_set_len(u, buf_len(u) - consumed);
                prev_buf = buf;
                buf_get(u, 2*len, &buf, &len);
                memmove(buf, prev_buf, produced);

                break;
        }
    }

done:

    (void)inflateEnd(&strm);

    len = strm.total_out;
    if (len > 0) {
        memmove(buf_p(u) + u->headlen, buf, len);
    }
    buf_set_len(u, u->headlen + len);

    debugf("[%d] gzip decompress status: %d (input length: %zd, output length: %zd)\n",
           u->index, rc, resp_len, len);

    return rc;
}
