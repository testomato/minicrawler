#include "h/config.h"
#include "h/proto.h"

static inline void buf_alloc(mcrawler_buf *buf, size_t len) {
	buf->dyn_buf = malloc(len);
	if (buf->dyn_buf) {
		buf->buf_sz = len;
		memcpy(buf->dyn_buf, buf->stat_buf, buf->bufp);
	}
}

unsigned char *buf_p(mcrawler_url *u) {
	if (u->buf.dyn_buf) {
		return u->buf.dyn_buf;
	} else {
		return u->buf.stat_buf;
	}
}

size_t buf_len(mcrawler_url *u) {
	return u->buf.bufp;
}

void buf_set_len(mcrawler_url *u, size_t len) {
	mcrawler_buf *buf = &u->buf;
	if (buf->dyn_buf && len > buf->buf_sz) {
		len = buf->buf_sz;
	} else if (!buf->dyn_buf && len > BUFSIZE) {
		len = BUFSIZE;
	}
	buf->bufp = len;
}

void buf_get(mcrawler_url *u, const size_t min_sz, unsigned char **data, size_t *len) {
	size_t left;
	mcrawler_buf *buf = &u->buf;
	if (!buf->dyn_buf) {
		left = BUFSIZE - buf->bufp;
		if (left < min_sz) {
			buf_alloc(buf, u->maxpagesize);
			debugf("[%i] Allocating dynamic buffer\n", u->index);
		} else {
			*data = buf->stat_buf + buf->bufp;
			*len = left;
			return;
		}
	}
	left = (buf->dyn_buf ? buf->buf_sz : BUFSIZE) - buf->bufp;
	*data = (buf->dyn_buf ? buf->dyn_buf : buf->stat_buf) + buf->bufp;
	*len = left;
}

size_t buf_write(mcrawler_url *u, const unsigned char *data, size_t len) {
	size_t left, copied;
	unsigned char *addr;
	mcrawler_buf *buf = &u->buf;

	addr = buf->stat_buf + buf->bufp;
	copied = len;

	if (!buf->dyn_buf && len > BUFSIZE - buf->bufp) {
		copied = BUFSIZE - buf->bufp;
		buf_alloc(buf, u->maxpagesize);
		debugf("[%i] Allocating dynamic buffer\n", u->index);
	}
	if (buf->dyn_buf) {
		left = buf->buf_sz - buf->bufp;
		addr = buf->dyn_buf + buf->bufp;
		if (len <= left) {
			copied = len;
		} else {
			copied = left;
		}
	}
	debugf("[%i] Copied %zd bytes to buffer at %zd\n", u->index, copied, buf->bufp);
	memcpy(addr, data, copied);
	buf->bufp += copied;
	return copied;
}

void buf_inc(mcrawler_url *u, size_t len) {
	u->buf.bufp += len;
}

void buf_del(mcrawler_url *u, size_t dellen) {
	if (dellen > u->buf.bufp) {
		u->buf.bufp = 0;
	} else {
		u->buf.bufp -= dellen;
	}
}

void buf_free(mcrawler_url *u) {
	mcrawler_buf *buf = &u->buf;
	if (buf->dyn_buf) {
		free(buf->dyn_buf);
		buf->dyn_buf = NULL;
	}
	buf->bufp = 0;
}
