#include "minicrawler.h"

enum {
	DEFAULT_TIMEOUT = 5,
	DEFAULT_DELAY = 100,
	MAX_REDIRECTS = 20,
};

struct nv {
    char *name, *value;
};

static inline void free_nv(struct nv *nv) {
	if (nv->name) free(nv->name);
	if (nv->value) free(nv->value);
}

enum {
	SURL_STATES_IO = 1<<SURL_S_CONNECT | 1<<SURL_S_HANDSHAKE | 1<<SURL_S_SENDREQUEST | 1<<SURL_S_RECVREPLY,
};

enum surl_rw {
	SURL_RW_WANT_READ,
	SURL_RW_WANT_WRITE,
	SURL_RW_READY_READ,
	SURL_RW_READY_WRITE,
};

enum surl_io {
	SURL_IO_WRITE = -3,
	SURL_IO_READ = -2,
	SURL_IO_ERROR = -1,
	SURL_IO_EOF = 0,
};
