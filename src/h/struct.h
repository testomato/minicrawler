#include "minicrawler.h"

enum {
	DEFAULT_TIMEOUT = 5,
	DEFAULT_DELAY = 100,
	MAX_REDIRECTS = 20,
};

struct nv {
    char *name, *value;
};

enum surl_s {
	SURL_S_JUSTBORN,
	SURL_S_PARSEDURL,
	SURL_S_INDNS,
	SURL_S_GOTIP,
	SURL_S_CONNECT,
	SURL_S_HANDSHAKE,
	SURL_S_GENREQUEST,
	SURL_S_SENDREQUEST,
	SURL_S_RECVREPLY,
	SURL_S_DONE,
	SURL_S_ERROR,
	SURL_S_OUTPUTED,
};

static inline const char *state_to_s(const enum surl_s x) {
	switch (x) {
		case SURL_S_JUSTBORN:
			return "SURL_S_JUSTBORN";
		case SURL_S_PARSEDURL:
			return "SURL_S_PARSEDURL";
		case SURL_S_INDNS:
			return "SURL_S_INDNS";
		case SURL_S_GOTIP:
			return "SURL_S_GOTIP";
		case SURL_S_CONNECT:
			return "SURL_S_CONNECT";
		case SURL_S_HANDSHAKE:
			return "SURL_S_HANDSHAKE";
		case SURL_S_GENREQUEST:
			return "SURL_S_GENREQUEST";
		case SURL_S_SENDREQUEST:
			return "SURL_S_SENDREQUEST";
		case SURL_S_RECVREPLY:
			return "SURL_S_RECVREPLY";
		case SURL_S_DONE:
			return "SURL_S_DONE";
		case SURL_S_ERROR:
			return "SURL_S_ERROR";
		case SURL_S_OUTPUTED:
			return "SURL_S_OUTPUTED";
	}
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
