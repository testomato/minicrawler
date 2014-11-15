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
	MCURL_STATES_IO = 1<<MCURL_S_CONNECT | 1<<MCURL_S_HANDSHAKE | 1<<MCURL_S_SENDREQUEST | 1<<MCURL_S_RECVREPLY,
};

enum mcrawler_url_rw {
	MCURL_RW_WANT_READ,
	MCURL_RW_WANT_WRITE,
	MCURL_RW_READY_READ,
	MCURL_RW_READY_WRITE,
};

enum mcrawler_url_io {
	MCURL_IO_WRITE = -3,
	MCURL_IO_READ = -2,
	MCURL_IO_ERROR = -1,
	MCURL_IO_EOF = 0,
};

typedef ssize_t (*read_callback)(const mcrawler_url *u, unsigned char *buf, const size_t size, char *errbuf);
typedef ssize_t (*write_callback)(const mcrawler_url *u, const unsigned char *buf, const size_t size, char *errbuf);

struct mcrawler_url_func {
	read_callback read;
	write_callback write;
	mcrawler_url_callback parse_url;
	mcrawler_url_callback launch_dns;
	mcrawler_url_callback check_dns;
	mcrawler_url_callback open_socket;
	mcrawler_url_callback connect_socket;
	mcrawler_url_callback handshake;
	mcrawler_url_callback gen_request;
	mcrawler_url_callback send_request;
	mcrawler_url_callback recv_reply;
};
typedef struct mcrawler_url_func mcrawler_url_func;
