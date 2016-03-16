#include "minicrawler.h"

enum {
	DEFAULT_TIMEOUT = 5,
	DEFAULT_DELAY = 100,
	MAX_REDIRECTS = 21,
};

struct nv {
    char *name, *value;
};

struct challenge {
	char *scheme, *realm;
	struct nv params[10];
};

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

typedef void (*url_callback)(mcrawler_url*);
typedef ssize_t (*read_callback)(const mcrawler_url *u, unsigned char *buf, const size_t size, char *errbuf);
typedef ssize_t (*write_callback)(const mcrawler_url *u, const unsigned char *buf, const size_t size, char *errbuf);

struct mcrawler_url_func {
	read_callback read;
	write_callback write;
	url_callback parse_url;
	url_callback launch_dns;
	url_callback check_dns;
	url_callback open_socket;
	url_callback connect_socket;
	url_callback handshake;
	url_callback gen_request;
	url_callback send_request;
	url_callback recv_reply;
};
typedef struct mcrawler_url_func mcrawler_url_func;
