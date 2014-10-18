#include <openssl/ssl.h>
#include <uriparser/Uri.h>

enum {
	BUFSIZE = 700*1024,
	MAXURLSIZE = 4095,
	COOKIESTORAGESIZE = 25,
};

enum {
	DEFAULT_TIMEOUT = 5,
	DEFAULT_DELAY = 100,
	MAX_REDIRECTS = 20,
};

struct nv {
    char *name, *value;
};

struct cookie {
    char *name, *value, *domain, *path;
	int secure, host_only, expire;
};

struct redirect_info {
	char *url;
	int status;
	struct redirect_info *next;
};

struct addr {
	int type;
	int length;
	unsigned char ip[16];
	struct addr *next;
};

static inline void free_addr(struct addr *addr) {
	while (addr != NULL) {
		struct addr *next = addr->next;
		free(addr);
		addr = next;
	}
}


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
	SURL_S_INTERNAL_ERROR,
	SURL_S_ERROR,
	SURL_S_DONE,
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
		case SURL_S_INTERNAL_ERROR:
			return "SURL_S_INTERNAL_ERROR";
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

struct surl;

typedef void (*surl_callback)(struct surl*);
typedef ssize_t (*read_callback)(const struct surl *u, char *buf, const size_t size);
typedef ssize_t (*write_callback)(const struct surl *u, const char *buf, const size_t size);

struct surl_func {
	read_callback read;
	write_callback write;
	surl_callback parse_url;
	surl_callback launch_dns;
	surl_callback check_dns;
	surl_callback open_socket;
	surl_callback connect_socket;
	surl_callback handshake;
	surl_callback gen_request;
	surl_callback send_request;
	surl_callback recv_reply;
};

struct surl {
	struct surl_func f;

    // ...
	int index;
	char rawurl[MAXURLSIZE + 1];
 
	UriUriA *uri;
	char *proto;
	char *host;
	int port;
	char *path;

	int ispost;
	char *post;

	// hlavicky	
	char location[MAXURLSIZE + 1];	// presne to co je v hlavicce Location - pro ucely redirect
	char *redirectedto;	// co nakonec hlasime ve vystupu v hlavicce
	int chunked;		// 1  pokud transfer-encoding: chunked
	int nextchunkedpos;
	struct cookie cookies[COOKIESTORAGESIZE];
	int cookiecnt;
	char customparam[256];		// parametr do custom headeru
	char charset[32];
	int gzipped;

	// request
	char *request;
	size_t request_len;
	size_t request_it;

	struct redirect_info *redirect_info;
	int redirect_limit;
 
	int state;
	int rw;
	int lastread;		// cas posledniho uspesneho cteni
	int downstart;		// time downloading start
	int handshaketime;

	// ares
	struct ares_channeldata *aresch;
	
	// network
	int sockfd;
	struct addr *addr;
	struct addr *prev_addr;
	int addrtype;
	
	// obsah
	char buf[BUFSIZE];
	int bufp;
	int headlen;
	int contentlen;
	int status;		// http navratovy kod
	char error_msg[256];

	// errno
 	int conv_errno;		// set in case of wrong conversion

	// SSL support
	SSL *ssl;
	long ssl_options;

	struct surl *next; // linked list
};

struct ssettings {
	int debug;
	int non_ssl;
	int timeout;
	int writehead;
	int impatient;
	int partial;
	int convert;		// 1 pokud se má konvertovat do textu
	int convert_to_utf;     // 1 pokud se ma konvertovat do utf8
	int delay;		// zpozdeni pri stahovani ze stejne ip, default je 100ms
	int gzip;
	int ipv6;
	char customagent[256];
	char customheader[4096];
};
