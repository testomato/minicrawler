#include <stdlib.h>
#include <string.h>

struct ssettings {
	int debug;
	int timeout;
	int impatient;
	int partial;
	int delay;
};

struct cookie {
    char *name, *value, *domain, *path;
	int secure, host_only, expire;
};

struct timing {
	int dnsstart;
	int dnsend;
	int connectionstart;
	int handshakestart;
	int sslstart;
	int sslend;
	int requeststart;
	int requestend;
	int firstbyte;
	int lastread;
	int done;
};

struct redirect_info {
	char *url;
	int status;
	struct timing timing;
	struct redirect_info *next;
};

struct addr {
	int type;
	int length;
	unsigned char ip[16];
	struct addr *next;
};

static inline void free_addr(struct addr *addr) {
	while (addr) {
		struct addr *next = addr->next;
		free(addr);
		addr = next;
	}
}

static inline void free_cookie(struct cookie *cookie) {
	if (cookie->name) free(cookie->name);
	if (cookie->value) free(cookie->value);
	if (cookie->domain) free(cookie->domain);
	if (cookie->path) free(cookie->path);
}

static inline void cp_cookie(struct cookie *dst, const struct cookie *src) {
	dst->name = malloc(strlen(src->name) + 1);
	dst->value = malloc(strlen(src->value) + 1);
	dst->domain = malloc(strlen(src->domain) + 1);
	dst->path = malloc(strlen(src->path) + 1);

	strcpy(dst->name, src->name);
	strcpy(dst->value, src->value);
	strcpy(dst->domain, src->domain);
	strcpy(dst->path, src->path);
	dst->host_only = src->host_only;
	dst->secure = src->secure;
	dst->expire = src->expire;
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
	SURL_S_DOWNLOADED,
	SURL_S_ERROR,
	SURL_S_DONE,
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
		case SURL_S_DOWNLOADED:
			return "SURL_S_DOWNLOADED";
		case SURL_S_ERROR:
			return "SURL_S_ERROR";
		case SURL_S_DONE:
			return "SURL_S_DONE";
	}
}

struct surl;

typedef void (*surl_callback)(struct surl*);

enum surl_options {
	SURL_OPT_NONSSL,
	SURL_OPT_CONVERT_TO_TEXT,
	SURL_OPT_CONVERT_TO_UTF8,
	SURL_OPT_GZIP,
	SURL_OPT_IPV6,
};

enum {
	BUFSIZE = 700*1024,
	MAXURLSIZE = 4095,
	COOKIESTORAGESIZE = 25,
};

struct surl {

	int index;
	char rawurl[MAXURLSIZE + 1];

	void *uri;
	char *proto;
	char *host;
	int port;
	char *path;

	char method[16];
	char *post;

	// hlavicky
	char location[MAXURLSIZE + 1];	// presne to co je v hlavicce Location - pro ucely redirect
	char *redirectedto;	// co nakonec hlasime ve vystupu v hlavicce
	int chunked;		// 1  pokud transfer-encoding: chunked
	int nextchunkedpos;
	struct cookie cookies[COOKIESTORAGESIZE];
	int cookiecnt;
	char customagent[256];
	char customheader[4096];
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
	struct timing timing;
	int downstart;		// time downloading start

	// ares
	void *aresch;

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
	void *ssl;
	long ssl_options;

	struct surl *next; // linked list

	long options;

	void *f;
};

void mcrawler_init_settings(struct ssettings *settings);

void mcrawler_init_url(struct surl *u, const char *url);

void mcrawler_go(struct surl *url, const struct ssettings *settings, surl_callback callback);
