#include <stdlib.h>
#include <string.h>

struct mcrawler_settings {
	int debug;
	int timeout;
	int impatient;
	int delay;
};
typedef struct mcrawler_settings mcrawler_settings;

struct mcrawler_cookie {
    char *name, *value, *domain, *path;
	int secure, host_only, expire;
};
typedef struct mcrawler_cookie mcrawler_cookie;

struct mcrawler_timing {
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
typedef struct mcrawler_timing mcrawler_timing;

struct mcrawler_redirect_info {
	char *url;
	int status;
	mcrawler_timing timing;
	struct mcrawler_redirect_info *next;
};
typedef struct mcrawler_redirect_info mcrawler_redirect_info;

struct mcrawler_addr {
	int type;
	int length;
	unsigned char ip[16];
	struct mcrawler_addr *next;
};
typedef struct mcrawler_addr mcrawler_addr;

static inline void free_addr(mcrawler_addr *addr) {
	while (addr) {
		mcrawler_addr *next = addr->next;
		free(addr);
		addr = next;
	}
}

static inline void free_cookie(mcrawler_cookie *cookie) {
	if (cookie->name) free(cookie->name);
	if (cookie->value) free(cookie->value);
	if (cookie->domain) free(cookie->domain);
	if (cookie->path) free(cookie->path);
}

static inline void cp_cookie(mcrawler_cookie *dst, const mcrawler_cookie *src) {
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

enum mcrawler_url_s {
	MCURL_S_JUSTBORN,
	MCURL_S_PARSEDURL,
	MCURL_S_INDNS,
	MCURL_S_GOTIP,
	MCURL_S_CONNECT,
	MCURL_S_HANDSHAKE,
	MCURL_S_GENREQUEST,
	MCURL_S_SENDREQUEST,
	MCURL_S_RECVREPLY,
	MCURL_S_DOWNLOADED,
	MCURL_S_ERROR,
	MCURL_S_DONE,
};

static inline const char *mcrawler_state_to_s(const enum mcrawler_url_s x) {
	switch (x) {
		case MCURL_S_JUSTBORN:
			return "MCURL_S_JUSTBORN";
		case MCURL_S_PARSEDURL:
			return "MCURL_S_PARSEDURL";
		case MCURL_S_INDNS:
			return "MCURL_S_INDNS";
		case MCURL_S_GOTIP:
			return "MCURL_S_GOTIP";
		case MCURL_S_CONNECT:
			return "MCURL_S_CONNECT";
		case MCURL_S_HANDSHAKE:
			return "MCURL_S_HANDSHAKE";
		case MCURL_S_GENREQUEST:
			return "MCURL_S_GENREQUEST";
		case MCURL_S_SENDREQUEST:
			return "MCURL_S_SENDREQUEST";
		case MCURL_S_RECVREPLY:
			return "MCURL_S_RECVREPLY";
		case MCURL_S_DOWNLOADED:
			return "MCURL_S_DOWNLOADED";
		case MCURL_S_ERROR:
			return "MCURL_S_ERROR";
		case MCURL_S_DONE:
			return "MCURL_S_DONE";
	}
	return "";
}

enum mcrawler_url_options {
	MCURL_OPT_NONSSL,
	MCURL_OPT_CONVERT_TO_TEXT,
	MCURL_OPT_CONVERT_TO_UTF8,
	MCURL_OPT_GZIP,
	MCURL_OPT_IPV6,
};

enum {
	BUFSIZE = 700*1024,
	MAXURLSIZE = 4095,
	COOKIESTORAGESIZE = 25,
};

struct mcrawler_url {

	int index;
	char rawurl[MAXURLSIZE + 1];

	void *uri;
	char *proto;
	char *host;
	int port;
	char *path;

	char method[16];
	unsigned char *post;
	int postlen;

	// hlavicky
	char location[MAXURLSIZE + 1];	// presne to co je v hlavicce Location - pro ucely redirect
	char *redirectedto;	// co nakonec hlasime ve vystupu v hlavicce
	int chunked;		// 1  pokud transfer-encoding: chunked
	int nextchunkedpos;
	mcrawler_cookie cookies[COOKIESTORAGESIZE];
	int cookiecnt;
	char customagent[256];
	char customheader[4096];
	char charset[32];
	int gzipped;

	// request
	unsigned char *request;
	size_t request_len;
	size_t request_it;

	mcrawler_redirect_info *redirect_info;
	int redirect_limit;

	int state;
	int rw;
	mcrawler_timing timing;
	int downstart;		// time downloading start

	// ares
	void *aresch;

	// network
	int sockfd;
	mcrawler_addr *addr;
	mcrawler_addr *prev_addr;
	int addrtype;

	// obsah
	unsigned char buf[BUFSIZE];
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

	long options;

	void *f;
};
typedef struct mcrawler_url mcrawler_url;

typedef void (*mcrawler_url_callback)(mcrawler_url*, void *);

void mcrawler_init_settings(mcrawler_settings *settings);

void mcrawler_init_url(mcrawler_url *u, const char *url);

void mcrawler_go(mcrawler_url **url, const mcrawler_settings *settings, mcrawler_url_callback callback, void *callback_arg);
