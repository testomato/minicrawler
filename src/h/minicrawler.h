/* Define WIN32 when build target is Win32 API (borrowed from libcurl) */
#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32)
# define WIN32
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef MCRAWLER_STATICLIB
# define MCRAWLER_EXTERN
#elif defined(WIN32)
# ifdef BUILDING_MCRAWLER
#  define MCRAWLER_EXTERN __declspec(dllexport)
# else
#  define MCRAWLER_EXTERN __declspec(dllimport)
# endif
#else
# if defined(BUILDING_MCRAWLER) && __GNUC__ >= 4
#  define MCRAWLER_EXTERN __attribute__((visibility("default")))
# else
#  define MCRAWLER_EXTERN
# endif
#endif

#define DEFAULTAGENT "minicrawler/%s"

struct mcrawler_settings {
	int debug;
	int timeout;
	int impatient;
	int delay;
};

struct mcrawler_cookie {
    char *name, *value, *domain, *path;
	int secure, host_only;
	time_t expires;
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

enum mcrawler_url_options {
	MCURL_OPT_NONSSL,
	MCURL_OPT_CONVERT_TO_TEXT,
	MCURL_OPT_CONVERT_TO_UTF8,
	MCURL_OPT_GZIP,
	MCURL_OPT_IPV6,
	MCURL_OPT_INSECURE,
	MCURL_OPT_NOT_FOLLOW_REDIRECTS,
	MCURL_OPT_DISABLE_HTTP2,
};

enum {
	BUFSIZE = 700*1024UL,
	MAXURLSIZE = 8191,
	COOKIESTORAGESIZE = 25,
};
// 700 KiB is enough for 99% requests, see https://bigquery.cloud.google.com/results/www-testomato-com:bquijob_78729d01_157d7e26b6c

struct mcrawler_url {

	int index;
	char rawurl[MAXURLSIZE + 1];

	void *uri;
	char proto[8];
	char host[256 + 6];
	char hostname[256];
	int port;
	int prev_port;
	char *path;

	char method[16];
	unsigned char *post;
	int postlen;

	// hlavicky
	char location[MAXURLSIZE + 1];	// presne to co je v hlavicce Location - pro ucely redirect
	char *redirectedto;	// co nakonec hlasime ve vystupu v hlavicce
	int chunked;		// 1  pokud transfer-encoding: chunked
	size_t nextchunkedpos;
	mcrawler_cookie cookies[COOKIESTORAGESIZE];
	int cookiecnt;
	char customagent[256];
	char customheader[4096];
	char *contenttype;
	char charset[32];
	int gzipped;
	int close_connection;

	// http auth
	char username[32];
	char password[32];
	char *wwwauthenticate;
	char *authorization;
	int auth_attempt;

	// request
	unsigned char *request;
	size_t request_len;
	size_t request_it;

	mcrawler_redirect_info *redirect_info;
	int redirect_limit;

	int state;
	int last_state;
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
	size_t bufp;
	size_t headlen;
	size_t contentlen;
	int has_contentlen;
	int status;		// http navratovy kod
	char error_msg[256];

	// SSL support
	void *ssl;
	long ssl_options;
	unsigned long ssl_error;

	// HTTP2
	int http2;
	void *http2_session;

	long options;

	void *f;

	void *userdata;
};

typedef struct mcrawler_settings mcrawler_settings;
typedef struct mcrawler_url mcrawler_url;
typedef void (*mcrawler_url_callback)(mcrawler_url*, void *);

MCRAWLER_EXTERN void  mcrawler_init_settings(mcrawler_settings *settings);
MCRAWLER_EXTERN void  mcrawler_init_url(mcrawler_url *u, const char *url);

MCRAWLER_EXTERN void  mcrawler_go(mcrawler_url **url, const mcrawler_settings *settings, mcrawler_url_callback callback, void *callback_arg);
MCRAWLER_EXTERN void  mcrawler_reset_url(mcrawler_url *u);

MCRAWLER_EXTERN char *mcrawler_version();

MCRAWLER_EXTERN void *mcrawler_url_serialize(mcrawler_url *url, void **buffer, int *buffer_size);
MCRAWLER_EXTERN int   mcrawler_url_unserialize(mcrawler_url *url, void *buffer, int buffer_size);
MCRAWLER_EXTERN void *mcrawler_urls_serialize(mcrawler_url **urls, mcrawler_settings *settings, void **buffer, int *buffer_size);
MCRAWLER_EXTERN int   mcrawler_urls_unserialize(mcrawler_url ***urls, mcrawler_settings **settings, void *buffer, int buffer_size, void *(*alloc_func)(size_t size));

MCRAWLER_EXTERN void  mcrawler_free_url(mcrawler_url *);
MCRAWLER_EXTERN void  mcrawler_free_cookie(mcrawler_cookie *);

MCRAWLER_EXTERN const char *mcrawler_state_to_s(const enum mcrawler_url_s x);
