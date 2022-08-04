#include "h/config.h"

#define _GNU_SOURCE // memmem(.) needs this :-(
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h> // select(.)
#else
# include <sys/time.h>
# include <sys/types.h>
#endif
#ifdef HAVE_LIMITS_H
# include <limits.h>
#else
# define LONG_MAX 2147483647
# define LONG_MIN (-LONG_MAX - 1)
#endif
#include <ares.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h> // socket(.)
#endif
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <netinet/tcp.h>
#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>
# ifndef SSL_OP_NO_TLSv1_2
#  error "please install OpenSSL 1.0.1"
# endif
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
#endif
#ifdef HAVE_LIBNGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#include "url/minicrawler-url.h"
#include "h/string.h"
#include "h/proto.h"

#ifdef HAVE_DEBUG
int debug = 0;
#endif

/**
Atomic setter for integer. Library c-ares uses threads and it can cause
non-defined state when we touch variables in non-atomic way inside it.
*/
static void set_atomic_int(int *ptr, const int val) {
	*(volatile int*)ptr = val;
	asm volatile ("" : : : "memory");  // memory barrier
}

/**
Atomic getter for integer. There is some pain with library c-ares, see doc for set_atomic_int(.) .
*/
static int get_atomic_int(const int* const ptr) {
	return *(volatile const int* const)ptr;
}

/** This function returns true if the state requires io and no io is available to it at the same time.
Otherwise it returns false.
HINT: This function says: you should call select(.) over the filedescriptor.
*/
static int want_io(const int state, const int rw) {
	return ((1 << state) & MCURL_STATES_IO) && (rw & (1 << MCURL_RW_WANT_READ | 1 << MCURL_RW_WANT_WRITE));
}

/** Assert like function: Check that actual state either doesn't requiere io or io is available for its socket.
Otherwise die in cruel pain!
HINT: This function simply checks whether we check availability of fd for reading/writing before using it for r/w.
*/
static void check_io(const int state, const int rw) {
	if ( ((1 << state) & MCURL_STATES_IO) && !(rw & (1 << MCURL_RW_READY_READ | 1 << MCURL_RW_READY_WRITE)) ) {
		abort();
	}
}

static inline void copy_addr_prev_addr(mcrawler_url *u) {
	free_addr(u->prev_addr);
	u->prev_addr = (mcrawler_addr*)malloc(sizeof(mcrawler_addr));
	memcpy(u->prev_addr, u->addr, sizeof(mcrawler_addr));
	u->prev_addr->next = NULL;
}

#ifdef HAVE_LIBSSL
/**
 * Sets lower TSL/SSL protocol
 */
static int lower_ssl_protocol(mcrawler_url *u) {
#if (HAVE_DECL_SSL_GET_MAX_PROTO_VERSION)
	int proto_ver = SSL_get_max_proto_version(u->ssl);

	if (proto_ver == SSL3_VERSION) {
		return -1;
	}

	if (proto_ver == 0) {
		proto_ver = TLS_MAX_VERSION;
	}

	debugf("[%d] Setting maximum supported protocol to version %x\n", u->index, proto_ver-1);
	u->ssl_options.max_proto = proto_ver - 1;
#else
	const long opts = SSL_get_options(u->ssl);

	if (opts & SSL_OP_NO_TLSv1) {
		return -1;
	}

	// SSL_CTX_set_min_proto_version since OpenSSL 1.1.0
	if (opts & SSL_OP_NO_TLSv1_1) {
		u->ssl_options.opts |= SSL_OP_NO_TLSv1;
		debugf("[%d] Switch to SSLv3\n", u->index);
	} else if (opts & SSL_OP_NO_TLSv1_2) {
		u->ssl_options.opts |= SSL_OP_NO_TLSv1_1;
		debugf("[%d] Switch to TLSv1.0\n", u->index);
	} else {
		u->ssl_options.opts |= SSL_OP_NO_TLSv1_2;
		debugf("[%d] Switch to TLSv1.1\n", u->index);
	}
#endif
	return 0;
}

/**
 * Closes connection and frees all related structures
 */
static void close_conn(mcrawler_url *u) {
	debugf("[%d] Closing connection (socket %d)\n", u->index, u->sockfd);

#ifdef HAVE_LIBNGHTTP2
	if (u->http2_session) {
		int rv;
		http2_session_data *session_data = (http2_session_data *)u->http2_session;
		rv = nghttp2_session_terminate_session(session_data->session, NGHTTP2_NO_ERROR);
		if (rv == 0) {
			http2_session_send(u);
		}
		nghttp2_session_del(session_data->session);
		free(u->http2_session);
		u->http2_session = NULL;
	}
#endif

#ifdef HAVE_LIBSSL
	if (u->ssl) {
		SSL_shutdown(u->ssl);
		SSL_free(u->ssl);
		u->ssl = NULL;
	}
#endif

	if (u->aresch) {
		ares_destroy(u->aresch);
		u->aresch = NULL;
	}

	if (u->sockfd) {
		close(u->sockfd);
		u->sockfd = 0;
	}
}

#ifdef HAVE_LIBNGHTTP2
static void genrequest_http2(mcrawler_url *u);
static void readreply_http2(mcrawler_url *u);
#endif
static void genrequest(mcrawler_url *u);
static void readreply(mcrawler_url *u);


/** Impement handshake over SSL non-blocking socket.
We may switch between need read/need write for several times.
SSL is blackbox this time for us.
*/
static void sec_handshake(mcrawler_url *u) {
	if (!u->timing.sslstart) u->timing.sslstart = get_time_int();

	if (!u->ssl) {
		if (create_ssl(u) < 0) {
			debugf("[%d] cannot create ssl session :-(\n", u->index);
			sprintf(u->error_msg, "Cannot create SSL session");
			unsigned long e;
			while ((e = ERR_get_error())) {
				debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
			}
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		}
	}

	const int t = SSL_connect(u->ssl);
	if (t == 1) {
		debugf("[%d] Connection will use %s\n", u->index, SSL_get_version(u->ssl));
#ifdef HAVE_LIBNGHTTP2
		// zjistíme aplikační protokol
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
# ifdef HAVE_SSL_CTX_SET_ALPN_PROTOS
		SSL_get0_alpn_selected(u->ssl, &alpn, &alpnlen);
		debugf("[%d] ALPN negotiated protocol: %.*s\n", u->index, alpnlen, alpn);
# else
		SSL_get0_next_proto_negotiated(u->ssl, &alpn, &alpnlen);
		debugf("[%d] NPN negotiated protocol: %.*s\n", u->index, alpnlen, alpn);
# endif
		if (alpn
				&& alpnlen == sizeof(NGHTTP2_PROTO_VERSION_ID) - 1
				&& !strncmp((const char *)alpn, NGHTTP2_PROTO_VERSION_ID, alpnlen)
		) {
			((mcrawler_url_func *)u->f)->gen_request = genrequest_http2;
			((mcrawler_url_func *)u->f)->recv_reply = readreply_http2;
		} else {
			((mcrawler_url_func *)u->f)->gen_request = genrequest;
			((mcrawler_url_func *)u->f)->recv_reply = readreply;
		}
#endif
		u->timing.sslend = get_time_int();
        set_atomic_int(&u->state, MCURL_S_GENREQUEST);
        return;
    }

    const int err = SSL_get_error(u->ssl, t);
    if (err == SSL_ERROR_WANT_READ) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
		return;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		return;
    }
	switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			debugf("[%d] Connection closed (in handshake)", u->index);
			sprintf(u->error_msg, "SSL connection closed during handshake");
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			debugf("[%d] SSL_ERROR_WANT_CONNECT\n", u->index);
			sprintf(u->error_msg, "Unexpected SSL error during handshake");
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		case SSL_ERROR_WANT_X509_LOOKUP:
			debugf("[%d] SSL_ERROR_WANT_X509_LOOKUP\n", u->index);
			sprintf(u->error_msg, "Unexpected SSL error during handshake");
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		case SSL_ERROR_SYSCALL:
			debugf("[%d] SSL_ERROR_SYSCALL (%d)\n", u->index, t);
			if (t < 0) { // t == 0: unexpected EOF
				sprintf(u->error_msg, "Unexpected SSL error during handshake (%.200m)");
				set_atomic_int(&u->state, MCURL_S_ERROR);
				return;
			}
	}

	// else err = SSL_ERROR_SSL = protocol error
	debugf("[%d] SSL protocol error (in handshake): \n", u->index);
	unsigned long e, last_e = 0;
	while ((e = ERR_get_error())) {
		debugf("[%d]\t\t%d\t%s\n", u->index, ERR_GET_REASON(e), ERR_error_string(e, NULL));
		last_e = e;
	}

	if (ERR_GET_REASON(last_e) == SSL_R_CERTIFICATE_VERIFY_FAILED) {
		long vr = SSL_get_verify_result(u->ssl);
		sprintf(u->error_msg, "SSL certificate verification failed (%.200s)", X509_verify_cert_error_string(vr));
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	} else if (lower_ssl_protocol(u) < 0) {
		// nižší protokol už nejde
		sprintf(u->error_msg, "SSL protocol error during handshake");
		if (last_e) {
			// nepodporovaný protocol, necháme si hlášku z předchozího handshaku, pokud ji máme
			if (ERR_GET_REASON(last_e) == SSL_R_UNSUPPORTED_PROTOCOL && u->ssl_error) {
				sprintf(u->error_msg + strlen(u->error_msg), " (%.200s)", ERR_reason_error_string(u->ssl_error));
			} else {
				sprintf(u->error_msg + strlen(u->error_msg), " (%.200s)", ERR_reason_error_string(last_e));
			}
		}
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	} else {
		// zkusíme ještě jednou
		u->ssl_error = last_e;
		close_conn(u);
		set_atomic_int(&u->state, MCURL_S_GOTIP);
		return;
	}
}

/** Read some data from SSL socket.
NOTE: We must read as much as possible, because select(.) may
not notify us that other data are available.
From select(.)'s point of view they are read but in fact they are in SSL buffers.
*/
static ssize_t sec_read(const mcrawler_url *u, unsigned char *buf, const size_t size, char *errbuf) {
	assert(u->ssl);

	const int t = SSL_read(u->ssl, buf, size);
	// FIX: ? fix this fix?
	/* Fix CVE-2009-3555. Disable reneg if started by client. */
	/*
	if (ps->renegotiation) {
		shutdown_proxy(ps, SHUTDOWN_SSL);
		return;
	}
	*/

	if (t > 0) {
		return (ssize_t)t;
	}
	const int err = SSL_get_error(u->ssl, t);
	switch (err) {
		case SSL_ERROR_WANT_WRITE:
			return MCURL_IO_WRITE;
		case SSL_ERROR_WANT_READ:
			return MCURL_IO_READ;
		case SSL_ERROR_ZERO_RETURN:
			return MCURL_IO_EOF;
		case SSL_ERROR_SYSCALL:
			debugf("[%d] SSL read failed: SSL_ERROR_SYSCALL (%d)\n", u->index, t);
			if (t < 0) { // t == 0: unexpected EOF
				sprintf(errbuf, "Downloading content failed (%.200m)");
				return MCURL_IO_ERROR;
			}
		case SSL_ERROR_SSL:
			debugf("[%d] SSL read failed: protocol error: \n", u->index);
			unsigned long e, last_e = 0;
			while ((e = ERR_get_error())) {
				debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
				last_e = e;
			}
			if (last_e == 0) {
				// error queue is empty and t == 0 => EOF that violates the protocol
				debugf("[%d] Unexpected EOF\n", u->index);
				return MCURL_IO_EOF;
			}
			const int n = sprintf(errbuf, "Downloading content failed");
			if (last_e && n > 0) {
				sprintf(errbuf + n, " (%.200s)", ERR_reason_error_string(last_e));
			}
			return MCURL_IO_ERROR;
		default:
			debugf("[%d] SSL read failed: %d (WANT_X509_LOOKUP: 4, WANT_CONNECT: 7, WANT_ACCEPT: 8)\n", u->index, err);
			sprintf(errbuf, "Downloading content failed (unexpected SSL error)");
			return MCURL_IO_ERROR;
	}
}

/** Write some data to SSL socket.
NOTE: We must write as much as possible otherwise
select(.) would not notify us that socket is writable again.
*/
static ssize_t sec_write(const mcrawler_url *u, const unsigned char *buf, const size_t size, char *errbuf) {
    assert(u->ssl);

	const int t = SSL_write(u->ssl, buf, size);
	if (t > 0) {
		return (ssize_t)t;
	}

	const int err = SSL_get_error(u->ssl, t);
	switch (err) {
		case SSL_ERROR_WANT_READ:
			return MCURL_IO_READ;
		case SSL_ERROR_WANT_WRITE:
			return MCURL_IO_WRITE;
		case SSL_ERROR_ZERO_RETURN:
			return MCURL_IO_EOF;
		case SSL_ERROR_SYSCALL:
			debugf("[%d] SSL write failed: SSL_ERROR_SYSCALL (%d)\n", u->index, t);
			if (t < 0) { // t == 0: unexpected EOF
				sprintf(errbuf, "Sending request failed (%.200m)");
				return MCURL_IO_ERROR;
			}
		case SSL_ERROR_SSL:
			debugf("[%d] SSL write failed: protocol error: \n", u->index);
			unsigned long e, last_e = 0;
			while ((e = ERR_get_error())) {
				debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
				last_e = e;
			}
			const int n = sprintf(errbuf, "Sending request failed");
			if (last_e && n > 0) {
				sprintf(errbuf + n, " (%.200s)", ERR_reason_error_string(last_e));
			}
			return MCURL_IO_ERROR;
		default:
			debugf("[%d] SSL write failed: %d (WANT_X509_LOOKUP: 4, WANT_CONNECT: 7, WANT_ACCEPT: 8)\n", u->index, err);
			sprintf(errbuf, "Sending request failed (unexpected SSL error)");
			return MCURL_IO_ERROR;
	}
}
#endif

/** callback funkce, kterou zavola ares
 */
static void dnscallback(void *arg, int status, int timeouts, struct hostent *hostent) {
	mcrawler_url *u;
	
	u=(mcrawler_url *)arg;
	if (status == ARES_EDESTRUCTION) {
		// resolving cancelled by ares_destroy
		return;
	}
	if (status != ARES_SUCCESS) {
		if ((status == ARES_ENODATA || status == ARES_ENOTFOUND) && u->addrtype == AF_INET) {
			// zkusíme ještě IPv6
			u->addrtype = AF_INET6;
			debugf("[%d] gethostbyname error: %d -> switch to ipv6\n", u->index, status);
			set_atomic_int(&u->state, MCURL_S_PARSEDURL);
			return;
		}
		debugf("[%d] gethostbyname error: %d: %s (%d timeouts)\n", u->index, status, ares_strerror(status), timeouts);
		sprintf(u->error_msg, "DNS: %.250s", ares_strerror(status));
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}
	
	if (hostent->h_addr == NULL) {
		if (u->addrtype == AF_INET) {
			// zkusíme ještě IPv6
			u->addrtype = AF_INET6;
			debugf("[%d] Could not resolve host -> switch to ipv6\n", u->index);
			set_atomic_int(&u->state, MCURL_S_PARSEDURL);
			return;
		}
		debugf("[%d] Could not resolve host\n", u->index);
		sprintf(u->error_msg, "Could not resolve host");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}

	debugf("[%d] Resolving %s ended => %s", u->index, u->hostname, hostent->h_name);

	// uvolníme staré struktury
	if (u->addr != NULL) {
		free_addr(u->prev_addr);
		u->prev_addr = u->addr;
		u->addr = NULL;
	}

	char **p_addr = hostent->h_addr_list;
	mcrawler_addr *last_addr;
	do {
		mcrawler_addr *addr;
		addr = (mcrawler_addr*)malloc(sizeof(mcrawler_addr));
		memset(addr, 0, sizeof(mcrawler_addr));
		addr->type = hostent->h_addrtype;
		addr->length = hostent->h_length;
		memcpy(addr->ip, *p_addr, hostent->h_length);
		if (u->addr == NULL) {
			u->addr = addr;
		} else {
			last_addr->next = addr;
		}
		last_addr = addr;

		if (addr->type == AF_INET6) {
			debugf(", %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x", addr->ip[0], addr->ip[1], addr->ip[2], addr->ip[3], addr->ip[4], addr->ip[5], addr->ip[6], addr->ip[7], addr->ip[8], addr->ip[9], addr->ip[10], addr->ip[11], addr->ip[12], addr->ip[13], addr->ip[14], addr->ip[15]);
		} else {
			debugf(", %d.%d.%d.%d", addr->ip[0], addr->ip[1], addr->ip[2], addr->ip[3]);
		}
	} while (*++p_addr != NULL);
	last_addr->next = NULL;
	debugf("\n");

	u->timing.dnsend = get_time_int();
	set_atomic_int(&u->state, MCURL_S_GOTIP);
}

static int parse_proto(const char *s);

static int check_proto(mcrawler_url *u);

/**
 * Nastaví proto, host, port a path
 * rawurl musí obsahovat scheme a authority!
 */
static int set_new_url(mcrawler_url *u, char *rawurl, mcrawler_url_url *base) {
	mcrawler_url_url *url = (mcrawler_url_url *)calloc(1, sizeof(mcrawler_url_url));

	if (mcrawler_url_parse(url, rawurl, base) != MCRAWLER_URL_SUCCESS) {
		debugf("[%d] error: url='%s' failed to parse\n", u->index, rawurl);
		sprintf(u->error_msg, "Failed to parse URL");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		mcrawler_url_free_url(url);
		free(url);
		return 0;
	}

	if (!url->scheme[0]) {
		debugf("[%d] error: url='%s' has no scheme\n", u->index, rawurl);
		sprintf(u->error_msg, "URL has no scheme");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		mcrawler_url_free_url(url);
		free(url);
		return 0;
	}
	SAFE_STRCPY(u->proto, url->scheme);

	if (check_proto(u) == -1) {
		mcrawler_url_free_url(url);
		free(url);
		return 0;
	}

	if (url->host == NULL || url->cannot_be_a_base_url) {
		debugf("[%d] error: url='%s' has no host\n", u->index, rawurl);
		sprintf(u->error_msg, "URL has no host");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		mcrawler_url_free_url(url);
		free(url);
		return 0;
	}

	// serialized host in url->host->domain
	mcrawler_url_get_host(url, u->host);
	mcrawler_url_get_hostname(url, u->hostname);

	if (url->port_not_null) {
		u->port = url->port;
	} else {
		u->port = parse_proto(u->proto);
	}

	// recompose path + query
	if (u->path != NULL) free(u->path);
	u->path = mcrawler_url_serialize_path_and_query(url);

	debugf("[%d] proto='%s' hostname='%s' port=%d path='%s'\n", u->index, u->proto, u->hostname, u->port, u->path);

	if (url->host->type == MCRAWLER_URL_HOST_IPV4) {
		free_addr(u->prev_addr);
		u->prev_addr = u->addr;
		u->addr = (mcrawler_addr*)malloc(sizeof(mcrawler_addr));
		memset(u->addr, 0, sizeof(mcrawler_addr));
		memcpy(u->addr->ip, url->host->ipv4, 4);
		u->addr->type = AF_INET;
		u->addr->length = 4;
		u->addr->next = NULL;
		set_atomic_int(&u->state, MCURL_S_GOTIP);
		debugf("[%d] go directly to ipv4\n", u->index);
	} else if (url->host->type == MCRAWLER_URL_HOST_IPV6) {
		free_addr(u->prev_addr);
		u->prev_addr = u->addr;
		u->addr = (mcrawler_addr*)malloc(sizeof(mcrawler_addr));
		memset(u->addr, 0, sizeof(mcrawler_addr));
		memcpy(u->addr->ip, url->host->ipv6, 16);
		u->addr->type = AF_INET6;
		u->addr->length = 16;
		u->addr->next = NULL;
		set_atomic_int(&u->state, MCURL_S_GOTIP);
		debugf("[%d] go directly to ipv6\n", u->index);
	} else {
		set_atomic_int(&u->state, MCURL_S_PARSEDURL);
	}

	if (u->uri != NULL) {
		mcrawler_url_free_url(u->uri);
		free(u->uri);
	}
	u->uri = url;
	return 1;
}

/**
 * Parse URL
 */
static void parseurl(mcrawler_url *u) {
	debugf("[%d] Parse url='%s'\n", u->index, u->rawurl);
	if (set_new_url(u, u->rawurl, NULL) == 0) {
		return;
	}
}

/** spusti preklad pres ares
 */
static void launchdns(mcrawler_url *u) {
	int t;

	debugf("[%d] Resolving %s starts\n", u->index, u->hostname);

	struct ares_options opts;
	opts.timeout = 5000;

	if (u->aresch) {
		ares_destroy(u->aresch);
	}

	t = ares_init_options((ares_channel *)&u->aresch, &opts, ARES_OPT_TIMEOUTMS);
	if(t) {
		debugf("[%d] ares_init failed (%d)\n", u->index, t);
		sprintf(u->error_msg, "ares init failed");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}
	if (!u->addrtype) {
		if (u->options & 1<<MCURL_OPT_IPV6) {
			u->addrtype = AF_INET6;
		} else {
			u->addrtype = AF_INET;
		}
	}

	set_atomic_int(&u->state, MCURL_S_INDNS);
	if (!u->timing.dnsstart) {
		const int time = get_time_int();
		u->timing.dnsstart = time;
	}

	ares_gethostbyname(u->aresch, u->hostname, u->addrtype, (ares_host_callback)&dnscallback, u);
}

/** uz je ares hotovy?
 */
static void checkdns(mcrawler_url *u) {
	int t;
	fd_set readfds;
	fd_set writefds;
	struct timeval timeout, *tp;

	timeout.tv_sec = 0;
	timeout.tv_usec = 5000;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	t = ares_fds(u->aresch, &readfds, &writefds);
	if(!t) {
		return;
	}
	tp = ares_timeout(u->aresch, &timeout, &timeout);
	select(t, &readfds, &writefds, NULL, tp);

	ares_process(u->aresch, &readfds, &writefds); // pri uspechu zavola callback sama
}

/**
Finish connection for non-blocking socket for which connect(.) returned EAGAIN.
*/
static void connectsocket(mcrawler_url *u) {
	int result;
	socklen_t result_len = sizeof(result);
	if (getsockopt(u->sockfd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
		// error, fail somehow, close socket
		debugf("[%d] Cannot connect, getsoskopt(.) returned error status: %m\n", u->index);
		if (u->addr->next != NULL) {
			mcrawler_addr *next = u->addr->next;
			free(u->addr);
			u->addr = next;
			debugf("[%d] Trying another ip\n", u->index);
			set_atomic_int(&u->state, MCURL_S_GOTIP);
			return;
		}
		sprintf(u->error_msg, "Failed to connect to host (%.200m)");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}

	if (result != 0) {
		debugf("[%d] Cannot connect, attempt to connect failed\n", u->index);
		if (u->addr->next != NULL) {
			mcrawler_addr *next = u->addr->next;
			free(u->addr);
			u->addr = next;
			debugf("[%d] Trying another ip\n", u->index);
			set_atomic_int(&u->state, MCURL_S_GOTIP);
			return;
		}
		sprintf(u->error_msg, "Failed to connect to host (%.200s)", strerror(result));
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}

	set_atomic_int(&u->state, MCURL_S_HANDSHAKE);
	set_atomic_int(&u->rw, 1<< MCURL_RW_READY_READ | 1<<MCURL_RW_READY_WRITE);
}

/** uz znam IP, otevri socket
 */
static void opensocket(mcrawler_url *u)
{
	int flags;
	struct sockaddr_storage addr;
	socklen_t addrlen;

	if (u->sockfd) {
		close_conn(u);
		u->close_connection = 0;
	}

	u->sockfd = socket(u->addr->type, SOCK_STREAM, 0);
	flags = fcntl(u->sockfd, F_GETFL,0);              // Get socket flags
	fcntl(u->sockfd, F_SETFL, flags | O_NONBLOCK);   // Add non-blocking flag	

#ifdef HAVE_DEBUG
	if (debug) {
		char straddr[INET6_ADDRSTRLEN];
		inet_ntop(u->addr->type, u->addr->ip, straddr, sizeof(straddr));
		debugf("[%d] connecting to ip: %s; %d, port: %i (socket %d)\n", u->index, straddr, get_time_slot(u->addr->ip), u->port, u->sockfd);
	}
#endif

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = u->addr->type;
	if (u->addr->type == AF_INET6) {
		(*(struct sockaddr_in6 *)&addr).sin6_port = htons(u->port);
		memcpy(&((*(struct sockaddr_in6 *)&addr).sin6_addr), &(u->addr->ip), u->addr->length);
		addrlen = sizeof(struct sockaddr_in6);
	} else {
		(*(struct sockaddr_in *)&addr).sin_port = htons(u->port);
		memcpy(&((*(struct sockaddr_in *)&addr).sin_addr), &(u->addr->ip), u->addr->length);
		addrlen = sizeof(struct sockaddr_in);
	}
	const int t = connect(u->sockfd, (struct sockaddr *)&addr, addrlen);
	copy_addr_prev_addr(u);
	u->prev_port = u->port;

	if (t) {
		if (errno == EINPROGRESS) {
			set_atomic_int(&u->state, MCURL_S_CONNECT);
			set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		} else {
			debugf("[%d] connect failed (%d, %s)\n", u->index, errno, strerror(errno));
			sprintf(u->error_msg, "Failed to connect to host (%.200m)");
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		}
	} else {
		set_atomic_int(&u->state, MCURL_S_HANDSHAKE);
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE | 1<<MCURL_RW_WANT_WRITE);
	}
}

static void prepare_for_request(mcrawler_url *u) {
	remove_expired_cookies(u);

	if (!u->method[0]) {
		strcpy(u->method, "GET");
	}
}

/** socket bezi, posli dotaz
 * cookie header see http://tools.ietf.org/html/rfc6265 section 5.4
 */
static void genrequest(mcrawler_url *u) {
	const char reqfmt[] = "%s %s HTTP/1.1";
	const char hostheader[] = "Host: ";
	const char useragentheader[] = "User-Agent: ";
	const char cookieheader[] = "Cookie: ";
	const char acceptheader[] = "Accept: */*";
	const char gzipheader[] = "Accept-Encoding: gzip";
	const char contentlengthheader[] = "Content-Length: ";
	const char contenttypeheader[] = "Content-Type: application/x-www-form-urlencoded";
	const char authorizationheader[] = "Authorization: ";

	size_t cookies_size = cookies_header_max_size(u);

	free(u->request);
	u->request = malloc(
			sizeof(reqfmt) + strlen(u->method) + strlen(u->path) + 2 + // method URL HTTP/1.1\n
			sizeof(hostheader) + strlen(u->host) + 2 + // Host: %s(:port)\n
			sizeof(acceptheader) + 2 + // Accept: */*\n
			(u->authorization != NULL ? strlen(authorizationheader) + strlen(u->authorization) + 2 : 0) + // Authorization: ...\n
			sizeof(useragentheader) + (u->customagent[0] ? strlen(u->customagent) : sizeof(DEFAULTAGENT) + 8) + 2 + // User-Agent: %s\n
			sizeof(cookieheader) + cookies_size + 2 + // Cookie: %s; %s...\n
			strlen(u->customheader) +
			(u->options & 1<<MCURL_OPT_GZIP ? sizeof(gzipheader) + 2 : 0) + // Accept-Encoding: gzip\n
			(u->post != NULL ? sizeof(contentlengthheader) + 6 + 2 + sizeof(contenttypeheader) + 2 : 0) + // Content-Length: %d\nContent-Type: ...\n
			2 + // end of header
			u->postlen + // body
			1 // \0
	);

	char *r = (char *)u->request;
	int s;

	s = sprintf(r, reqfmt, u->method, u->path);
	if (s > 0) r += s;
	r = stpcpy(r, "\r\n");

	// Host
	r = stpcpy(r, hostheader);
	r = stpcpy(r, u->host);
	r = stpcpy(r, "\r\n");

	// Accept
	char *p = strstr(u->customheader, "Accept:");
	if (p && (p == u->customheader || *(p-1) == '\n')) {
		// Accept header is located in custom header -> skip
	} else {
		r = stpcpy(r, acceptheader);
		r = stpcpy(r, "\r\n");
	}

	// Authorization
	if (u->authorization != NULL) {
		r = stpcpy(r, authorizationheader);
		r = stpcpy(r, u->authorization);
		r = stpcpy(r, "\r\n");
	}

	// User-Agent
	r = stpcpy(r, useragentheader);
	if (u->customagent[0]) {
		r = stpcpy(r + strlen(r), u->customagent);
	} else {
		s = sprintf(r + strlen(r), DEFAULTAGENT, VERSION);
		if (s > 0) r += s;
	}
	r = stpcpy(r, "\r\n");

	// Cookie
	set_cookies_header(u, r + sizeof(cookieheader) - 1, &cookies_size);
	if (cookies_size) {
		strncpy(r, cookieheader, sizeof(cookieheader) - 1);
		r += sizeof(cookieheader) - 1 + cookies_size;
		r = stpcpy(r, "\r\n");
	}

	// Custom header
	if (u->customheader[0]) {
		r = stpcpy(r, u->customheader);
	}

	// gzip
	if (u->options & 1<<MCURL_OPT_GZIP) {
		r = stpcpy(r, gzipheader);
		r = stpcpy(r, "\r\n");
	}

	if (u->post != NULL) {
		r = stpcpy(r, contentlengthheader);
		s = sprintf(r, "%d", u->postlen);
		if (s > 0) r += s;
		r = stpcpy(r, "\r\n");

		char *p = strstr(u->customheader, "Content-Type:");
		if (p && (p == u->customheader || *(p-1) == '\n')) {
		// Content-Type header is located in custom header -> skip
		} else {
			r = stpcpy(r, contenttypeheader);
			r = stpcpy(r, "\r\n");
		}
	}

	// end of header
	r = stpcpy(r, "\r\n");

	// body
	if (u->post != NULL) {
		r = mempcpy(r, u->post, u->postlen);
	}
	*r = 0;

	debugf("[%d] Request: [%s]", u->index, u->request);
	u->request_len = r - (char *)u->request;
	u->request_it = 0;

	set_atomic_int(&u->state, MCURL_S_SENDREQUEST);
	set_atomic_int(&u->rw, 1<<MCURL_RW_READY_WRITE);
}

#ifdef HAVE_LIBNGHTTP2

#define MAKE_NGHTTP2_NV(NAME, VALUE) {\
	(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE), NGHTTP2_NV_FLAG_NO_COPY_VALUE \
}

#define MAKE_NGHTTP2_NV_COPY(NAME, VALUE) {\
	(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE \
}

#define MAKE_NGHTTP2_NV_COPY_L(NAME, VALUE, VALUE_LEN) {\
	(uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUE_LEN, NGHTTP2_NV_FLAG_NONE \
}

#define MAKE_NGHTTP2_NV_COPY_LL(NAME, NAMELEN, VALUE, VALUE_LEN) {\
	(uint8_t *) NAME, (uint8_t *)VALUE, NAMELEN, VALUE_LEN, NGHTTP2_NV_FLAG_NONE \
}

static ssize_t http2_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;

	const ssize_t ret = ((mcrawler_url_func *)u->f)->write(u, data, length, (char *)&u->error_msg);

	if (ret == MCURL_IO_ERROR || ret == MCURL_IO_EOF) {
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	else if (ret == MCURL_IO_WRITE) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		return NGHTTP2_ERR_WOULDBLOCK;
	} else if (ret == MCURL_IO_READ) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
		return NGHTTP2_ERR_WOULDBLOCK;
	} else {
		assert(ret > 0);
		debugf("[%d] Written %zd bytes to socket %d\n", u->index, ret, u->sockfd);
		//set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		return ret;
	}
}

/**
 * Copy request to buffer
 */
static ssize_t http2_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	http2_session_data *session_data = (http2_session_data *)u->http2_session;
	if (session_data->stream_id == stream_id) {
		mcrawler_url *u = (mcrawler_url *)source->ptr;
		size_t ret = u->postlen - u->request_it > length ? length : u->postlen - u->request_it;

		if (ret == 0) {
			*data_flags = *data_flags | NGHTTP2_DATA_FLAG_EOF;
		} else {
			memcpy(buf, u->post + u->request_it, ret);
			debugf("[%d] Copied %zd bytes to read buffer [%.*s]\n", u->index, ret, (int)ret, buf);
			u->request_it += ret;
		}
		return ret;
	}
	return 0;
}

static void header_cb(const char *name, char *value, void *data);

/**
 * Received header from server
 */
static int http2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	http2_session_data *session_data = (http2_session_data *)u->http2_session;
	switch (frame->hd.type) {
		case NGHTTP2_HEADERS:
			if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
					session_data->stream_id == frame->hd.stream_id) {
				debugf("[%d] header: %s: %s\n", u->index, name, value);
				char *val = strdup((const char *)value);
				header_cb((const char *)name, val, user_data);
				free(val);

				if (buf_len(u) > 0) {
					// delete the last empty line
					buf_del(u, 2);
				}
				buf_write(u, name, namelen);
				buf_write_lit(u, ": ");
				buf_write(u, value, valuelen);
				buf_write_lit(u, "\r\n\r\n");
				u->headlen = buf_len(u);

				break;
			}
	}
	return 0;
}

/**
 * Received data from server
 */
static int http2_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	http2_session_data *session_data = (http2_session_data *)u->http2_session;
	if (session_data->stream_id == stream_id) {
		size_t written = buf_write(u, data, len);
		if (written < len) {
			debugf("[%d] Buffer is full\n", u->index);
		}
	}

	return 0;
}

static int http2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, nghttp2_error_code error_code, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	http2_session_data *session_data = (http2_session_data *)u->http2_session;
	int rv;
	if (session_data->stream_id == stream_id) {
		if (error_code > 0) {
#ifdef HAVE_NGHTTP2_HTTP2_STRERROR
			// since nghttp2 1.9.0
			debugf("[%d] HTTP2 stream %d closes with error %s (%d)\n", u->index, stream_id, nghttp2_http2_strerror(error_code), error_code);
			sprintf(u->error_msg, "HTTP2 stream closes with error %s", nghttp2_http2_strerror(error_code));
#else
			debugf("[%d] HTTP2 stream %d closes with error %d\n", u->index, stream_id, error_code);
			sprintf(u->error_msg, "HTTP2 stream closes with error %d", error_code);
#endif
			set_atomic_int(&u->state, MCURL_S_ERROR);
			rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
			if (rv) {
				return NGHTTP2_ERR_CALLBACK_FAILURE;
			}
		} else {
			debugf("[%d] HTTP2 stream %d closes successfuly\n", u->index, stream_id);
			set_atomic_int(&u->state, MCURL_S_DOWNLOADED);
		}
	}
	return 0;
}

static inline const char *strframetype(uint8_t type) {
	switch (type) {
		case NGHTTP2_DATA:
			return "DATA";
		case NGHTTP2_HEADERS:
			return "HEADERS";
		case NGHTTP2_PRIORITY:
			return "PRIORITY";
		case NGHTTP2_RST_STREAM:
			return "RST_STREAM";
		case NGHTTP2_SETTINGS:
			return "SETTINGS";
		case NGHTTP2_PUSH_PROMISE:
			return "PUSH_PROMISE";
		case NGHTTP2_PING:
			return "PING";
		case NGHTTP2_GOAWAY:
			return "GOAWAY";
		case NGHTTP2_WINDOW_UPDATE:
			return "WINDOW_UPDATE";
		case NGHTTP2_CONTINUATION:
			return "CONTINUATION";
		default:
			return "UKNOWN";
	}
}

static inline const char *str_settings_id(int32_t id) {
    switch (id) {
        case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
            return "HEADER_TABLE_SIZE";
        case NGHTTP2_SETTINGS_ENABLE_PUSH:
            return "ENABLE_PUSH";
        case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
            return "MAX_CONCURRENT_STREAMS";
        case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
            return "INITIAL_WINDOW_SIZE";
        case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
            return "MAX_FRAME_SIZE";
        case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
            return "MAX_HEADER_LIST_SIZE";
#if HAVE_DECL_NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL
        case NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
            return "ENABLE_CONNECT_PROTOCOL";
#endif
        default:
            return "UNKNOWN";
    }
}

static int http2_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	debugf("[%d] Sent %s frame of length %zu in stream %d\n", u->index, strframetype(frame->hd.type), frame->hd.length, frame->hd.stream_id);
	return 0;
}

static int http2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;

    switch (frame->hd.type) {
		case NGHTTP2_SETTINGS:
            debugf("[%d] Received SETTING frame:", u->index);
            for (int i = 0; i < frame->settings.niv; i++) {
                debugf(" %s=%u", str_settings_id(frame->settings.iv[i].settings_id), frame->settings.iv[i].value);
            }
            if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
                debugf(" ACK");
            }
            debugf("\n");
            break;
		case NGHTTP2_RST_STREAM:
            debugf("[%d] Received RST_STREAM frame with error %u in stream %d\n", u->index, frame->rst_stream.error_code, frame->hd.stream_id);
            break;
        default:
            debugf("[%d] Received %s frame of length %zu in stream %d\n", u->index, strframetype(frame->hd.type), frame->hd.length, frame->hd.stream_id);
    }

	return 0;
}

#ifdef HAVE_NGHTTP2_SESSION_CALLBACKS_SET_ERROR_CALLBACK
static int http2_on_error_callback(nghttp2_session *session, const char *msg, size_t len, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	debugf("[%d] HTTP2 error: %.*s\n", u->index, (int)len, msg);
	if (len > 200) len = 200;
	sprintf(u->error_msg, "HTTP2 error (%.*s)", (int)len, msg);
	set_atomic_int(&u->state, MCURL_S_ERROR);
	return 0;
}
#endif

static int http2_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
	mcrawler_url *u = (mcrawler_url *)user_data;
	if (!u->timing.firstbyte) {
		u->timing.lastread = u->timing.firstbyte = get_time_int();
	}
	return 0;
}

static int http2_create_session(mcrawler_url *u) {
	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);
	nghttp2_session_callbacks_set_send_callback(callbacks, http2_send_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, http2_on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, http2_on_stream_close_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, http2_on_header_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, http2_on_begin_headers_callback);
#ifdef HAVE_NGHTTP2_SESSION_CALLBACKS_SET_ERROR_CALLBACK
	nghttp2_session_callbacks_set_error_callback(callbacks, http2_on_error_callback);
#endif

#ifdef HAVE_DEBUG
	if (debug) {
		nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, http2_on_frame_send_callback);
		nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, http2_on_frame_recv_callback);
	}
#endif

	// init session data
	http2_session_data *session_data = malloc(sizeof(http2_session_data));
	memset(session_data, 0, sizeof(http2_session_data));
	u->http2_session = session_data;

	nghttp2_session_client_new(&session_data->session, callbacks, u);
	nghttp2_session_callbacks_del(callbacks);

	// TCP NODELAY
	int val = 1;
	setsockopt(u->sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

	// submit SETTINGS
	int rv;
	nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
	/* client 24 bytes magic string will be sent by nghttp2 library */
	rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
	if (rv != 0) {
		debugf("[%d] Could not submit SETTINGS: %s", u->index, nghttp2_strerror(rv));
		sprintf(u->error_msg, "HTTP2 error (%.200s)", nghttp2_strerror(rv));
	}
	return rv;
}

struct http2_headers {
	size_t len;
	nghttp2_nv nv[32];
	uint32_t alloc;
};

static void http2_custom_header_cb(const char *name, char *value, void *data) {
	struct http2_headers *hdrs = (struct http2_headers *)data;
	if (hdrs->len < ARRLEN(hdrs->nv)) {
		hdrs->alloc |= 1<<hdrs->len;
		hdrs->nv[hdrs->len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY_LL(strdup(name), strlen(name), strdup(value), strlen(value));
	}
}

static void genrequest_http2(mcrawler_url *u) {
	struct http2_headers hdrs;
	hdrs.len = 0;
	hdrs.alloc = 0;
	hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV(":method", u->method);
	hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV(":scheme", u->proto);
	hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV(":authority", u->host);
	hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV(":path", u->path);

	// Accept
	char *p = strstr(u->customheader, "Accept:");
	if (p && (p == u->customheader || *(p-1) == '\n')) {
		// Accept header is located in custom header -> skip
	} else {
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY("accept", "*/*");
	}

	// Authorization
	if (u->authorization != NULL) {
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV("authorization", u->authorization);
	}

	// User-Agent
	char useragent[sizeof(DEFAULTAGENT) + sizeof(VERSION)];
	if (u->customagent[0]) {
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV("user-agent", u->customagent);
	} else {
		int len = sprintf(useragent, DEFAULTAGENT, VERSION);
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY_L("user-agent", useragent, len);
	}

	// Cookie
	char cookie[cookies_header_max_size(u) + 1];
	size_t len;
	set_cookies_header(u, cookie, &len);
	if (len) {
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY_L("cookie", cookie, len);
	}

	// gzip
	if (u->options & 1<<MCURL_OPT_GZIP) {
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY("accept-encoding", "gzip");
	}

	nghttp2_data_provider data_provider, *p_data_provider = NULL;
	char postlen[6];
	if (u->post != NULL) {
		sprintf(postlen, "%d", u->postlen);
		hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY_L("content-length", postlen, strlen(postlen));

		char *p = strstr(u->customheader, "Content-Type:");
		if (p && (p == u->customheader || *(p-1) == '\n')) {
		// Content-Type header is located in custom header -> skip
		} else {
			hdrs.nv[hdrs.len++] = (nghttp2_nv) MAKE_NGHTTP2_NV_COPY("content-type", "application/x-www-form-urlencoded");
		}

		p_data_provider = &data_provider;
		data_provider.source.ptr = u;
		data_provider.read_callback = http2_read_callback;
		u->request_it = 0;
	}

	// Custom header
	if (u->customheader[0]) {
		parsehead((const unsigned char *)u->customheader, strlen(u->customheader), NULL, http2_custom_header_cb, &hdrs, u->index);
	}

#ifdef HAVE_DEBUG
	if (debug) {
		debugf("[%d] Request headers:\n", u->index);
		for (size_t i = 0; i < hdrs.len; i++) {
			debugf("\t%s: %s %zd %zd %ud\n", hdrs.nv[i].name, hdrs.nv[i].value, hdrs.nv[i].namelen, hdrs.nv[i].valuelen, hdrs.nv[i].flags);
		}
	}
#endif

	if (!u->http2_session) {
		int rv;
		rv = http2_create_session(u);
		if (rv != 0) {
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		}
	}
	http2_session_data *session_data = (http2_session_data *)u->http2_session;

	// submit headers
	int32_t stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs.nv, hdrs.len, p_data_provider, u);

	// free allocated memory for headers
	for (size_t i = 0; i < hdrs.len; i++) {
		if (hdrs.alloc & (1<<i)) {
			free(hdrs.nv[i].name);
			free(hdrs.nv[i].value);
		}
	}

	if (stream_id < 0) {
		set_atomic_int(&u->state, MCURL_S_ERROR);
		debugf("[%d] Could not submit HTTP request: %s", u->index, nghttp2_strerror(stream_id));
		sprintf(u->error_msg, "Could not submit HTTP request (%.200s)", nghttp2_strerror(stream_id));
		return;
	}
	session_data->stream_id = stream_id;

	if (http2_session_send(u)) {
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}

	set_atomic_int(&u->state, MCURL_S_RECVREPLY);
	set_atomic_int(&u->rw, 1<< MCURL_RW_READY_READ | 1<<MCURL_RW_READY_WRITE);
}
#endif

/** Sends the request string. This string was generated in previous state:
GEN_REQUEST.
*/
static void sendrequest(mcrawler_url *u) {
	if (u->request_it < u->request_len) {
		const ssize_t ret = ((mcrawler_url_func *)u->f)->write(u, &u->request[u->request_it], u->request_len - u->request_it, (char *)&u->error_msg);
		if (ret == MCURL_IO_ERROR || ret == MCURL_IO_EOF) {
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		}
		else if (ret == MCURL_IO_WRITE) {
			set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		} else if (ret == MCURL_IO_READ) {
			set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
		} else {
			assert(ret > 0);
			u->request_it += (size_t)ret;
		}
	}
	if (u->request_it == u->request_len) {
		set_atomic_int(&u->state, MCURL_S_RECVREPLY);
		set_atomic_int(&u->rw, 1<<MCURL_RW_READY_READ);
	} else {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
	}
}

/** Fake handshake handler that does nothing, only increments state.
Usefull for plain http protocol that does not need handshake.
*/
static void empty_handshake(mcrawler_url *u) {
	set_atomic_int(&u->state, MCURL_S_GENREQUEST);
}

static void header_cb(const char *name, char *value, void *data) {
	mcrawler_url *u = (mcrawler_url *)data;
	if (!strcasecmp(name, ":status")) {
		u->status = atoi(value);
		return;
	}

	if (!strcasecmp(name, "Content-Length")) {
		u->has_contentlen = 1;
		u->contentlen = atoi(value);
		debugf("[%d] Head, Content-Length: %zd\n", u->index, u->contentlen);
		if (!strcmp(u->method, "HEAD")) { // there will be no content
			u->contentlen = 0;
			debugf("[%d] HEAD request, no content\n", u->index);
		}
		return;
	}

	if ((!strcasecmp(name, "Location") && (u->status >= 300 && u->status < 400)) ||
			!strcasecmp(name, "Refresh")) {
		if (!strcasecmp(name, "Refresh")) {
			if (strncmp(value, "0;url=", 6)) {
				return;
			} else {
				value += 6;
			}
		}
		if (strlen(value) > MAXURLSIZE) {
			sprintf(u->error_msg, "Redirect URL is too long");
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		}
		strcpy(u->location, value);
		if (!u->has_contentlen && !u->chunked) {
			// do not need content - some servers returns no content-length and keeps conection open
			u->has_contentlen = 1;
			u->contentlen = 0; 
		}
		debugf("[%d] Location='%s'\n", u->index, u->location);
		return;
	}

	if (!strcasecmp(name, "Set-Cookie")) {
		setcookie(u, value);
		return;
	}

	if (!strcasecmp(name, "Transfer-Encoding")) {
		if (!strcasecmp(value, "chunked")) {
			u->chunked = 1;
			u->nextchunkedpos = u->headlen;
			u->has_contentlen = 0; // we will read until empty chunk, not until contentlen is reached
			debugf("[%d] Chunked!\n", u->index);
		}
		return;
	}

	if (!strcasecmp(name, "Content-Encoding")) {
		if (strstr(value, "gzip")) {
			u->gzipped = 1;
			debugf("[%d] Gzipped!\n", u->index);
		}
		return;
	}

	if (!strcasecmp(name, "Content-Type")) {
		char *p;
		if (u->contenttype) free(u->contenttype);
		if ((p = strstr(value, " charset="))) {
			u->contenttype = malloc(p - value + 1);
			memcpy(u->contenttype, value, p-value+1);
			for (int i = p-value; u->contenttype[i] == ' ' || u->contenttype[i] == ';'; i--) u->contenttype[i] = 0;
			p += 9;
			if (strlen(p) < sizeof(u->charset)) {
				strcpy(u->charset, p);
				debugf("[%d] charset='%s'\n", u->index, u->charset);
			}
		} else {
			u->contenttype = strdup(value);
		}
		return;
	}

	if (!strcasecmp(name, "WWW-Authenticate")) {
		if (u->wwwauthenticate) free(u->wwwauthenticate);
		u->wwwauthenticate = strdup(value);
		if (u->status == 401 && u->username[0]) {
			// TODO: header can exists multiple times
			parse_authchallenge(u, value);
		}
		return;
	}

	if (!strcasecmp(name, "Connection")) {
		if (strcasestr(value, "close")) {
			u->close_connection = 1;
		}
		return;
	}
}

/**
Perform simple non-blocking read.
It uses callback function that performs the reaing so it can read from both SSL and plain connections.
Length of the read data is not limited if possible.
Unread data may remain in SSL buffers and select(.) may not notify us about it,
because from its point of view they were read.
*/
ssize_t plain_read(const mcrawler_url *u, unsigned char *buf, const size_t size, char *errbuf) {
	const int fd = u->sockfd;
	const ssize_t res = read(fd, buf, size);
	if (0 < res) {
		return res;
	}
	if (0 == res) {
		return MCURL_IO_EOF;
	}
	if (-1 == res) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return MCURL_IO_READ;
		}
	}
	debugf("[%d] read failed: %m\n", u->index);
	sprintf(errbuf, "Downloading content failed (%.200m)");
	return MCURL_IO_ERROR;
}

ssize_t plain_write(const mcrawler_url *u, const unsigned char *buf, const size_t size, char *errbuf) {
	const int fd = u->sockfd;
	const ssize_t res = write(fd, buf, size);
	if (0 < res) {
		return res;
	}	
	if (0 == res) {
		return MCURL_IO_EOF;
	}
	if (-1 == res) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return MCURL_IO_WRITE;
		}
	}
	debugf("[%d] write failed: %m\n", u->index);
	sprintf(errbuf, "Sending request failed (%.200m)");
	return MCURL_IO_ERROR;
}

static void finish(mcrawler_url *u, mcrawler_url_callback callback, void *callback_arg) {

	if (u->gzipped) {
		char *errmsg = NULL;
		unsigned char *buf;
		size_t len, resp_len = buf_len(u) - u->headlen;
		int ret;

		buf_get(u, 9*resp_len, &buf, &len); // 9times -> approx size after ungzip
		ret = gunzip(buf_p(u) + u->headlen, resp_len, buf, &len, &errmsg);
		debugf("[%d] gzip decompress status: %d (input length: %zd, output length: %zd)\n", u->index, ret, resp_len, len);
		if (ret != 0) {
			if (errmsg != NULL) {
				sprintf(u->error_msg, "Gzip decompression error: %.200s", errmsg);
				free(errmsg);
			} else {
				sprintf(u->error_msg, "Gzip decompression error (%d)", ret);
			}
			u->status = MCURL_S_DOWNLOADED - MCURL_S_ERROR;
		} else {
			memmove(buf_p(u) + u->headlen, buf, len);
			buf_set_len(u, u->headlen + len);
		}
	}

	if (u->options & 1<<MCURL_OPT_CONVERT_TO_UTF8) {
		if (!*u->charset) {
			unsigned charset_len = 0;
			char *charset = detect_charset_from_html((char *)buf_p(u) + u->headlen, buf_len(u) - u->headlen, &charset_len);
			if (charset && charset_len < sizeof(u->charset)) {
				*(char*)mempcpy(u->charset, charset, charset_len) = 0;
			}
		}
		if (!*u->charset) {
			strcpy(u->charset, "ISO-8859-1"); // default see http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7.1
		}
		debugf("[%d] converting from %s to UTF-8\n", u->index, u->charset);
		const int r = conv_charset(u);
		if (r == 0) {
			// success, content charset is ut-8 now
			strcpy(u->charset, "utf-8");
		} else {
			debugf("[%d] conversion error: %m\n", u->index);
			sprintf(u->error_msg, "Charset conversion error (%.200m)");
			u->status = MCURL_S_DOWNLOADED - MCURL_S_ERROR;
		}
	}

	if (u->options & 1<<MCURL_OPT_CONVERT_TO_TEXT) {
		size_t new_len = converthtml2text((char *)buf_p(u)+u->headlen, buf_len(u)-u->headlen);
		buf_set_len(u, new_len+u->headlen);
	}

	remove_expired_cookies(u);

	u->timing.done = get_time_int();
	u->last_state = get_atomic_int(&u->state);

	callback(u, callback_arg);

	debugf("[%d] Done.\n",u->index);
	set_atomic_int(&u->state, MCURL_S_DONE);
}

/**
 * Sets the url to initial state
 */
void reset_url(mcrawler_url *u) {
	u->status = 0;
	u->location[0] = 0;
	u->headlen = 0;
	u->contentlen = 0;
	u->has_contentlen = 0;
	u->chunked = 0;
	u->gzipped = 0;
	u->ssl_options.opts = 0;
	if (u->contenttype) {
		free(u->contenttype);
		u->contenttype = NULL;
	}
	if (u->wwwauthenticate) {
		free(u->wwwauthenticate);
		u->wwwauthenticate = NULL;
	}
	buf_free(u);

	memset(&u->timing, 0, sizeof(u->timing));
}

/**
 * Turn the state to INTERNAL ERROR with information that
 * we have been requested to download url with unsupported protocol.
 */
static void set_unsupported_protocol(mcrawler_url *u) {
	debugf("[%d] Unsupported protocol: [%s]\n", u->index, u->proto);
	sprintf(u->error_msg, "Protocol [%s] not supported", u->proto);
	set_atomic_int(&u->state, MCURL_S_ERROR);
}

/** Parse string with the name of the protocol and return default port for that protocol or 0,
if such protocol is not supported by minicrawler.
*/
static int parse_proto(const char *s) {
	if (0 == strcmp(s, "https")) {
		return 443;
	}
	if (0 == strcmp(s, "http")) {
		return 80;
	}
	return -1;
}

/**
 * Check the protocol of the destination url. If it is supported protocol,
 * then set all callbacks, otherwise turn the state to UNSUPPORTED PROTOCOL.
 */
static int check_proto(mcrawler_url *u) {
	const int port = parse_proto(u->proto);
	mcrawler_url_func *f = u->f;
	switch (port) {
		case 80:
			f->read = plain_read;
			f->write = plain_write;
			f->handshake = empty_handshake;
			f->gen_request = genrequest;
			f->recv_reply = readreply;
			break;
#ifdef HAVE_LIBSSL
		case 443:
			if (u->options & 1<<MCURL_OPT_NONSSL) {
				set_unsupported_protocol(u);
				return -1;
			} else {
				f->read = sec_read;
				f->write = sec_write;
				f->handshake = sec_handshake;
			}
			break;
#endif
		default:
			set_unsupported_protocol(u);
			return -1;
	}
	return port;
}

/** vyres presmerovani
 */
static int resolvelocation(mcrawler_url *u) {
	if (--u->redirect_limit <= 0) {
		debugf("[%d] Exceeded redirects limit", u->index);
		sprintf(u->error_msg, "Too many redirects, possibly a redirect loop");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return 1;
	}

	char ohost[ strlen(u->hostname) + 1 ];
	strcpy(ohost, u->hostname);

	debugf("[%d] Resolve location='%s'\n", u->index, u->location);

	if (set_new_url(u, u->location, u->uri) == 0) {
		return 1;
	}

	free(u->redirectedto);
	u->redirectedto = mcrawler_url_serialize_url(u->uri, 0);

	if (strcmp(u->hostname, ohost) == 0) {
		if (!u->close_connection && u->port == u->prev_port) {
			// the same host & post -> send request to the previous connection
			debugf("[%d] Using existing connection at socket %d!\n", u->index, u->sockfd);
			set_atomic_int(&u->state, MCURL_S_GENREQUEST);
		} else {
			// muzes se pripojit na tu puvodni IP
			set_atomic_int(&u->state, MCURL_S_GOTIP);
		}
	} else {
		// zmena host
		if (get_atomic_int(&u->state) != MCURL_S_GOTIP) {
			// pokud jsme nedostali promo ip, přepneme se do ipv4
			u->addrtype = AF_INET;
		}
	}

	mcrawler_redirect_info *rinfo = malloc(sizeof(mcrawler_redirect_info));
	memset(rinfo, 0, sizeof(mcrawler_redirect_info));
	rinfo->url = malloc(strlen(u->location)+1);
	strcpy(rinfo->url, u->location);
	rinfo->status = u->status;
	memcpy(&rinfo->timing, &u->timing, sizeof(u->timing));
	rinfo->next = u->redirect_info;
	u->redirect_info = rinfo;

	// GET method after redirect
	strcpy(u->method, "GET");
	if (u->post != NULL) {
		free(u->post);
		u->post = NULL;
		u->postlen = 0;
	}
	// Remove authorization or we should keep session for protection space
	// @see http://tools.ietf.org/html/rfc2617#section-3.3
	if (u->authorization) {
		free(u->authorization);
		u->authorization = NULL;
		u->auth_attempt = 0;
	}

	reset_url(u);
	return 0;
}


/**
 * Continue with crawling? - return 0
 */
static int cont(mcrawler_url *u) {
	if (u->options & 1<<MCURL_OPT_NOT_FOLLOW_REDIRECTS) {
		return 1;
	} else if (u->location[0] && strcmp(u->method, "HEAD")) {
		resolvelocation(u);
		return 0;
	} else if (u->authorization && u->status == 401) {
		if (!u->auth_attempt) {
			// try to authorize
			u->auth_attempt = 1;
			reset_url(u);
			set_atomic_int(&u->state, MCURL_S_GOTIP);
			return 0;
		}
	}
	return 1;
}

/**
Try read some data from the socket, check that we have some available place in the buffer.
*/
static ssize_t try_read(mcrawler_url *u) {
	size_t len;
	unsigned char *buf;
	buf_get(u, 1, &buf, &len);
	if (len <= 0) {
		return 0;
	}

	ssize_t read = ((mcrawler_url_func *)u->f)->read(u, buf, len, (char *)&u->error_msg);
	if (read > 0) {
		buf_inc(u, (size_t)read);
	}
	return read;
}

/** cti odpoved
 */
static void readreply(mcrawler_url *u) {
	const ssize_t t = try_read(u);
	assert(t >= MCURL_IO_WRITE);
	if (t == MCURL_IO_READ) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
		return;
	}
	if (t == MCURL_IO_WRITE) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		return;
	}
	if (t >= 0) {
		u->timing.lastread = get_time_int();
	}
	if (t > 0 && !u->timing.firstbyte) {
		u->timing.firstbyte = u->timing.lastread;
	}

	debugf("[%d] Read %zd bytes; buf_len = %zd; chunked = %d\n", u->index, t, buf_len(u), !!u->chunked);

	unsigned char *head_end, *buf = buf_p(u);
	if (u->headlen == 0 && (head_end = find_head_end(buf, buf_len(u)))) {
		debugf("[%d] Found head end\n", u->index);
		u->headlen = head_end - buf;
		parsehead(buf, u->headlen, &u->status, header_cb, (void *)u, u->index);
	}
	
	// u->chunked is set in parsehead()
	if (t > 0 && u->chunked) {
		while (eatchunk(u));
	}
	
	if (t == MCURL_IO_EOF || t == MCURL_IO_ERROR || (u->has_contentlen && buf_len(u) >= u->headlen + u->contentlen)) {
		if (t == MCURL_IO_ERROR) {
			set_atomic_int(&u->state, MCURL_S_ERROR);
		} else if (get_atomic_int(&u->state) != MCURL_S_ERROR) {
			set_atomic_int(&u->state, MCURL_S_DOWNLOADED);
			debugf("[%d] Downloaded.\n",u->index);
		}
		// FIXME: Is it correct to close the connection before we read the whole reply from the server?
	} else {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
	}
}

#ifdef HAVE_LIBNGHTTP2
static void readreply_http2(mcrawler_url *u) {
	unsigned char buf[100 * 1024];
	const ssize_t t = ((mcrawler_url_func *)u->f)->read(u, buf, 100 * 1024, (char *)&u->error_msg);
	assert(t >= MCURL_IO_WRITE);
	if (t == MCURL_IO_READ) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
		return;
	}
	if (t == MCURL_IO_WRITE) {
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		return;
	}
	http2_session_data *session_data = (http2_session_data *)u->http2_session;

	if (t >= 0) {
		if (u->timing.firstbyte) {
			u->timing.lastread = get_time_int();
		}

		ssize_t readlen = nghttp2_session_mem_recv(session_data->session, buf, t);
		debugf("[%d] Read %zd bytes from socket %d\n", u->index, readlen, u->sockfd);
		if (readlen < 0) {
			debugf("[%d] HTTP2 read error: %s\n", u->index, nghttp2_strerror((int)readlen));
			sprintf(u->error_msg, "HTTP2 read error (%.250s)", nghttp2_strerror((int)readlen));
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		}
	}

	if (t == MCURL_IO_ERROR) {
		set_atomic_int(&u->state, MCURL_S_ERROR);
	} else {
		if (http2_session_send(u)) {
			set_atomic_int(&u->state, MCURL_S_ERROR);
			return;
		} else {
			if (t == MCURL_IO_EOF && nghttp2_session_want_read(session_data->session) == 0 &&
					nghttp2_session_want_write(session_data->session) == 0) {

				set_atomic_int(&u->state, MCURL_S_DOWNLOADED);
			} else {
				set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ | 1<<MCURL_RW_WANT_WRITE);
			}
		}
	}
}
#endif

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede systemovy select nad vsemi streamy
 */
static void selectall(mcrawler_url **urls) {
	fd_set set;
	fd_set writeset;
	struct timeval timeout;	
	mcrawler_url *url;
	
	FD_ZERO (&set);
	FD_ZERO (&writeset);

	int wantio = 0;
	
	timeout.tv_sec = 0;
	timeout.tv_usec = 20000;
	
	for (int i = 0; urls[i] != NULL; i++) {
		url = urls[i];
		const int state = get_atomic_int(&url->state);
		const int rw = get_atomic_int(&url->rw);
		debugf("[%d] select.state = [%s][%d]\n", url->index, mcrawler_state_to_s(state), want_io(state, rw));
		if (!want_io(state, rw)) {
			continue;
		}
		wantio = 1;
		if(rw & 1<<MCURL_RW_WANT_READ) {
			FD_SET(url->sockfd, &set);
		}
		
		if(rw & 1<<MCURL_RW_WANT_WRITE) {
			FD_SET(url->sockfd, &writeset);
		}
	}
	if (!wantio) {
		// nothing can happen
		return;
	}
	switch (select(FD_SETSIZE, &set, &writeset, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "select failed: %m\n");
			return;
		case 0:
			return; // nothing
	}
	for (int i = 0; urls[i] != NULL; i++) {
		url = urls[i];
		const int rw = !!FD_ISSET(url->sockfd, &set) << MCURL_RW_READY_READ | !!FD_ISSET(url->sockfd, &writeset) << MCURL_RW_READY_WRITE;
		if (rw) {
			set_atomic_int(&url->rw, rw);
		} else {
			// Do nothing, this way you preserve the original value !!
		}
	}
}


/** provede jeden krok pro dane url
 */
static void goone(mcrawler_url *u, const mcrawler_settings *settings, mcrawler_url_callback callback, void *callback_arg) {
	const int state = get_atomic_int(&u->state);
	const int rw = get_atomic_int(&u->rw);
	int timeout;

	debugf("[%d] state = [%s][%d]\n", u->index, mcrawler_state_to_s(state), want_io(state, rw));

	if (want_io(state, rw)) {
		timeout = (settings->timeout > 6 ? settings->timeout / 3 : 2) * 1000;

		switch(state) {
		case MCURL_S_CONNECT:
			if (u->addr->next && get_time_int() - u->timing.connectionstart > timeout) {
				mcrawler_addr *next = u->addr->next;
				free(u->addr);
				u->addr = next;
				debugf("[%d] Connection timeout (%d ms), trying another ip\n", u->index, timeout);
				close(u->sockfd);
				u->sockfd = 0;
				set_atomic_int(&u->state, MCURL_S_GOTIP);
			}
			break;
		case MCURL_S_HANDSHAKE:
#ifdef HAVE_LIBSSL
			if (get_time_int() - u->timing.handshakestart > timeout) {
				// we retry handshake with another protocol
				if (lower_ssl_protocol(u) == 0) {
					debugf("[%d] SSL handshake timeout (%d ms), closing connection\n", u->index, timeout);
					close_conn(u);
					set_atomic_int(&u->state, MCURL_S_GOTIP);
				}
			}
#endif
			break;
		}

		return;  // select will look after this state
	}
	check_io(state, rw); // Checks that when we need some io, then the socket is in readable/writeable state

	const int time = get_time_int();
	mcrawler_url_func *f = u->f;

	switch(state) {  
	case MCURL_S_JUSTBORN:
		f->parse_url(u);
		break;

	case MCURL_S_PARSEDURL:
		f->launch_dns(u);
		break;
  
	case MCURL_S_INDNS:
		f->check_dns(u);
		break;

	case MCURL_S_GOTIP:
		if (test_free_channel(u->addr->ip, settings->delay, u->prev_addr && !memcmp(u->addr->ip, u->prev_addr->ip, sizeof(u->addr->ip)))) {
			if (!u->timing.connectionstart) u->timing.connectionstart = time;
			if (!u->downstart) u->downstart = time;
			f->open_socket(u);
		}
		break;
  
	case MCURL_S_CONNECT:
		f->connect_socket(u);
		break;

	case MCURL_S_HANDSHAKE:
		u->timing.handshakestart = time;
		f->handshake(u);
		break;

	case MCURL_S_GENREQUEST:
		prepare_for_request(u);
		f->gen_request(u);
		break;

	case MCURL_S_SENDREQUEST:
		if (!u->timing.requeststart) u->timing.requeststart = time;
		f->send_request(u);
		break;

	case MCURL_S_RECVREPLY:
		if (!u->timing.requestend) u->timing.requestend = time;
		f->recv_reply(u);
		break;

	case MCURL_S_DOWNLOADED:
		if (cont(u) != 0) {
			close_conn(u);
			finish(u, callback, callback_arg);
		}
		break;
  
	case MCURL_S_ERROR:
		assert(u->status < 0);
		close_conn(u);
		finish(u, callback, callback_arg);
		break;
	}

	const int stateAfter = get_atomic_int(&u->state);
	if (stateAfter == MCURL_S_ERROR) {
		u->status = state - stateAfter;
	}

#ifdef HAVE_DEBUG
	if (debug) {
		const int duration = get_time_int() - time;
		if(duration > 200) {
			debugf("[%d] State %d (->%d) took too long (%d ms)\n", u->index, state, get_atomic_int(&u->state), duration);
		}
	}
#endif
}

/** vrati 1 pokud je dobre ukoncit se predcasne
 */
static int exitprematurely(mcrawler_url **urls, int time) {
	int notdone = 0, lastread = 0, i;
	mcrawler_url *url;
	
	for (i = 0; urls[i] != NULL; i++) {
		url = urls[i];
		const int url_state = get_atomic_int(&url->state);
		if(url_state<MCURL_S_DONE) {
			notdone++;
		}
		if(url->timing.lastread > lastread) {
			lastread = url->timing.lastread;
		}
	}
	
	debugf("[-] impatient: %d not done, last read at %d ms (now %d)\n",notdone,lastread,time);
	
	if (i >= 5 && notdone == 1 && (time-lastread) > 400) {
		debugf("[-] Forcing premature end 1!\n");
		return 1;
	}
	if (i >= 20 && notdone <= 2 && (time-lastread) > 400) {
		debugf("[-] Forcing premature end 2!\n");
		return 1;
	}
	
	return 0;
}

/** vypise obsah vsech dosud neuzavrenych streamu
 */
static void outputpartial(mcrawler_url **urls, mcrawler_url_callback callback, void *callback_arg) {
	mcrawler_url *url;

	for (int i = 0; urls[i] != NULL; i++) {
		url = urls[i];
		const int url_state = get_atomic_int(&url->state);
		if(url_state < MCURL_S_DONE) {
			close_conn(url);
			finish(url, callback, callback_arg);
		}
	}
}

mcrawler_url_func get_url_callbacks() {
	return (mcrawler_url_func) {
		read:plain_read,
		write:plain_write,
		parse_url:parseurl,
		launch_dns:launchdns,
		check_dns:checkdns,
		open_socket:opensocket,
		connect_socket:connectsocket,
		handshake:empty_handshake,
		gen_request:genrequest,
		send_request:sendrequest,
		recv_reply:readreply,
	};
}

/**
 * hlavni smycka
 */
void mcrawler_go(mcrawler_url **urls, const mcrawler_settings *settings, mcrawler_url_callback callback, void *callback_arg) {
	int done;
	int change;
	mcrawler_url *url;

	init_birth();

#ifdef HAVE_DEBUG
	debug = settings->debug;
#endif

	debugf("Go: timeout %d; delay %d\n", settings->timeout, settings->delay);

	do {
		done = 1;
		change = 0;
		
		selectall(urls);
		for (int i = 0; urls[i] != NULL; i++) {
			url = urls[i];
			const int state = get_atomic_int(&url->state);
			if(state < MCURL_S_DONE) {
				goone(url, settings, callback, callback_arg);
				done = 0;
			}
			// url->state can change inside goone
			if(state != get_atomic_int(&url->state)) {
				change = 1;
			}
		}

		const int t = get_time_int();
		if(t > settings->timeout*1000) {
			debugf("Timeout (%d ms elapsed). The end.\n", t);
			outputpartial(urls, callback, callback_arg);
			break;
		}
		if(!change && !done) {
			if (settings->impatient && t >= settings->timeout*1000-1000) {
				done = exitprematurely(urls, t);
			}
		}
	} while(!done);
	
	if(done) {
		debugf("All successful. Took %d ms.\n", get_time_int());
	}
}
