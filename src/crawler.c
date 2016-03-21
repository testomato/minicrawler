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
#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>
# ifndef SSL_OP_NO_TLSv1_2
#  error "please install OpenSSL 1.0.1"
# endif
# include <openssl/md5.h>
# include <openssl/err.h>
#endif

#include "url/minicrawler-urlparser.h"
#include "h/string.h"
#include "h/proto.h"
#include "h/digcalc.h"

int debug = 0;

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

#ifdef HAVE_LIBSSL
/**
 * Sets lower TSL/SSL protocol
 */
static int lower_ssl_protocol(mcrawler_url *u) {
	const long opts = SSL_get_options(u->ssl);

	if (opts & SSL_OP_NO_TLSv1) {
		return -1;
	}

	if (opts & SSL_OP_NO_TLSv1_1) {
		u->ssl_options |= SSL_OP_NO_TLSv1;
		debugf("[%d] Switch to SSLv3\n", u->index);
	} else if (opts & SSL_OP_NO_TLSv1_2) {
		u->ssl_options |= SSL_OP_NO_TLSv1_1;
		debugf("[%d] Switch to TLSv1.0\n", u->index);
	} else {
		u->ssl_options |= SSL_OP_NO_TLSv1_2;
		debugf("[%d] Switch to TLSv1.1\n", u->index);
	}
	return 0;
}

/** Impement handshake over SSL non-blocking socket.
We may switch between need read/need write for several times.
SSL is blackbox this time for us.
*/
static void sec_handshake(mcrawler_url *u) {
	assert(u->ssl);

	if (!u->timing.sslstart) u->timing.sslstart = get_time_int();

	const int t = SSL_connect(u->ssl);
    if (t == 1) {
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

	// else SSL_ERROR_SSL = protocol error
	debugf("[%d] SSL protocol error (in handshake): \n", u->index);
	unsigned long e, last_e = 0;
	while ((e = ERR_get_error())) {
		debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
		last_e = e;
	}

	if (lower_ssl_protocol(u) < 0) {
		sprintf(u->error_msg, "SSL protocol error during handshake");
		if (last_e) {
			sprintf(u->error_msg + strlen(u->error_msg), " (%.200s)", ERR_reason_error_string(last_e));
		}
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}
	else {
		// zkusíme ještě jednou
		SSL_shutdown(u->ssl);
		SSL_free(u->ssl);
		u->ssl = NULL;
		close(u->sockfd);
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
	if (status != ARES_SUCCESS) {
		if (status == ARES_ENODATA && u->addrtype == AF_INET) {
			// zkusíme ještě IPv6
			u->addrtype = AF_INET6;
			debugf("[%d] gethostbyname error: no data -> switch to ipv6\n", u->index);
			set_atomic_int(&u->state, MCURL_S_PARSEDURL);
			return;
		}
		debugf("[%d] gethostbyname error: %d: %s (%d timeouts)\n", u->index, status, ares_strerror(status), timeouts);
		sprintf(u->error_msg, "%.255s", ares_strerror(status));
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

	debugf("[%d] Resolving %s ended => %s", u->index, u->host, hostent->h_name);

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
static int set_new_url(mcrawler_url *u, char *rawurl, mcrawler_parser_url *base) {
	mcrawler_parser_url *url = (mcrawler_parser_url *)malloc(sizeof(mcrawler_parser_url));

	if (mcrawler_parser_parse(url, rawurl, base) != MCRAWLER_PARSER_SUCCESS) {
		debugf("[%d] error: url='%s' failed to parse\n", u->index, rawurl);
		sprintf(u->error_msg, "Failed to parse URL");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		mcrawler_parser_free_url(url);
		free(url);
		return 0;
	}

	if (!url->scheme[0]) {
		debugf("[%d] error: url='%s' has no scheme\n", u->index, rawurl);
		sprintf(u->error_msg, "URL has no scheme");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		mcrawler_parser_free_url(url);
		free(url);
		return 0;
	}
	SAFE_STRCPY(u->proto, url->scheme);

	if (check_proto(u) == -1) {
		mcrawler_parser_free_url(url);
		free(url);
		return 0;
	}

	if (url->host == NULL || url->non_relative) {
		debugf("[%d] error: url='%s' has no host\n", u->index, rawurl);
		sprintf(u->error_msg, "URL has no host");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		mcrawler_parser_free_url(url);
		free(url);
		return 0;
	}

	// serialized host in url->host->domain
	SAFE_STRCPY(u->host, url->host->domain);

	if (url->port) {
		u->port = url->port;
	} else {
		u->port = parse_proto(u->proto);
	}

	// recompose path + query
	if (u->path != NULL) free(u->path);
	u->path = mcrawler_parser_serialize_path_and_query(url);

	debugf("[%d] proto='%s' host='%s' port=%d path='%s'\n", u->index, u->proto, u->host, u->port, u->path);

	if (url->host->type == MCRAWLER_PARSER_HOST_IPV4) {
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
	} else if (url->host->type == MCRAWLER_PARSER_HOST_IPV6) {
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
		mcrawler_parser_free_url(u->uri);
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

/**
 * Check syntax of domain name
 * @see https://tools.ietf.org/html/rfc1034#section-3.5
 * @see http://tools.ietf.org/html/rfc1123#page-13
 */
static int checkDomainNameSyntax(const char *domain) {
	const char *p, *s = domain;

	while (*(p = s++) != 0) {
		if (*p == '-' && (p == domain || *(p-1) == '.' || *(p+1) == 0 || *(p+1) == '.')) {
			// dash can be only in the middle of a label
			return 0;
		} else if (*p == '.' || *p == '-' || (*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')) {
			//ok
		} else {
			return 0;
		}
	}
	return 1;
}

/** spusti preklad pres ares
 */
static void launchdns(mcrawler_url *u) {
	int t;

	debugf("[%d] Resolving %s starts\n", u->index, u->host);

	// check syntax
	if (!checkDomainNameSyntax(u->host)) {
		debugf("[%d] invalid host!)\n", u->index);
		sprintf(u->error_msg, "Invalid domain name");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}

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
	ares_gethostbyname(u->aresch, u->host, u->addrtype, (ares_host_callback)&dnscallback, u);
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
		close(u->sockfd);
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
		close(u->sockfd);
		return;
	}

	set_atomic_int(&u->state, MCURL_S_HANDSHAKE);
	set_atomic_int(&u->rw, 1<< MCURL_RW_READY_READ | 1<<MCURL_RW_READY_WRITE);
}

/** Allocate ssl objects for ssl connection. Do nothing for plain connection.
*/
static int maybe_create_ssl(mcrawler_url *u) {
#ifdef HAVE_LIBSSL
	if (0 != strcmp(u->proto, "https")) {
		return 1;
	}

	SSL *ssl = SSL_new(mossad());
	BIO *sbio = BIO_new_socket(u->sockfd, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	SSL_set_options(ssl, u->ssl_options);
	SSL_set_tlsext_host_name(ssl, u->host);

	u->ssl = ssl;
#endif
	return 1;
}

/** uz znam IP, otevri socket
 */
static void opensocket(mcrawler_url *u)
{
	int flags;
	struct sockaddr_storage addr;
	socklen_t addrlen;

	u->sockfd = socket(u->addr->type, SOCK_STREAM, 0);
	flags = fcntl(u->sockfd, F_GETFL,0);              // Get socket flags
	fcntl(u->sockfd, F_SETFL, flags | O_NONBLOCK);   // Add non-blocking flag	

	if (debug) {
		char straddr[INET6_ADDRSTRLEN];
		inet_ntop(u->addr->type, u->addr->ip, straddr, sizeof(straddr));
		debugf("[%d] connecting to ip: %s; %d, port: %i (socket %d)\n", u->index, straddr, get_time_slot(u->addr->ip), u->port, u->sockfd);
	}

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
	if (!maybe_create_ssl(u)) {
		debugf("%d: cannot create ssl session :-(\n", u->index);
		sprintf(u->error_msg, "Cannot create SSL session");
		set_atomic_int(&u->state, MCURL_S_ERROR);
	}
	if(t) {
		if(errno == EINPROGRESS) {
			set_atomic_int(&u->state, MCURL_S_CONNECT);
			set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE);
		}
		else {
			debugf("%d: connect failed (%d, %s)\n", u->index, errno, strerror(errno));
			sprintf(u->error_msg, "Failed to connect to host (%.200m)");
			set_atomic_int(&u->state, MCURL_S_ERROR);
		}
	} else {
		set_atomic_int(&u->state, MCURL_S_HANDSHAKE);
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_WRITE | 1<<MCURL_RW_WANT_WRITE);
	}
}

static void remove_expired_cookies(mcrawler_url *u);

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
	const char defaultagent[] = "minicrawler/%s";

	remove_expired_cookies(u);
	size_t cookies_size = 0;
	for (int i = 0; i < u->cookiecnt; i++) cookies_size += 3 + strlen(u->cookies[i].name) + strlen(u->cookies[i].value);

	if (!u->method[0]) {
		strcpy(u->method, "GET");
	}

	free(u->request);
	u->request = malloc(
			strlen(reqfmt) + strlen(u->method) + strlen(u->path) + 2 + // method URL HTTP/1.1\n
			strlen(hostheader) + strlen(u->host) + 6 + 2 + // Host: %s(:port)\n
			strlen(acceptheader) + 2 + // Accept: */*\n
			(u->authorization != NULL ? strlen(authorizationheader) + strlen(u->authorization) + 2 : 0) + // Authorization: ...\n
			strlen(useragentheader) + (u->customagent[0] ? strlen(u->customagent) : strlen(defaultagent) + 8) + 2 + // User-Agent: %s\n
			strlen(cookieheader) + cookies_size + 2 + // Cookie: %s; %s...\n
			strlen(u->customheader) + 2 +
			(u->options & 1<<MCURL_OPT_GZIP ? strlen(gzipheader) + 2 : 0) + // Accept-Encoding: gzip\n
			(u->post != NULL ? strlen(contentlengthheader) + 6 + 2 + strlen(contenttypeheader) + 2 : 0) + // Content-Length: %d\nContent-Type: ...\n
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
	const int port = parse_proto(u->proto);
	if (port != u->port) {
		s = sprintf(r, ":%d", u->port);
		if (s > 0) r += s;
	}
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

	// Uset-Agent
	r = stpcpy(r, useragentheader);
	if (u->customagent[0]) {
		r = stpcpy(r + strlen(r), u->customagent);
	} else {
		s = sprintf(r + strlen(r), defaultagent, VERSION);
		if (s > 0) r += s;
	}
	r = stpcpy(r, "\r\n");

	// Cookie
	for (int t = 0; t < u->cookiecnt; t++) {
		char *p, c;
		// see http://tools.ietf.org/html/rfc6265 section 5.4
		if (
				((u->cookies[t].host_only == 1 && strcasecmp(u->host, u->cookies[t].domain) == 0) || // The cookie's host-only-flag is true and the canonicalized request-host is identical to the cookie's domain.
					(u->cookies[t].host_only == 0 && (p = strcasestr(u->host, u->cookies[t].domain)) && *(p+strlen(u->cookies[t].domain)) == 0)) && //  Or: The cookie's host-only-flag is false and the canonicalized request-host domain-matches the cookie's domain.
				(!strncmp(u->path, u->cookies[t].path, strlen(u->cookies[t].path)) && (u->cookies[t].path[strlen(u->cookies[t].path)-1] == '/' || (c = u->path[strlen(u->cookies[t].path)]) == '/' || c == '?' || c == 0)) && // The request-uri's path path-matches the cookie's path.
				(u->cookies[t].secure == 0 || strcmp(u->proto, "https") == 0) //  If the cookie's secure-only-flag is true, then the request- uri's scheme must denote a "secure" protocol
		) {
			if (!r[0]) {
				strcpy(r, cookieheader);
				sprintf(r + strlen(r), "%s=%s", u->cookies[t].name, u->cookies[t].value);
			} else {
				sprintf(r + strlen(r), "; %s=%s", u->cookies[t].name, u->cookies[t].value);
			}
		}
	}
	if (r[0]) {
		strcpy(r + strlen(r), "\r\n");
	}
	r += strlen(r);

	// Custom header
	if (u->customheader[0]) {
		r = stpcpy(r, u->customheader);
		r = stpcpy(r, "\r\n");
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
		r = stpcpy(r, contenttypeheader);
		r = stpcpy(r, "\r\n");
	}

	// end of header
	r = stpcpy(r, "\r\n");

	// body
	if (u->post != NULL) {
		r = mempcpy(r, u->post, u->postlen);
	}
	*r = 0;

	debugf("[%d] Request: [%s]", u->index, u->request);
	u->request_len = strlen((char *)u->request);;
	u->request_it = 0;

	set_atomic_int(&u->state, MCURL_S_SENDREQUEST);
	set_atomic_int(&u->rw, 1<<MCURL_RW_READY_WRITE);
}

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

/** sezere to radku tam, kde ceka informaci o delce chunku
 *  jedinou vyjimkou je, kdyz tam najde 0, tehdy posune i contentlen, aby dal vedet, ze jsme na konci
 *  @return 0 je ok, -1 pokud tam neni velikost chunku zapsana cela
 */
static int eatchunked(mcrawler_url *u) {
	int t,i;
	unsigned char hex[10];
	int size;
	int movestart;

	// čte velikost chunku
	for (t=u->nextchunkedpos, i=0; u->buf[t] != '\r' && u->buf[t] != '\n' && t < u->bufp; t++) {
		if (i < 9) {
			hex[i++] = u->buf[t];
		}
	}
	t += 2; // eat CRLF
	if (t > u->bufp) {
		debugf("[%d] Missing end of chunksize!", u->index);
		return -1;
	}

	assert(i > 0);
	hex[i] = 0;
	size = strtol((char *)hex, NULL, 16);

	debugf("[%d] Chunksize at %d (buffer %d): '%s' (=%d)\n", u->index, u->nextchunkedpos, u->bufp, hex, size);

	movestart = u->nextchunkedpos;
	if (u->nextchunkedpos != u->headlen) {
		movestart -= 2; // CRLF before chunksize
	}
	assert(t <= u->bufp);
	memmove(u->buf+movestart, u->buf+t, u->bufp-t);		// cely zbytek posun
	u->bufp -= (t-movestart);					// ukazatel taky
	
	u->nextchunkedpos = movestart+size+2;			// 2 more for CRLF
	
	if (size == 0) {
		// a to je konec, pratele! ... taaadydaaadydaaa!
		debugf("[%d] Chunksize=0 (end)\n", u->index);
		// zbytek odpovedi zahodime
		u->bufp = movestart;
		u->contentlen = movestart - u->headlen;
	}
	
	return 0;
}

/** 
 * zapíše si do pole novou cookie (pokud ji tam ještě nemá; pokud má, tak ji nahradí)
 * see http://tools.ietf.org/html/rfc6265 section 5.2 and 5.3
 */
static void setcookie(mcrawler_url *u, char *str) {
	mcrawler_cookie cookie;
	struct nv attributes[10];
	int att_len = 0;
	char *namevalue, *attributestr;
	char *p, *q;
	int i;

	memset(&cookie, 0, sizeof(mcrawler_cookie));
	cookie.expires = -1;
	memset(attributes, 0, sizeof(attributes));

	namevalue = str;
	p = strchrnul(str, ';');
	if (*p == ';') {
		*p = 0;
		attributestr = p + 1;
	} else {
		attributestr = p; // attribute string is empty
	}

	// parse name and value
	if ((p = strchr(namevalue, '=')) == NULL) {
		debugf("[%d] Cookie string '%s' lacks a '=' character\n", u->index, namevalue);
		goto fail;
	}
	*p = 0; p++;

	cookie.name = malloc(strlen(namevalue) + 1);
	cookie.value = malloc(strlen(p) + 1);
	strcpy(cookie.name, namevalue);
	strcpy(cookie.value, p);

	trim(cookie.name);
	trim(cookie.value);

	if (strlen(cookie.name) == 0) {
		debugf("[%d] Cookie string '%s' has empty name\n", u->index, namevalue);
		goto fail;
	}
	
	// parse cookie attributes
	struct nv *attr;
	p = attributestr;
	while (*p) {
		if (att_len > 9) {
			debugf("[%d] Cookie string '%s%s' has more 10 attributes (not enough memory)... skipping the rest\n", u->index, namevalue, attributestr);
			break;
		}

		attr = attributes + att_len++;

		attr->name = p;
		p = strchrnul(p, ';');
		if (*p) {
			*p = 0; p++;
		}
		if ((q = strchr(attr->name, '='))) {
			*q = 0;
			attr->value = q + 1;
		} else { // value is empty
			attr->value = attr->name + strlen(attr->name);
		}
		trim(attr->name);
		trim(attr->value);
	}

	// process attributes
	for (i = 0; i < att_len; i++) {
		attr = attributes + i;

		// The Expires Attribute
		if (!strcasecmp(attr->name, "Expires")) {
			time_t expires = parse_cookie_date(attr->value);
			if (expires < 0) {
				debugf("[%d] Failed to parse cookie date from '%s'\n", u->index, attr->value);
			} else {
				cookie.expires = expires;
			}

			continue;
		}

		// The Max-Age Attribute
		if (!strcasecmp(attr->name, "Max-Age")) {
			char *p;
			int max_age = strtol(attr->value, &p, 10);
			if (*p != 0) {
				debugf("[%d] Invalid Max-Age attribute '%s'\n", u->index, attr->value);
				continue;
			}
			if (max_age <= 0) {
				cookie.expires = (time_t)(0);
			} else {
				cookie.expires = time(NULL) + (time_t)max_age;
			}

			continue;
		}

		// The Domain Attribute
		if (!strcasecmp(attr->name, "Domain")) {
			store_cookie_domain(attr, &cookie);

			continue;
		}

		// The Path Attribute
		if (!strcasecmp(attr->name, "Path")) {
			if (cookie.path) {
				free(cookie.path);
				cookie.path = NULL;
			}
			if (attr->value[0] == '/') {
				cookie.path = malloc(strlen(attr->value) + 1);
				strcpy(cookie.path, attr->value);
			}

			continue;
		}

		// The Secure Attribute
		if (!strcasecmp(attr->name, "Secure")) {
			cookie.secure = 1;

			continue;
		}
	}

	if (!cookie.domain) {
		cookie.domain = malloc(strlen(u->host) +1);
		strcpy(cookie.domain, u->host);
		cookie.host_only = 1;
	} else {
		// match request host
		if ((p = strcasestr(u->host, cookie.domain)) == NULL || *(p+strlen(cookie.domain)) != 0) {
			debugf("[%d] Domain '%s' in cookie string does not match request host '%s'... ignoring\n", u->index, cookie.domain, u->host);
			goto fail;
		}
	}

	if (cookie.expires < 0) {
		cookie.expires = LONG_MAX;
	}

	if (!cookie.path) {
		// default-path, see http://tools.ietf.org/html/rfc6265#section-5.1.4
		char *p = strchrnul(u->path, '?');
		assert(p > u->path);
		cookie.path = malloc(p - u->path + 1);
		*(char *)mempcpy(cookie.path, u->path, p - u->path) = 0;
		p = strrchr(cookie.path, '/');
		if (p > cookie.path) {
			*p = 0;
		} else {
			*(p + 1) = 0;
		}
	}


	int t;
	for (t = 0; t<u->cookiecnt; ++t) {
		if(!strcasecmp(cookie.name,u->cookies[t].name) && !strcasecmp(cookie.domain,u->cookies[t].domain) && !strcmp(cookie.path,u->cookies[t].path)) {
			break;
		}
	}

	if (t<u->cookiecnt) { // už tam byla
		mcrawler_free_cookie(&u->cookies[t]);
		debugf("[%d] Changed cookie\n",u->index);
	} else {
		u->cookiecnt++;
	}

	if (t < sizeof(u->cookies)/sizeof(*u->cookies)) {
		u->cookies[t] = cookie;
		debugf("[%d] Storing cookie #%d: name='%s', value='%s', domain='%s', path='%s', host_only=%d, secure=%d\n",u->index,t,cookie.name,cookie.value,cookie.domain,cookie.path,cookie.host_only,cookie.secure);
		return;
	} else {
		u->cookiecnt--;
		debugf("[%d] Not enough memory for storing cookies\n",u->index);
	}

fail:
	mcrawler_free_cookie(&cookie);
}

// The user agent MUST evict all expired cookies from the cookie store
// if, at any time, an expired cookie exists in the cookie store.
static void remove_expired_cookies(mcrawler_url *u) {
	time_t tim = time(NULL);
	for (int t = 0; t < u->cookiecnt;) {
		if (tim > u->cookies[t].expires) {
			debugf("[%d] Cookie %s expired. Deleting\n", u->index, u->cookies[t].name);
			mcrawler_free_cookie(&u->cookies[t]);
			u->cookiecnt--;
			if (t < u->cookiecnt) {
				memmove(&u->cookies[t], &u->cookies[t+1], (u->cookiecnt-t)*sizeof(*u->cookies));
			}
		} else {
			t++;
		}
	}
}


/**
 * http://tools.ietf.org/html/rfc2617#section-2
 */
static void basicauth(mcrawler_url *u, struct challenge *ch) {
	*strchrnul(u->username, ':') = 0; // dobledot not allowed in unserid

	char userpass[strlen(u->username) + strlen(u->password) + 1 + 1]; // one for : and one for 0
	sprintf(userpass, "%s:%s", u->username, u->password);
	u->authorization = malloc(base64_len(strlen(userpass)) + 1 + 6); // 6 for "Basic"
	strcpy(u->authorization, "Basic ");
	base64(u->authorization + 6, userpass, strlen(userpass));
}

#ifdef HAVE_LIBSSL
/**
 * http://tools.ietf.org/html/rfc2617#section-3
 */
static void digestauth(mcrawler_url *u, struct challenge *ch) {
	char *nonce = NULL, *alg = NULL, *qop = NULL, *opaq = NULL;
	char nonce_count[] = "00000001";
	char cnonce[] = "97jGn565ggO9jsp";
	HASHHEX HA1, HEntity, response;
	size_t authlen;

	for (int i = 0; i < 10 && ch->params[i].name != NULL; i++) {
		if (!strcmp("nonce", ch->params[i].name)) nonce = ch->params[i].value;
		if (!strcmp("algorithm", ch->params[i].name)) alg = ch->params[i].value;
		if (!strcmp("qop", ch->params[i].name)) {
			qop = ch->params[i].value;
			// take the first value
			*strchrnul(qop, ',') = 0;
		}
		if (!strcmp("opaque", ch->params[i].name)) opaq = ch->params[i].value;
	}

	if (!nonce) {
		debugf("[%d] digest auth error: missing nonce\n", u->index);
		return;
	}
	if (!alg) alg = strdup("MD5");
	if (!qop) qop = strdup("");

	*strchrnul(u->username, ':') = 0; // dobledot not allowed in unserid

	if (!strcasecmp("auth-int", qop)) {
		MD5_CTX context;
		MD5_Init(&context);
		MD5_Update(&context, u->buf + u->headlen, u->bufp - u->headlen);
		MD5_Final(HEntity, &context);
	}

	DigestCalcHA1(alg, u->username, ch->realm, u->password, nonce, cnonce, HA1);
	DigestCalcResponse(HA1, nonce, nonce_count, cnonce, qop, u->method, u->path, HEntity, response);

	if (*qop) {
		char authformat[] = "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=%s, cnonce=\"%s\", qop=%s, nc=%s";
		authlen = strlen(authformat) + strlen(u->username) + strlen(ch->realm) + strlen(nonce) + strlen(u->path) + HASHHEXLEN + strlen(alg) + strlen(cnonce) + strlen(qop) + strlen(nonce_count);
		u->authorization = malloc(authlen + 1);
		sprintf(u->authorization, authformat, u->username, ch->realm, nonce, u->path, response, alg, cnonce, qop, nonce_count);
	} else {
		char authformat[] = "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=%s";
		authlen = strlen(authformat) + strlen(u->username) + strlen(ch->realm) + strlen(nonce) + strlen(u->path) + HASHHEXLEN + strlen(alg);
		u->authorization = malloc(authlen + 1);
		sprintf(u->authorization, authformat, u->username, ch->realm, nonce, u->path, response, alg);
	}
	if (opaq) {
		char opaqfmt[] = ", opaque=\"%s\"";
		u->authorization = realloc(u->authorization, authlen + strlen(opaq) + strlen(opaqfmt) + 1);
		sprintf(u->authorization + authlen, opaqfmt, opaq);
	}
}
#endif

/**
 * Z hlavičky WWW-Authenitcate vyparsuje právě jednu neprázndou challenge
 */
static void parse_single_challenge(mcrawler_url *u, char **pp, struct challenge *ch) {
	char *param, *value, *p = *pp;
	int params_len = 0;

	while (*p == ',') p++; // skip empty challenges

	ch->scheme = p;
	p = strchr(p, ' ');
	if (!p) {
		debugf("[%d] auth challenge '%s' should contain at least realm\n", u->index, *pp);
		*pp = p;
		return;
	}
	*p = 0; p++;

	while (1) {
		while (*p == ' ' || *p == '\t' || *p == ',') p++;
		if (!*p) break;

		param = p;
		p = strpbrk(p, " =");
		if (!p) {
			debugf("[%d] error parsing auth challenge: scheme should be terminated by space and param by '=' ('%s')'\n", u->index, param);
			break;
		}
		if (*p == ' ') { // start of a new challenge
			*pp = param;
			return;
		}
		*p = 0; p++;
		if (*p == '"') { // quoted string
			value = p + 1;
			while (*(++p) && *p != '"') {
				if (*p == '\\') { // quoted pair
					memmove(p, p+1, strlen(p));
				}
			}
			if (!*p) {
				debugf("[%d] error parsing auth challenge: unterminated quoted string '%s'\n", u->index, value);
				break;
			}
		} else {
			value = p;
			p = strpbrk(p, " \t,");
			if (p == NULL) {
				p = value + strlen(value);
			}
		}
		if (*p) {
			*p = 0; p++;
		}

		if (!strcasecmp(param, "realm")) {
			ch->realm = value;
		} else {
			if (params_len > 9) {
				debugf("[%d] error parsing auth challenge: not enough memory for params\n", u->index);
				break;
			} else {
				ch->params[params_len].name = param;
				ch->params[params_len].value = value;
				params_len++;
			}
		}
	}

	*pp = p;
}

/**
 * HTTP Authentication
 * @see http://tools.ietf.org/html/rfc2617
 */
static void parse_authchallenge(mcrawler_url *u, char *challenge) {
	struct challenge challenges[3];
	int i = 0;

	char *p = challenge;
	memset(challenges, 0, sizeof(challenges));

	while (p && *p) {
		if (i < 3) {
			parse_single_challenge(u, &p, &challenges[i]);
			i++;
		} else {
			debugf("[%d] error parsing auth challenge: not enough memory for challenges\n", u->index);
			break;
		}
	}

	if (u->authorization) {
		free(u->authorization);
		u->authorization = NULL;
	}

	int can_basic = -1, can_digest = -1;

	for (i = 0; i < 3 && challenges[i].scheme != NULL; i++) {
		if (challenges[i].realm == NULL) {
			debugf("[%d] missing realm for auth scheme %s\n", u->index, challenges[i].scheme);
		} else if (!strcasecmp(challenges[i].scheme, "basic")) {
			can_basic = i;
#ifdef HAVE_LIBSSL
		} else if (!strcasecmp(challenges[i].scheme, "digest")) {
			can_digest = i;
#endif
		} else {
			debugf("[%d] unsupported auth scheme '%s'\n", u->index, challenges[i].scheme);
		}
	}

	if (can_digest > -1) {
		digestauth(u, &challenges[can_digest]);
	} else if (can_basic > -1) {
		basicauth(u, &challenges[can_basic]);
	} else {
		sprintf(u->error_msg, "No supported HTTP authentication scheme");
	}
}

/**  Tries to find the end of a head in the server's reply.
        It works in a way that it finds a sequence of characters of the form: m{\r*\n\r*\n} */
static unsigned char *find_head_end(mcrawler_url *u) {
	unsigned char *s = u->buf;
	const size_t len = u->bufp > 0 ? (size_t)u->bufp : 0;
	unsigned nn = 0;
	size_t i;
	for (i = 0; i < len && nn < 2; ++i) {
		if (s[i] == '\r') {
			;
		} else if (s[i] == '\n') {
			++nn;
		} else {
			nn = 0;
		}
	}
	return nn == 2 ? &s[i] : NULL;
}

static void header_callback(mcrawler_url *u, char *name, char *value) {
	if (!strcasecmp(name, "Content-Length")) {
		u->contentlen = atoi(value);
		debugf("[%d] Head, Content-Length: %d\n", u->index, u->contentlen);
		if (!strcmp(u->method, "HEAD")) { // there will be no content
			u->contentlen = 0;
			debugf("[%d] HEAD request, no content\n", u->index);
		}
		return;
	}

	if ((!strcasecmp(name, "Location") && (u->status >= 300 || u->status < 400)) ||
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
		u->contentlen = 0; // do not need content - some servers returns no content-length and keeps conection open
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
	}
}

/**
 * @see https://www.ietf.org/rfc/rfc2616.txt
 */
static int parsehead(mcrawler_url *u) {
	char buf[u->headlen + 1];
	char *p = buf, *q;
	char *name, *value;

	memcpy(buf, u->buf, u->headlen);
	buf[u->headlen] = 0;

    if (strncmp("HTTP/1.0", p, 8) && strncmp("HTTP/1.1", p, 8)) {
		debugf("[%d] Unsupported protocol\n", u->index);
		return 1;
	}

	p += 9;
	u->status = atoi(p);
	assert(u->status > 0);

	p = strchr(p, '\n');
	assert(p != 0); // we know, there are two newlines somewhere

	while (1) {
		while (*p == '\r' || *p == '\n') p++;
		if (*p == 0) break;

		name = p;
		p = strpbrk(p, "\r\n:");
		assert(p != 0);
		if (*p != ':') {
			debugf("[%d] Header name terminator ':' not found\n", u->index);
			continue;
		}
		*p = 0; p++;

		while (*p == ' ' || *p == '\t') p++;
		value = p;
		while (1) {
			while (*p != '\r' && *p != '\n') p++;
			q = p;
			while (*q == '\r' || *q == '\n') q++;
			if (*q == ' ' || *q == '\t') { // value continues
				memmove(p, q, strlen(q) + 1);
			} else {
				break;
			}
		}

		*p = 0; p++;

		header_callback(u, name, value);
	}

	return 0;
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
		unsigned char *buf;
		int buflen = BUFSIZE - u->headlen;
		int ret;

		buf = (unsigned char *)malloc(u->bufp);
		memcpy(buf, u->buf + u->headlen, u->bufp - u->headlen);
		ret = gunzip(u->buf + u->headlen, &buflen, buf, u->bufp - u->headlen);
		debugf("[%d] gzip decompress status: %d (input length: %d, output length: %d)\n", u->index, ret, u->bufp - u->headlen, buflen);
		u->bufp = buflen + u->headlen;
		if (ret != 0) {
			sprintf(u->error_msg, "Gzip decompression error %d", ret);
			u->status = MCURL_S_DOWNLOADED - MCURL_S_ERROR;
		}
		free(buf);
	}

	if (u->options & 1<<MCURL_OPT_CONVERT_TO_UTF8) {
		if (!*u->charset) {
			unsigned charset_len = 0;
			char *charset = detect_charset_from_html((char *)u->buf + u->headlen, u->bufp - u->headlen, &charset_len);
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
			u->bufp = u->headlen;  // discard whole input in case of error
		}
	}

	if (u->options & 1<<MCURL_OPT_CONVERT_TO_TEXT) {
		u->bufp = converthtml2text((char *)u->buf+u->headlen, u->bufp-u->headlen)+u->headlen;
	}

	remove_expired_cookies(u);

	if (u->aresch) {
		ares_destroy(u->aresch);
		u->aresch = NULL;
	}

	u->timing.done = get_time_int();

	callback(u, callback_arg);

	debugf("[%d] Done.\n",u->index);
	set_atomic_int(&u->state, MCURL_S_DONE);
}

/**
 * Sets the url to initial state
 */
static void reset_url(mcrawler_url *u) {
	u->status = 0;
	u->location[0] = 0;
	u->bufp = 0;
	u->headlen = 0;
	u->contentlen = -1;
	u->chunked = 0;
	u->gzipped = 0;
	u->ssl_options = 0;
	if (u->contenttype) {
		free(u->contenttype);
		u->contenttype = NULL;
	}
	if (u->wwwauthenticate) {
		free(u->wwwauthenticate);
		u->wwwauthenticate = NULL;
	}

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
static void resolvelocation(mcrawler_url *u) {
	if (--u->redirect_limit <= 0) {
		debugf("[%d] Exceeded redirects limit", u->index);
		sprintf(u->error_msg, "Too many redirects, possibly a redirect loop");
		set_atomic_int(&u->state, MCURL_S_ERROR);
		return;
	}

	char ohost[ strlen(u->host) ];
	strcpy(ohost, u->host);

	debugf("[%d] Resolve location='%s'\n", u->index, u->location);

	if (set_new_url(u, u->location, u->uri) == 0) {
		return;
	}

	free(u->redirectedto);
	u->redirectedto = mcrawler_parser_serialize(u->uri, 0);

	if (strcmp(u->host, ohost) == 0) {
		// muzes se pripojit na tu puvodni IP
		free_addr(u->prev_addr);
		u->prev_addr = (mcrawler_addr*)malloc(sizeof(mcrawler_addr));
		memcpy(u->prev_addr, u->addr, sizeof(mcrawler_addr));
		u->prev_addr->next = NULL;
		set_atomic_int(&u->state, MCURL_S_GOTIP);
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
}

/**
Try read some data from the socket, check that we have some available place in the buffer.
*/
static ssize_t try_read(mcrawler_url *u) {
	ssize_t left = BUFSIZE - u->bufp;
	if(left <= 0) {
		return 0;
	}

	return ((mcrawler_url_func *)u->f)->read(u, u->buf + u->bufp, left, (char *)&u->error_msg);
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
		u->bufp += t;
		u->timing.lastread = get_time_int();
	}
	if (t > 0 && !u->timing.firstbyte) {
		u->timing.firstbyte = u->timing.lastread;
	}

	debugf("[%d] Read %zd bytes; bufp = %d; chunked = %d; data = [%.*s]\n", u->index, t, u->bufp, !!u->chunked, (int)t, u->buf + u->bufp - t);

	unsigned char *head_end;
	if (u->headlen == 0 && (head_end = find_head_end(u))) {
		u->headlen = head_end - u->buf;
		parsehead(u);
	}
	
	// u->chunked is set in parsehead()
	if(t > 0 && u->chunked) {
		//debugf("debug: bufp=%d nextchunkedpos=%d",u->bufp,u->nextchunkedpos);
		while(u->bufp > u->nextchunkedpos) {
			const int i = eatchunked(u);	// pokud jsme presli az pres chunked hlavicku, tak ji sezer
			if(i == -1) {
				break;
			}
		}
	}
	
	if(t == MCURL_IO_EOF || t == MCURL_IO_ERROR || (u->contentlen != -1 && u->bufp >= u->headlen + u->contentlen)) {
#ifdef HAVE_LIBSSL
		if (u->ssl != NULL) {
			SSL_free(u->ssl);
			u->ssl = NULL;
		}
#endif

		if (t == MCURL_IO_ERROR) {
			set_atomic_int(&u->state, MCURL_S_ERROR);
		} else if (get_atomic_int(&u->state) != MCURL_S_ERROR) {
			set_atomic_int(&u->state, MCURL_S_DOWNLOADED);
			debugf("[%d] Downloaded.\n",u->index);
			if (u->location[0] && strcmp(u->method, "HEAD")) {
				resolvelocation(u);
			} else if (u->authorization && u->status == 401) {
				if (!u->auth_attempt) {
					// try to authorize
					u->auth_attempt = 1;
					reset_url(u);
					set_atomic_int(&u->state, MCURL_S_GOTIP);
				}
			}
		}

		close(u->sockfd); // FIXME: Is it correct to close the connection before we read the whole reply from the server?
		debugf("[%d] Closing connection (socket %d)\n", u->index, u->sockfd);
	} else {
		set_atomic_int(&u->state, MCURL_S_RECVREPLY);
		set_atomic_int(&u->rw, 1<<MCURL_RW_WANT_READ);
	}
}

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
				set_atomic_int(&u->state, MCURL_S_GOTIP);
			}
			break;
		case MCURL_S_HANDSHAKE:
#ifdef HAVE_LIBSSL
			if (get_time_int() - u->timing.handshakestart > timeout) {
				// we retry handshake with another protocol
				if (lower_ssl_protocol(u) == 0) {
					debugf("[%d] SSL handshake timeout (%d ms), closing connection\n", u->index, timeout);

					if (u->ssl) {
						SSL_free(u->ssl);
						u->ssl = NULL;
					}
					close(u->sockfd);
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
		if (!u->timing.dnsstart) u->timing.dnsstart = time;
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
		finish(u, callback, callback_arg);
		break;
  
	case MCURL_S_ERROR:
		assert(u->status < 0);
		finish(u, callback, callback_arg);
		break;
	}

	const int stateAfter = get_atomic_int(&u->state);
	if (stateAfter == MCURL_S_ERROR) {
		u->status = state - stateAfter;
	}

	if (debug) {
		const int duration = get_time_int() - time;
		if(duration > 200) {
			debugf("[%d] State %d (->%d) took too long (%d ms)\n", u->index, state, get_atomic_int(&u->state), duration);
		}
	}
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
			finish(url, callback, callback_arg);
		}
	}
}

void mcrawler_init_settings(mcrawler_settings *settings) {
	memset(settings, 0, sizeof(mcrawler_settings));
	settings->timeout = DEFAULT_TIMEOUT;
	settings->delay = DEFAULT_DELAY;
}

/**
 * Init URL struct
 */
void mcrawler_init_url(mcrawler_url *u, const char *url) {
	u->state = MCURL_S_JUSTBORN;
	u->redirect_limit = MAX_REDIRECTS;
	if (url && strlen(url) > MAXURLSIZE) {
		*(char*)mempcpy(u->rawurl, url, MAXURLSIZE) = 0;
		sprintf(u->error_msg, "URL is too long");
		u->status = MCURL_S_JUSTBORN - MCURL_S_ERROR;
		set_atomic_int(&u->state, MCURL_S_ERROR);
	} else if (url) {
		strcpy(u->rawurl, url);
	}
	u->contentlen = -1;

	// init callbacks
	mcrawler_url_func f = (mcrawler_url_func) {
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
	u->f = (mcrawler_url_func*)malloc(sizeof(mcrawler_url_func));
	memcpy(u->f, &f, sizeof(mcrawler_url_func));
}

/**
 * hlavni smycka
 */
void mcrawler_go(mcrawler_url **urls, const mcrawler_settings *settings, mcrawler_url_callback callback, void *callback_arg) {
	int done;
	int change;
	mcrawler_url *url;

	init_birth();

	debug = settings->debug;

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
	
	free_mossad();
	if(done) {
		debugf("All successful. Took %d ms.\n", get_time_int());
	}
}

char *mcrawler_version() {
	return VERSION;
}
