#define _GNU_SOURCE // memmem(.) needs this :-(
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <ares.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uriparser/Uri.h>

#include "h/string.h"
#include "h/proto.h"
#include "h/version.h"

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
	return ((1 << state) & SURL_STATES_IO) && (rw & (1 << SURL_RW_WANT_READ | 1 << SURL_RW_WANT_WRITE));
}

/** Assert like function: Check that actual state either doesn't requiere io or io is available for its socket.
Otherwise die in cruel pain!
HINT: This function simply checks whether we check availability of fd for reading/writing before using it for r/w.
*/
static int check_io(const int state, const int rw) {
	if ( ((1 << state) & SURL_STATES_IO) && !(rw & (1 << SURL_RW_READY_READ | 1 << SURL_RW_READY_WRITE)) ) {
		abort();
	}
}

/**
 * Sets lower TSL/SSL protocol
 */
static int lower_ssl_protocol(struct surl *u) {
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
static void sec_handshake(struct surl *u) {
	assert(u->ssl);

	if (!u->timing.sslstart) u->timing.sslstart = get_time_int();

	const int t = SSL_connect(u->ssl);
    if (t == 1) {
		u->timing.sslend = get_time_int();
        set_atomic_int(&u->state, SURL_S_GENREQUEST);
        return;
    }

    const int err = SSL_get_error(u->ssl, t);
    if (err == SSL_ERROR_WANT_READ) {
    	set_atomic_int(&u->rw, 1<<SURL_RW_WANT_READ);
		return;
    }
    if (err == SSL_ERROR_WANT_WRITE) {
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_WRITE);
		return;
    }
	switch (err) {
		case SSL_ERROR_ZERO_RETURN:
			debugf("[%d] Connection closed (in handshake)", u->index);
			sprintf(u->error_msg, "SSL connection closed during handshake");
			set_atomic_int(&u->state, SURL_S_ERROR);
			return;
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			debugf("[%d] SSL_ERROR_WANT_CONNECT\n", u->index);
			sprintf(u->error_msg, "Unexpected SSL error during handshake");
			set_atomic_int(&u->state, SURL_S_ERROR);
			return;
		case SSL_ERROR_WANT_X509_LOOKUP:
			debugf("[%d] SSL_ERROR_WANT_X509_LOOKUP\n", u->index);
			sprintf(u->error_msg, "Unexpected SSL error during handshake");
			set_atomic_int(&u->state, SURL_S_ERROR);
			return;
		case SSL_ERROR_SYSCALL:
			debugf("[%d] SSL_ERROR_SYSCALL (%d)\n", u->index, t);
			if (t < 0) { // t == 0: unexpected EOF
				sprintf(u->error_msg, "Unexpected SSL error during handshake");
				set_atomic_int(&u->state, SURL_S_ERROR);
				return;
			}
	}

	// else SSL_ERROR_SSL = protocol error
	debugf("[%d] SSL protocol error (in handshake): \n", u->index);
	unsigned long e, last_e = 0;
	while (e = ERR_get_error()) {
		debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
		last_e = e;
	}

	if (lower_ssl_protocol(u) < 0) {
		sprintf(u->error_msg, "SSL protocol error during handshake");
		if (last_e) {
			sprintf(u->error_msg + strlen(u->error_msg), " (%s)", ERR_reason_error_string(last_e));
		}
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}
	else {
		// zkusíme ještě jednou
		SSL_shutdown(u->ssl);
		SSL_free(u->ssl);
		close(u->sockfd);
		set_atomic_int(&u->state, SURL_S_GOTIP);
		return;
	}
}

/** Read some data from SSL socket.
NOTE: We must read as much as possible, because select(.) may
not notify us that other data are available.
From select(.)'s point of view they are read but in fact they are in SSL buffers.
*/
static ssize_t sec_read(const struct surl *u, char *buf, const size_t size, char *errbuf) {
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
			return SURL_IO_WRITE;
		case SSL_ERROR_WANT_READ:
			return SURL_IO_READ;
		case SSL_ERROR_ZERO_RETURN:
			return SURL_IO_EOF;
		case SSL_ERROR_SYSCALL:
			debugf("[%d] SSL read failed: SSL_ERROR_SYSCALL (%d)\n", u->index, t);
			if (t < 0) { // t == 0: unexpected EOF
				sprintf(errbuf, "Downloading content failed (%m)");
				return SURL_IO_ERROR;
			}
		case SSL_ERROR_SSL:
			debugf("[%d] SSL read failed: protocol error: \n", u->index);
			unsigned long e, last_e = 0;
			while (e = ERR_get_error()) {
				debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
				last_e = e;
			}
			const int n = sprintf(errbuf, "Downloading content failed");
			if (last_e && n > 0) {
				sprintf(errbuf + n, " (%s)", ERR_reason_error_string(last_e));
			}
			return SURL_IO_ERROR;
		default:
			debugf("[%d] SSL read failed: %d (WANT_X509_LOOKUP: 4, WANT_CONNECT: 7, WANT_ACCEPT: 8)\n", u->index, err);
			sprintf(errbuf, "Downloading content failed (unexpected SSL error)");
			return SURL_IO_ERROR;
	}
}

/** Write some data to SSL socket.
NOTE: We must write as much as possible otherwise
select(.) would not notify us that socket is writable again.
*/
static ssize_t sec_write(const struct surl *u, const char *buf, const size_t size, char *errbuf) {
    assert(u->ssl);

	const int t = SSL_write(u->ssl, buf, size);
	if (t > 0) {
		return (ssize_t)t;
	}

	const int err = SSL_get_error(u->ssl, t);
	switch (err) {
		case SSL_ERROR_WANT_READ:
			return SURL_IO_READ;
		case SSL_ERROR_WANT_WRITE:
			return SURL_IO_WRITE;
		case SSL_ERROR_ZERO_RETURN:
			return SURL_IO_EOF;
		case SSL_ERROR_SYSCALL:
			debugf("[%d] SSL write failed: SSL_ERROR_SYSCALL (%d)\n", u->index, t);
			if (t < 0) { // t == 0: unexpected EOF
				sprintf(errbuf, "Sending request failed (%m)");
				return SURL_IO_ERROR;
			}
		case SSL_ERROR_SSL:
			debugf("[%d] SSL write failed: protocol error: \n", u->index);
			unsigned long e, last_e = 0;
			while (e = ERR_get_error()) {
				debugf("[%d]\t\t%s\n", u->index, ERR_error_string(e, NULL));
				last_e = e;
			}
			const int n = sprintf(errbuf, "Sending request failed");
			if (last_e && n > 0) {
				sprintf(errbuf + n, " (%s)", ERR_reason_error_string(last_e));
			}
			return SURL_IO_ERROR;
		default:
			debugf("[%d] SSL write failed: %d (WANT_X509_LOOKUP: 4, WANT_CONNECT: 7, WANT_ACCEPT: 8)\n", u->index, err);
			sprintf(errbuf, "Sending request failed (unexpected SSL error)");
			return SURL_IO_ERROR;
	}
}

/** callback funkce, kterou zavola ares
 */
static void dnscallback(void *arg, int status, int timeouts, struct hostent *hostent) {
	struct surl *u;
	
	u=(struct surl *)arg;
	if (status != ARES_SUCCESS) {
		if (u->addrtype == AF_INET) {
			// zkusíme ještě IPv6
			u->addrtype = AF_INET6;
			debugf("[%d] gethostbyname error: %d: %s -> switch to ipv6\n", u->index, *(int *) arg, ares_strerror(status));
			set_atomic_int(&u->state, SURL_S_PARSEDURL);
			return;
		}
		debugf("[%d] gethostbyname error: %d: %s\n", u->index, *(int *) arg, ares_strerror(status));
		sprintf(u->error_msg, "%s", ares_strerror(status));
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}
	
	if (hostent->h_addr == NULL) {
		if (u->addrtype == AF_INET) {
			// zkusíme ještě IPv6
			u->addrtype = AF_INET6;
			debugf("[%d] Could not resolve host -> switch to ipv6\n", u->index);
			set_atomic_int(&u->state, SURL_S_PARSEDURL);
			return;
		}
		debugf("[%d] Could not resolve host\n", u->index);
		sprintf(u->error_msg, "Could not resolve host");
		set_atomic_int(&u->state, SURL_S_ERROR);
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
	struct addr *last_addr;
	do {
		struct addr *addr;
		addr = (struct addr*)malloc(sizeof(struct addr));
		memset(addr, 0, sizeof(struct addr));
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
	set_atomic_int(&u->state, SURL_S_GOTIP);
}

static int parse_proto(const char *s);

static int check_proto(struct surl *u);

/**
 * Nastaví proto, host, port a path
 * rawurl musí obsahovat scheme a authority!
 */
static int set_new_uri(struct surl *u, char *rawurl) {
	int r;

	if (u->uri != NULL) {
		uriFreeUriMembersA(u->uri);
		free(u->uri);
	}

	UriParserStateA state;

	u->uri = (UriUriA *)malloc(sizeof(UriUriA));
	state.uri = u->uri;

	if (uriParseUriA(&state, rawurl) != URI_SUCCESS) {
		debugf("[%d] error: url='%s' failed to parse\n", u->index, rawurl);
		sprintf(u->error_msg, "Failed to parse URL");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return 0;
	}

	if (u->uri->scheme.first == NULL) {
		debugf("[%d] error: url='%s' has no scheme\n", u->index, rawurl);
		sprintf(u->error_msg, "URL has no scheme");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return 0;
	}
	if (u->proto != NULL) free(u->proto);
	u->proto = malloc(u->uri->scheme.afterLast - u->uri->scheme.first + 1);
	*(char*)mempcpy(u->proto, u->uri->scheme.first, u->uri->scheme.afterLast-u->uri->scheme.first) = 0;

	if (check_proto(u) == -1) {
		return 0;
	}

	if (u->uri->hostText.first == NULL) {
		debugf("[%d] error: url='%s' has no host\n", u->index, rawurl);
		sprintf(u->error_msg, "URL has no host");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return 0;
	}
	if (u->host != NULL) free(u->host);
	u->host = malloc(u->uri->hostText.afterLast - u->uri->hostText.first + 1);
	*(char*)mempcpy(u->host, u->uri->hostText.first, u->uri->hostText.afterLast-u->uri->hostText.first) = 0;

	if (u->uri->portText.first == NULL) {
		u->port = parse_proto(u->proto);
	} else {
		r = sscanf(u->uri->portText.first, "%d", &u->port);
		if (r == 0) { // prázdný port
			u->port = parse_proto(u->proto);
		}
	}

	// recompose path + query
	if (u->path != NULL) free(u->path);
	u->path = malloc(strlen(rawurl)); // path nebude delší, než celé URL
	char *p = u->path;
	if (u->uri->pathHead != NULL) {
		UriPathSegmentA *walker = u->uri->pathHead;
		do {
			*p++ = '/';
			const int chars = (int)(walker->text.afterLast - walker->text.first);
			memcpy(p, walker->text.first, chars);
			p += chars;
			walker = walker->next;
		} while (walker != NULL);
	} else {
		*p++ = '/';
	}
	if (u->uri->query.first != NULL) {
		*p++ = '?';
		const int chars = (int)(u->uri->query.afterLast - u->uri->query.first);
		memcpy(p, u->uri->query.first, chars);
		p += chars;
	}
	*p = '\0';

	debugf("[%d] proto='%s' host='%s' port=%d path='%s'\n", u->index, u->proto, u->host, u->port, u->path);

	if (u->uri->hostData.ip4 != NULL) {
		free_addr(u->prev_addr);
		u->prev_addr = u->addr;
		u->addr = (struct addr*)malloc(sizeof(struct addr));
		memset(u->addr, 0, sizeof(struct addr));
		memcpy(u->addr->ip, u->uri->hostData.ip4->data, 4);
		u->addr->type = AF_INET;
		u->addr->length = 4;
		u->addr->next = NULL;
		set_atomic_int(&u->state, SURL_S_GOTIP);
		debugf("[%d] go directly to ipv4\n", u->index);
	} else if (u->uri->hostData.ip6 != NULL) {
		free_addr(u->prev_addr);
		u->prev_addr = u->addr;
		u->addr = (struct addr*)malloc(sizeof(struct addr));
		memset(u->addr, 0, sizeof(struct addr));
		memcpy(u->addr->ip, u->uri->hostData.ip6->data, 16);
		u->addr->type = AF_INET6;
		u->addr->length = 16;
		u->addr->next = NULL;
		set_atomic_int(&u->state, SURL_S_GOTIP);
		debugf("[%d] go directly to ipv6\n", u->index);
	} else {
		set_atomic_int(&u->state, SURL_S_PARSEDURL);
	}
	return 1;
}

/** Parsujeme URL
 */
static void parseurl(struct surl *u) {
	debugf("[%d] Parse url='%s'\n", u->index, u->rawurl);
	if (!urlencode(u->rawurl)) {
		debugf("[%d] Not enough memory for urlencode '%s'\n", u->index, u->rawurl);
		sprintf(u->error_msg, "URL is too long");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}
	if (set_new_uri(u, u->rawurl) == 0) {
		return;
	}
}

/** spusti preklad pres ares
 */
static void launchdns(struct surl *u) {
	int t;

	debugf("[%d] Resolving %s starts\n", u->index, u->host);
	t = ares_init(&(u->aresch));
	if(t) {
		debugf("[%d] ares_init failed\n", u->index);
		sprintf(u->error_msg, "ares init failed");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	set_atomic_int(&u->state, SURL_S_INDNS);
	ares_gethostbyname(u->aresch,u->host,u->addrtype,(ares_host_callback)&dnscallback,u);
}

/** uz je ares hotovy?
 */
static void checkdns(struct surl *u) {
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
static void connectsocket(struct surl *u) {
	int result;
	socklen_t result_len = sizeof(result);
	if (getsockopt(u->sockfd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0) {
		// error, fail somehow, close socket
		debugf("[%d] Cannot connect, getsoskopt(.) returned error status: %m\n", u->index);
		if (u->addr->next != NULL) {
			struct addr *next = u->addr->next;
			free(u->addr);
			u->addr = next;
			debugf("[%d] Trying another ip\n", u->index);
			set_atomic_int(&u->state, SURL_S_GOTIP);
			return;
		}
		sprintf(u->error_msg, "Failed to connect to host (%m)");
		set_atomic_int(&u->state, SURL_S_ERROR);
		close(u->sockfd);
		return;
	}

	if (result != 0) {
		debugf("[%d] Cannot connect, attempt to connect failed\n", u->index);
		if (u->addr->next != NULL) {
			struct addr *next = u->addr->next;
			free(u->addr);
			u->addr = next;
			debugf("[%d] Trying another ip\n", u->index);
			set_atomic_int(&u->state, SURL_S_GOTIP);
			return;
		}
		sprintf(u->error_msg, "Failed to connect to host (%s)", strerror(result));
		set_atomic_int(&u->state, SURL_S_ERROR);
		close(u->sockfd);
		return;
	}

	set_atomic_int(&u->state, SURL_S_HANDSHAKE);
	set_atomic_int(&u->rw, 1<< SURL_RW_READY_READ | 1<<SURL_RW_READY_WRITE);
}

/** Allocate ssl objects for ssl connection. Do nothing for plain connection.
*/
static int maybe_create_ssl(struct surl *u) {
	if (0 != strcmp(u->proto, "https")) {
		return 1;
	}

	SSL *ssl = SSL_new(mossad());
	BIO *sbio = BIO_new_socket(u->sockfd, BIO_NOCLOSE);
	SSL_set_bio(ssl, sbio, sbio);
	SSL_set_options(ssl, u->ssl_options);
	SSL_set_tlsext_host_name(ssl, u->host);

	u->ssl = ssl;

	return 1;
}

/** uz znam IP, otevri socket
 */
static void opensocket(struct surl *u)
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
		set_atomic_int(&u->state, SURL_S_ERROR);
	}
	if(t) {
		if(errno == EINPROGRESS) {
			set_atomic_int(&u->state, SURL_S_CONNECT);
			set_atomic_int(&u->rw, 1<<SURL_RW_WANT_WRITE);
		}
		else {
			debugf("%d: connect failed (%d, %s)\n", u->index, errno, strerror(errno));
			sprintf(u->error_msg, "Failed to connect to host (%m)");
			set_atomic_int(&u->state, SURL_S_ERROR);
		}
	} else {
		set_atomic_int(&u->state, SURL_S_HANDSHAKE);
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_WRITE | 1<<SURL_RW_WANT_WRITE);
	}
}

/** socket bezi, posli dotaz
 * cookie header see http://tools.ietf.org/html/rfc6265 section 5.4
 */
static void genrequest(struct surl *u) {
	const char reqfmt[] = "%s %s HTTP/1.1";
	const char hostheader[] = "Host: ";
	const char useragentheader[] = "User-Agent: ";
	const char cookieheader[] = "Cookie: ";
	const char gzipheader[] = "Accept-Encoding: gzip";
	const char contentlengthheader[] = "Content-Length: ";
	const char contenttypeheader[] = "Content-Type: application/x-www-form-urlencoded";
	const char defaultagent[] = "minicrawler/%s";

	free(u->request);
	u->request = malloc(
			strlen(reqfmt) + strlen(u->method) + strlen(u->path) + 2 + // method URL HTTP/1.1\n
			strlen(hostheader) + strlen(u->host) + 6 + 2 + // Host: %s(:port)\n
			strlen(useragentheader) + (u->customagent[0] ? strlen(u->customagent) : strlen(defaultagent) + 8) + 2 + // User-Agent: %s\n
			strlen(cookieheader) + 1024 * u->cookiecnt + 2 + // Cookie: %s; %s...\n
			strlen(u->customheader) + 2 +
			(u->options & 1<<SURL_OPT_GZIP ? strlen(gzipheader) + 2 : 0) + // Accept-Encoding: gzip\n
			(u->post != NULL ? strlen(contentlengthheader) + 6 + 2 + strlen(contenttypeheader) + 2 : 0) + // Content-Length: %d\nContent-Type: ...\n
			2 + // end of header
			(u->post != NULL ? strlen(u->post) : 0) // body
	);

	char *r = u->request;

	sprintf(r, reqfmt, u->method, u->path);
	r += strlen(r);
	strcpy(r, "\r\n");
	r += 2;

	// Host
	strcpy(r, hostheader);
	strcpy(r + strlen(r), u->host);
	const int port = parse_proto(u->proto);
	if (port != u->port) {
		sprintf(r + strlen(r), ":%d", u->port);
	}
	r += strlen(r);
	strcpy(r, "\r\n");
	r += 2;

	// Uset-Agent
	strcpy(r, useragentheader);
	if (u->customagent[0]) {
		strcpy(r + strlen(r), u->customagent);
	} else {
		sprintf(r + strlen(r), defaultagent, VERSION);
	}
	r += strlen(r);
	strcpy(r, "\r\n");
	r += 2;

	// Cookie
	for (int t = 0; t < u->cookiecnt; t++) {
		char *p;
		// see http://tools.ietf.org/html/rfc6265 section 5.4
		// TODO: The request-uri's path path-matches the cookie's path.
		if (
				(u->cookies[t].host_only == 1 && strcasecmp(u->host, u->cookies[t].domain) == 0 ||
					u->cookies[t].host_only == 0 && (p = strcasestr(u->host, u->cookies[t].domain)) != NULL && *(p+strlen(u->cookies[t].domain)+1) == '\0') &&
				(u->cookies[t].secure == 0 || strcmp(u->proto, "https") == 0)
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
		strcpy(r, u->customheader);
		r += strlen(r);
		strcpy(r, "\r\n");
		r += 2;
	}

	// gzip
	if (u->options & 1<<SURL_OPT_GZIP) {
		strcpy(r, gzipheader);
		r += strlen(r);
		strcpy(r, "\r\n");
		r += 2;
	}

	if (u->post != NULL) {
		strcpy(r, contentlengthheader);
		sprintf(r + strlen(r), "%d", strlen(u->post));
		r += strlen(r);
		strcpy(r, "\r\n");
		r += 2;
		strcpy(r, contenttypeheader);
		r += strlen(r);
		strcpy(r, "\r\n");
		r += 2;
	}

	// end of header
	strcpy(r, "\r\n");
	r += 2;

	// body
	if (u->post != NULL) {
		strcpy(r, u->post);
	}

	debugf("[%d] Request: [%s]", u->index, u->request);
	u->request_len = strlen(u->request);
	u->request_it = 0;

	set_atomic_int(&u->state, SURL_S_SENDREQUEST);
	set_atomic_int(&u->rw, 1<<SURL_RW_READY_WRITE);
}

/** Sends the request string. This string was generated in previous state:
GEN_REQUEST.
*/
static void sendrequest(struct surl *u) {
	if (u->request_it < u->request_len) {
		const ssize_t ret = u->f.write(u, &u->request[u->request_it], u->request_len - u->request_it, (char *)&u->error_msg);
		if (ret == SURL_IO_ERROR || ret == SURL_IO_EOF) {
			set_atomic_int(&u->state, SURL_S_ERROR);
			return;
		}
		else if (ret == SURL_IO_WRITE) {
			set_atomic_int(&u->rw, 1<<SURL_RW_WANT_WRITE);
		} else if (ret == SURL_IO_READ) {
			set_atomic_int(&u->rw, 1<<SURL_RW_WANT_READ);
		} else {
			assert(ret > 0);
			u->request_it += (size_t)ret;
		}
	}
	if (u->request_it == u->request_len) {
		set_atomic_int(&u->state, SURL_S_RECVREPLY);
		set_atomic_int(&u->rw, 1<<SURL_RW_READY_READ);
	} else {
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_WRITE);
	}
}

/** Fake handshake handler that does nothing, only increments state.
Usefull for plain http protocol that does not need handshake.
*/
static void empty_handshake(struct surl *u) {
	set_atomic_int(&u->state, SURL_S_GENREQUEST);
}

/** sezere to radku tam, kde ceka informaci o delce chunku
 *  jedinou vyjimkou je, kdyz tam najde 0, tehdy posune i contentlen, aby dal vedet, ze jsme na konci
 *  @return 0 je ok, -1 pokud tam neni velikost chunku zapsana cela
 */
static int eatchunked(struct surl *u) {
	int t,i;
	unsigned char hex[10];
	int size;
	int movestart;

	//if (!memchr(u->nextchunkedpos, '\n', ))
	// čte velikost chunku
	debugf("nextchunkedpos = %d; bufp = %d\n", u->nextchunkedpos, u->bufp);
	for(t=u->nextchunkedpos, i=0; u->buf[t] != '\r' && u->buf[t] != '\n' && t < u->bufp; t++) {
		if(i < 9) {
			hex[i++] = u->buf[t];
		}
	}
	if(t >= u->bufp) {
		debugf("[%d] Incorrectly ended chunksize!", u->index);
		return -1;
	}
	if(t < u->bufp && u->buf[t] == '\r') {
		t++;
	}
	if(t < u->bufp && u->buf[t] == '\n') {
		t++;
	}

	if(i == 0) {
		debugf("[%d] Warning: empty string for chunksize\n",u->index);
	}
	hex[i] = 0;
	size = strtol(hex, NULL, 16);

	debugf("[%d] Chunksize at %d (now %d): '%s' (=%d)\n",u->index,u->nextchunkedpos,u->bufp,hex,size);

	movestart=u->nextchunkedpos;
	if (u->nextchunkedpos != u->headlen) {
		movestart -= 2;
	}
	assert(t <= u->bufp);
	memmove(u->buf+movestart,u->buf+t,u->bufp-t);		// cely zbytek posun
	u->bufp-=(t-movestart);					// ukazatel taky
	
	u->nextchunkedpos=movestart+size+2;			// o 2 vic kvuli odradkovani na konci chunku
	
	if(size == 0) {
		// a to je konec, pratele! ... taaadydaaadydaaa!
		debugf("[%d] Chunksize=0 (end)\n",u->index);
		// zbytek odpovedi zahodime
		u->bufp = movestart;
		u->contentlen = movestart - u->headlen;
	}
	
	return 0;
}

/** 
 * zapíše si do pole novou cookie (pokud ji tam ještě nemá; pokud má, tak ji nahradí)
 * kašleme na *cestu* a na dobu platnosti cookie (to by mělo být pro účely minicrawleru v pohodě)
 * see http://tools.ietf.org/html/rfc6265 section 5.2 and 5.3
 */
static void setcookie(struct surl *u,char *str) {
	struct cookie cookie;
	char *p, *q, *r;
	int len;

	memset(&cookie, 0, sizeof(struct cookie));

	p = strpbrk(str, ";\r\n");
	if (p == NULL) return;

	char namevalue[p-str+1];
	*(char*)mempcpy(namevalue, str, p-str) = 0;

	char *attributestr;
	if (p[0] == ';') {
		q = strpbrk(str, "\r\n");
		if (q == NULL) return;
		attributestr = (char *) malloc(q - p + 1);
		*(char*)mempcpy(attributestr, p, q - p) = 0;
	} else {
		attributestr = malloc(1);
		attributestr[0] = '\0';
	}

	// parse name and value
	if ((p = strchr(namevalue, '=')) == NULL) {
		debugf("[%d] Cookie string '%s' lacks a '=' character\n", u->index, namevalue);
		return;
	}

	cookie.name = malloc(p - namevalue + 1);
	cookie.value = malloc(strlen(namevalue) - (p-namevalue));
	*(char*)mempcpy(cookie.name, namevalue, p - namevalue) = 0;
	*(char*)mempcpy(cookie.value, p + 1, strlen(namevalue) - (p-namevalue) - 1) = 0;

	trim(cookie.name);
	trim(cookie.value);

	if (strlen(cookie.name) == 0) {
		debugf("[%d] Cookie string '%s' has empty name\n", u->index, namevalue);
		return;
	}
	
	// parse cookie attributes
	struct nv attributes[10];
	struct nv *attr;
	int att_len = 0;
	p = attributestr;
	while (*p) {
		if (att_len > 9) {
			debugf("[%d] Cookie string '%s%s' has more 10 attributes (not enough memory)... skipping the rest\n", u->index, namevalue, attributestr);
			break;
		}

		attr = attributes + att_len++;
		q = strchrnul(p+1, ';');
		if ((r = strchr(p+1, '=')) != NULL && r < q) {
			attr->name = malloc(r-(p+1)+1);
			attr->value = malloc(q-r);
			*(char*)mempcpy(attr->name, p+1, r-(p+1)) = 0;
			*(char*)mempcpy(attr->value, r+1, q-r-1) = 0;
		} else {
			attr->name = malloc(q-(p+1)+1);
			attr->value = malloc(1);
			*(char*)mempcpy(attr->name, p+1, q-(p+1)) = 0;
			attr->value[0] = '\0';
		}
		trim(attr->name);
		trim(attr->value);
		
		p = q;
	}

	// process attributes
	int i;
	for (i = 0; i < att_len; i++) {
		attr = attributes + i;

		// The Domain Attribute
		if (!strcasecmp(attr->name, "Domain")) {
			if (strlen(attr->value) == 0) {
				debugf("[%d] Cookie string '%s%s' has empty value for domain attribute... ignoring\n", u->index, namevalue, attributestr);
				return;
			}

			// ignore leading '.'
			if (attr->value[0] == '.') {
				memmove(attr->value, attr->value + 1, strlen(attr->value));
			}

			// TODO: ignore public suffixes, see 5.3.5
			
			// match request host
			if ((p = strcasestr(u->host, attr->value)) == NULL || *(p+strlen(attr->value)+1) != '\0') {
				debugf("[%d] Domain in cookie string '%s%s' does not match request host '%s'... ignoring\n", u->index, namevalue, attributestr, u->host);
				return;
			}

			cookie.domain = malloc(strlen(attr->value)+1);
			strcpy(cookie.domain, attr->value);
			cookie.host_only = 0;
		}

		// The Secure Attribute
		if (!strcasecmp(attr->name, "Secure")) {
			cookie.secure = 1;
		}
	}

	if (!cookie.domain) {
		cookie.domain = malloc(strlen(u->host) +1);
		strcpy(cookie.domain, u->host);
		cookie.host_only = 1;
	}

	int t;
	for (t = 0; t<u->cookiecnt; ++t) {
		if(!strcasecmp(cookie.name,u->cookies[t].name) && !strcasecmp(cookie.domain,u->cookies[t].domain)) {
			break;
		}
	}

	if (t<u->cookiecnt) { // už tam byla
		free(u->cookies[t].name);
		free(u->cookies[t].value);
		free(u->cookies[t].domain);
		debugf("[%d] Changed cookie\n",u->index);
	} else {
		u->cookiecnt++;
	}

	if (t < sizeof(u->cookies)/sizeof(*u->cookies)) {
		memcpy(&u->cookies[t], &cookie, sizeof(cookie));
		debugf("[%d] Storing cookie #%d: name='%s', value='%s', domain='%s', host_only=%d, secure=%d\n",u->index,t,cookie.name,cookie.value,cookie.domain,cookie.host_only,cookie.secure);
	} else {
		u->cookiecnt--;
		debugf("[%d] Not enough memory for storing cookies\n",u->index);
	}

}

/** Find string with content type inside the http head.
*/
static void find_content_type(struct surl *u) {
	static const char content_type[] = "\nContent-Type:";
	static const char charset[] = " charset=";
	char *p_ct = (char*) memmem(u->buf, u->headlen, content_type, sizeof(content_type) - 1);
	if(!p_ct)
		return;
	char *end;
	for (end = &p_ct[sizeof(content_type) - 1]; end < &u->buf[u->headlen] && *end != '\n' && *end != '\r'; ++end);
	char *p_charset = (char*) memmem(&p_ct[sizeof(content_type) - 1], end - &p_ct[sizeof(content_type) - 1], charset, sizeof(charset) - 1);
	if (!p_charset)
		return;
	char *p_charset_end = &p_charset[sizeof(charset) - 1];
	if (sizeof(u->charset) > end - p_charset_end) {
		*(char*)mempcpy(u->charset, p_charset_end, end - p_charset_end) = 0;
		debugf("charset='%s'\n", u->charset);
	}
}

/**  Tries to find the end of a head in the server's reply.
        It works in a way that it finds a sequence of characters of the form: m{\r*\n\r*\n} */
static char *find_head_end(struct surl *u) {
	char *s = u->buf;
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

/** pozná status a hlavičku http požadavku
 *  FIXME: handle http headers case-insensitive!!
 */
static int detecthead(struct surl *u) {
	u->status = atoi(u->buf + 9);
	u->buf[u->bufp] = 0;
	
	char *p = find_head_end(u);

	if(p == NULL) {
		debugf("[%d] cannot find end of http header?\n", u->index);
		return 0;
	}
	
	u->headlen = p-u->buf;
	
	p=(char*)memmem(u->buf, u->headlen, "Content-Length: ", 16)?:(char*)memmem(u->buf, u->headlen, "Content-length: ", 16)?:(char*)memmem(u->buf, u->headlen, "content-length: ", 16);
	if(p != NULL) {
		u->contentlen = atoi(p + 16);
	}
	debugf("[%d] Head, Content-Length: %d\n", u->index, u->contentlen);
	if (!strcmp(u->method, "HEAD")) { // there will be no content
		u->contentlen = 0;
		debugf("[%d] HEAD request, no content\n", u->index);
	}

	p=(char*)memmem(u->buf,u->headlen,"\nLocation: ",11)?:(char*)memmem(u->buf,u->headlen,"\nlocation: ",11);
	if(p!=NULL) {
		if (!strcpy_term(u->location,p+11,MAXURLSIZE)) {
			sprintf(u->error_msg, "Redirect URL is too long");
			set_atomic_int(&u->state, SURL_S_ERROR);
		}
		u->contentlen = 0; // do not need content - some servers returns no content-length and keeps conection open
		debugf("[%d] Location='%s'\n",u->index,u->location);
	}

	p=(char*)memmem(u->buf,u->headlen,"\nRefresh: 0;url=",16)?:(char*)memmem(u->buf,u->headlen,"\nrefresh: 0;url=",16);
	if(p!=NULL) {
		if (!strcpy_term(u->location,p+16,MAXURLSIZE)) {
			sprintf(u->error_msg, "Redirect URL is too long");
			set_atomic_int(&u->state, SURL_S_ERROR);
		}
		u->contentlen = 0; // do not need content
		debugf("[%d] Refresh='%s'\n",u->index,u->location);
	}

	for (char *q = u->buf; q < &u->buf[u->headlen];) {
		q = (char*)memmem(q, u->headlen - (q - u->buf), "\nSet-Cookie: ", 13);
		if (q != NULL) {
			q += 13;
			setcookie(u, q);
		} else {
			break;
		}
	}
	
	p=(char*)memmem(u->buf, u->headlen, "Transfer-Encoding: chunked", 26)?:(char*)memmem(u->buf,u->headlen,"transfer-encoding: chunked", 26)?:(char*)memmem(u->buf, u->headlen, "Transfer-Encoding:  chunked", 27);
	if(p != NULL) {
		u->chunked = 1;
		u->nextchunkedpos=u->headlen;
		debugf("[%d] Chunked!\n",u->index);
	}

	p=(char*)memmem(u->buf, u->headlen, "Content-Encoding: gzip", 22)?:(char*)memmem(u->buf,u->headlen,"content-encoding: gzip", 22)?:(char*)memmem(u->buf, u->headlen, "Content-Encoding:  gzip", 23);
	if(p != NULL) {
		u->gzipped = 1;
		debugf("[%d] Gzipped!\n",u->index);
	}

	find_content_type(u);

	debugf("[%d] status=%d, headlen=%d, content-length=%d, charset=%s\n",u->index,u->status,u->headlen,u->contentlen, u->charset);

	return 1;
}

/**
Perform simple non-blocking read.
It uses callback function that performs the reaing so it can read from both SSL and plain connections.
Length of the read data is not limited if possible.
Unread data may remain in SSL buffers and select(.) may not notify us about it,
because from its point of view they were read.
*/
ssize_t plain_read(const struct surl *u, char *buf, const size_t size, char *errbuf) {
	const int fd = u->sockfd;
	const ssize_t res = read(fd, buf, size);
	if (0 < res) {
		return res;
	}
	if (0 == res) {
		return SURL_IO_EOF;
	}
	if (-1 == res) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return SURL_IO_READ;
		}
	}
	debugf("[%d] read failed: %m\n", u->index);
	sprintf(errbuf, "Downloading content failed (%m)");
	return SURL_IO_ERROR;
}

ssize_t plain_write(const struct surl *u, const char *buf, const size_t size, char *errbuf) {
	const int fd = u->sockfd;
	const ssize_t res = write(fd, buf, size);
	if (0 < res) {
		return res;
	}	
	if (0 == res) {
		return SURL_IO_EOF;
	}
	if (-1 == res) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			return SURL_IO_WRITE;
		}
	}
	debugf("[%d] write failed: %m\n", u->index);
	sprintf(errbuf, "Sending request failed (%m)");
	return SURL_IO_ERROR;
}

static void finish(struct surl *u, surl_callback callback) {

	if (u->gzipped) {
		char *buf;
		int buflen = BUFSIZE - u->headlen;
		int ret;

		buf = (char *)malloc(u->bufp);
		memcpy(buf, u->buf + u->headlen, u->bufp - u->headlen);
		ret = gunzip(u->buf + u->headlen, &buflen, buf, u->bufp - u->headlen);
		debugf("[%d] gzip decompress status: %d (input length: %d, output length: %d)\n", u->index, ret, u->bufp - u->headlen, buflen);
		if (ret == 0) {
			u->bufp = buflen + u->headlen;
		} else {
			sprintf(u->error_msg, "Gzip decompression error %d", ret);
			u->status = SURL_S_DOWNLOADED - SURL_S_ERROR;
			u->bufp = u->headlen;
		}
	}

	if (!*u->charset) {
		unsigned charset_len = 0;
		char *charset = detect_charset_from_html(u->buf + u->headlen, u->bufp - u->headlen, &charset_len);
		if (charset && charset_len < sizeof(u->charset)) {
			*(char*)mempcpy(u->charset, charset, charset_len) = 0;
		}
	}
	if (!*u->charset) {
		strcpy(u->charset, "unknown");
	}
	if (*u->charset && u->options & 1<<SURL_OPT_CONVERT_TO_UTF8) {
		conv_charset(u);
	}
	if (u->options & 1<<SURL_OPT_CONVERT_TO_TEXT) {
		u->bufp=converthtml2text(u->buf+u->headlen, u->bufp-u->headlen)+u->headlen;
	}

	u->timing.done = get_time_int();

	callback(u);

	debugf("[%d] Done.\n",u->index);
	set_atomic_int(&u->state, SURL_S_DONE);
}

/**
 * Sets the url to initial state
 */
static void reset_url(struct surl *u) {
	u->status = 0;
	u->location[0] = 0;
	if (u->post != NULL) {
		free(u->post);
		u->post = NULL;
	}
	u->bufp = 0;
	u->headlen = 0;
	u->contentlen = -1;
	u->chunked = 0;
	u->gzipped = 0;
	u->ssl_options = 0;

	memset(&u->timing, 0, sizeof(u->timing));
}

/**
 * Turn the state to INTERNAL ERROR with information that
 * we have been requested to download url with unsupported protocol.
 */
static void set_unsupported_protocol(struct surl *u) {
	debugf("[%d] Unsupported protocol: [%s]\n", u->index, u->proto);
	sprintf(u->error_msg, "Protocol [%s] not supported", u->proto);
	set_atomic_int(&u->state, SURL_S_ERROR);
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
static int check_proto(struct surl *u) {
	const int port = parse_proto(u->proto);
	switch (port) {
		case 80:
			u->f.read = plain_read;
			u->f.write = plain_write;
			u->f.handshake = empty_handshake;
			break;

		case 443:
			if (u->options & 1<<SURL_OPT_NONSSL) {
				set_unsupported_protocol(u);
				return -1;
			} else {
				u->f.read = sec_read;
				u->f.write = sec_write;
				u->f.handshake = sec_handshake;
			}
			break;

		default:
			set_unsupported_protocol(u);
			return -1;
	}
	return port;
}

/** vyres presmerovani
 */
static void resolvelocation(struct surl *u) {
	if (--u->redirect_limit <= 0) {
		debugf("[%d] Exceeded redirects limit", u->index);
		sprintf(u->error_msg, "Too many redirects, possibly a redirect loop");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	char ohost[ strlen(u->host) ];
	strcpy(ohost, u->host);

	debugf("[%d] Resolve location='%s'\n", u->index, u->location);

	if (!urlencode(u->location)) {
		debugf("[%d] Not enough memory for urlencode '%s'\n", u->index, u->location);
		sprintf(u->error_msg, "URL is too long");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	// workaround for uriparser bug with resolving URI "/"
	if (u->location[0] == '/' && (
				u->location[1] == 0 ||
				u->location[1] == '?' ||
				u->location[1] == '#'
				)
	   ) {
		memmove(u->location + 2, u->location + 1, strlen(u->location));
		u->location[1] = '.';
	}

	UriParserStateA state;
	UriUriA locUri, *uri;

	state.uri = &locUri;
	if (uriParseUriA(&state, u->location) != URI_SUCCESS) {
		uriFreeUriMembersA(&locUri);

		debugf("[%d] error: url='%s' failed to parse\n", u->index, u->location);
		sprintf(u->error_msg, "Failed to parse URL %s", u->location);
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	// méně striktní resolvování url ve tvaru http:g
	// see http://tools.ietf.org/html/rfc3986#section-5 section 5.4.2
	if (locUri.scheme.first != NULL && locUri.hostText.first == NULL && locUri.pathHead != NULL && locUri.pathHead->text.first != NULL) {
		locUri.hostText = u->uri->hostText;
		locUri.hostData = u->uri->hostData;
	}

	uri = (UriUriA *)malloc(sizeof(UriUriA));

	if (uriAddBaseUriA(uri, &locUri, u->uri) != URI_SUCCESS) {
		uriFreeUriMembersA(&locUri);
		uriFreeUriMembersA(uri);
		free(uri);

		debugf("[%d] error: url='%s' failed to resolve\n", u->index, u->location);
		sprintf(u->error_msg, "Failed to resolve URL %s", u->location);
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	uriFreeUriMembersA(&locUri);

	// normalizujeme
	uriNormalizeSyntaxA(uri);

	int chars;
	chars = 0;
	if (u->redirectedto != NULL) free(u->redirectedto);
	if (uriToStringCharsRequiredA(uri, &chars) != URI_SUCCESS) {
		debugf("[%d] failed recomposing uri\n", u->index);
	}
	u->redirectedto = malloc(chars + 1);
	if (uriToStringA(u->redirectedto, uri, chars + 1, NULL) != URI_SUCCESS) {
		debugf("[%d] failed recomposing uri\n", u->index);
	}

	if (set_new_uri(u, u->redirectedto) == 0) {
		return;
	}

	if (strcmp(u->host, ohost) == 0) {
		// muzes se pripojit na tu puvodni IP
		free_addr(u->prev_addr);
		u->prev_addr = (struct addr*)malloc(sizeof(struct addr));
		memcpy(u->prev_addr, u->addr, sizeof(struct addr));
		u->prev_addr->next = NULL;
		set_atomic_int(&u->state, SURL_S_GOTIP);
	} else {
		// zmena host
		if (get_atomic_int(&u->state) != SURL_S_GOTIP) {
			// pokud jsme nedostali promo ip, přepneme se do ipv4
			u->addrtype = AF_INET;
		}
	}

	struct redirect_info *rinfo = malloc(sizeof(*rinfo));
	bzero(rinfo, sizeof(*rinfo));
	rinfo->url = malloc(strlen(u->location)+1);
	strcpy(rinfo->url, u->location);
	rinfo->status = u->status;
	memcpy(&rinfo->timing, &u->timing, sizeof(u->timing));
	rinfo->next = u->redirect_info;
	u->redirect_info = rinfo;

	// GET method after redirect
	strcpy(u->method, "GET");
	reset_url(u);
}

/**
Try read some data from the socket, check that we have some available place in the buffer.
*/
static ssize_t try_read(struct surl *u) {
	ssize_t left = BUFSIZE - u->bufp;
	if(left <= 0) {
		return 0;
	}

	return u->f.read(u, u->buf + u->bufp, left, (char *)&u->error_msg);
}

/** cti odpoved
 */
static void readreply(struct surl *u) {
	const ssize_t t = try_read(u);
	assert(t >= SURL_IO_WRITE);
	if (t == SURL_IO_READ) {
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_READ);
		return;
	}
	if (t == SURL_IO_WRITE) {
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_WRITE);
		return;
	}
	if (t >= 0) {
		u->bufp += t;
		u->timing.lastread = get_time_int();
	}
	if (t > 0 && !u->timing.firstbyte) {
		u->timing.firstbyte = u->timing.lastread;
	}

	debugf("[%d] Read %zd bytes; bufp = %d; chunked = %d; data = [%.*s]\n", u->index, t, u->bufp, !!u->chunked, t, u->buf + u->bufp - t);
	if (u->headlen == 0 && find_head_end(u)) {
		detecthead(u);		// pokud jsme to jeste nedelali, tak precti hlavicku
	}
	
	// u->chunked is set in detecthead()
	if(t > 0 && u->chunked) {
		//debugf("debug: bufp=%d nextchunkedpos=%d",u->bufp,u->nextchunkedpos);
		while(u->bufp > u->nextchunkedpos) {
			const int i = eatchunked(u);	// pokud jsme presli az pres chunked hlavicku, tak ji sezer
			if(i == -1) {
				break;
			}
		}
	}
	
	if(t == SURL_IO_EOF || t == SURL_IO_ERROR || (u->contentlen != -1 && u->bufp >= u->headlen + u->contentlen)) {
		if (u->ssl != NULL) {
			SSL_free(u->ssl);
			u->ssl = NULL;
		}
		close(u->sockfd); // FIXME: Is it correct to close the connection before we read the whole reply from the server?
		debugf("[%d] Closing connection (socket %d)\n", u->index, u->sockfd);

		if (t == SURL_IO_ERROR) {
			set_atomic_int(&u->state, SURL_S_ERROR);
		} else if (get_atomic_int(&u->state) != SURL_S_ERROR) {
			set_atomic_int(&u->state, SURL_S_DOWNLOADED);
			debugf("[%d] Downloaded.\n",u->index);
			if (u->location[0] && strcmp(u->method, "HEAD")) {
				resolvelocation(u);
			}
		}
	} else {
		set_atomic_int(&u->state, SURL_S_RECVREPLY);
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_READ);
	}
}

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede systemovy select nad vsemi streamy
 */
static void selectall(struct surl *url) {
	fd_set set;
	fd_set writeset;
	struct timeval timeout;	
	struct surl *curl;
	
	FD_ZERO (&set);
	FD_ZERO (&writeset);

	int wantio = 0;
	
	timeout.tv_sec = 0;
	timeout.tv_usec = 20000;
	
	curl = url;
	do {
		const int state = get_atomic_int(&curl->state);
		const int rw = get_atomic_int(&curl->rw);
		debugf("[%d] select.state = [%s][%d]\n", curl->index, state_to_s(state), want_io(state, rw));
		if (!want_io(state, rw)) {
			continue;
		}
		wantio = 1;
		if(rw & 1<<SURL_RW_WANT_READ) {
			FD_SET(curl->sockfd, &set);
		}
		
		if(rw & 1<<SURL_RW_WANT_WRITE) {
			FD_SET(curl->sockfd, &writeset);
		}
	} while ((curl = curl->next) != NULL);
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
	curl = url;
	do {
		const int rw = !!FD_ISSET(curl->sockfd, &set) << SURL_RW_READY_READ | !!FD_ISSET(curl->sockfd, &writeset) << SURL_RW_READY_WRITE;
		if (rw) {
			set_atomic_int(&curl->rw, rw);
		} else {
			// Do nothing, this way you preserve the original value !!
		}
	} while ((curl = curl->next) != NULL);
}


/** provede jeden krok pro dane url
 */
static void goone(struct surl *u, const struct ssettings *settings, surl_callback callback) {
	const int state = get_atomic_int(&u->state);
	const int rw = get_atomic_int(&u->rw);
	int timeout;

	debugf("[%d] state = [%s][%d]\n", u->index, state_to_s(state), want_io(state, rw));

	if (want_io(state, rw)) {
		timeout = (settings->timeout > 6 ? settings->timeout / 3 : 2) * 1000;

		switch(state) {
		case SURL_S_CONNECT:
			if (u->addr->next && get_time_int() - u->timing.connectionstart > timeout) {
				struct addr *next = u->addr->next;
				free(u->addr);
				u->addr = next;
				debugf("[%d] Connection timeout (%d ms), trying another ip\n", u->index, timeout);
				close(u->sockfd);
				set_atomic_int(&u->state, SURL_S_GOTIP);
			}
			break;
		case SURL_S_HANDSHAKE:
			if (get_time_int() - u->timing.handshakestart > timeout) {
				// we retry handshake with another protocol
				if (lower_ssl_protocol(u) == 0) {
					debugf("[%d] SSL handshake timeout (%d ms), closing connection\n", u->index, timeout);

					SSL_free(u->ssl);
					close(u->sockfd);
					set_atomic_int(&u->state, SURL_S_GOTIP);
				}
			}
			break;
		}

		return;  // select will look after this state
	}
	check_io(state, rw); // Checks that when we need some io, then the socket is in readable/writeable state

	const int time = get_time_int();

	switch(state) {  
	case SURL_S_JUSTBORN:
		u->f.parse_url(u);
		break;

	case SURL_S_PARSEDURL:
		if (!u->timing.dnsstart) u->timing.dnsstart = time;
		u->f.launch_dns(u);
		break;
  
	case SURL_S_INDNS:
		u->f.check_dns(u);
		break;

	case SURL_S_GOTIP:
		if (test_free_channel(u->addr->ip, settings->delay, u->prev_addr && !strcmp(u->addr->ip, u->prev_addr->ip))) {
			if (!u->timing.connectionstart) u->timing.connectionstart = time;
			if (!u->downstart) u->downstart = time;
			u->f.open_socket(u);
		}
		break;
  
	case SURL_S_CONNECT:
		u->f.connect_socket(u);
		break;

	case SURL_S_HANDSHAKE:
		u->timing.handshakestart = time;
		u->f.handshake(u);
		break;

	case SURL_S_GENREQUEST:
		u->f.gen_request(u);
		break;

	case SURL_S_SENDREQUEST:
		if (!u->timing.requeststart) u->timing.requeststart = time;
		u->f.send_request(u);
		break;

	case SURL_S_RECVREPLY:
		if (!u->timing.requestend) u->timing.requestend = time;
		u->f.recv_reply(u);
		break;

	case SURL_S_DOWNLOADED:
		finish(u, callback);
		break;
  
	case SURL_S_ERROR:
		assert(u->status < 0);
		finish(u, callback);
		break;
	}

	const int stateAfter = get_atomic_int(&u->state);
	if (stateAfter == SURL_S_ERROR) {
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
static int exitprematurely(struct surl *url) {
	int tim;
	int cnt = 0, notdone = 0, lastread = 0;
	struct surl *curl;
	
	curl = url;
	do {
		const int url_state = get_atomic_int(&curl->state);
		if(url_state<SURL_S_DONE) {
			notdone++;
		}
		if(curl->timing.lastread>lastread) {
			lastread=curl->timing.lastread;
		}
		cnt++;
	} while ((curl = curl->next) != NULL);
	
	debugf("[-] impatient: %d not done, last read at %d ms (now %d)\n",notdone,lastread,tim);
	
	if(cnt >= 5 && notdone == 1 && (tim-lastread) > 400) {
		debugf("[-] Forcing premature end 1!\n");
		return 1;
	}
	if(cnt >= 20 && notdone <= 2 && (tim-lastread) > 400) {
		debugf("[-] Forcing premature end 2!\n");
		return 1;
	}
	
	return 0;
}

/** vypise obsah vsech dosud neuzavrenych streamu
 */
static void outputpartial(struct surl *url, surl_callback callback) {
	struct surl *curl;

	curl = url;
	do {
		const int url_state = get_atomic_int(&curl->state);
		if(url_state < SURL_S_DONE) {
			finish(curl, callback);
		}
	} while ((curl = curl->next) != NULL);
}

void init_settings(struct ssettings *settings) {
	memset(settings, 0, sizeof(struct ssettings));
	settings->timeout = DEFAULT_TIMEOUT;
	settings->delay = DEFAULT_DELAY;
}

/**
 * Init URL struct
 */
void init_url(struct surl *u, const char *url, const int index, char *post, struct cookie *cookies, const int cookiecnt) {
	reset_url(u);

	// Init the url
	u->index = index;
	u->state = SURL_S_JUSTBORN;
	u->redirect_limit = MAX_REDIRECTS;
	if (strlen(url) > MAXURLSIZE) {
		*(char*)mempcpy(u->rawurl, url, MAXURLSIZE) = 0;
		sprintf(u->error_msg, "URL is too long");
		set_atomic_int(&u->state, SURL_S_ERROR);
	} else {
		strcpy(u->rawurl, url);
	}
	if (u->options & 1<<SURL_OPT_IPV6) {
		u->addrtype = AF_INET6;
	} else {
		u->addrtype = AF_INET;
	}
	if (!u->method[0]) {
		strcpy(u->method, post == NULL ? "GET" : "POST");
	}
	if (post != NULL) {
		u->post = post;
	}
	for (int i = 0; i < cookiecnt; i++) {
		u->cookies[i].name = malloc(strlen(cookies[i].name) + 1);
		u->cookies[i].value = malloc(strlen(cookies[i].value) + 1);
		u->cookies[i].domain = malloc(strlen(cookies[i].domain) + 1);
		u->cookies[i].path = malloc(strlen(cookies[i].path) + 1);

		strcpy(u->cookies[i].name, cookies[i].name);
		strcpy(u->cookies[i].value, cookies[i].value);
		strcpy(u->cookies[i].domain, cookies[i].domain);
		strcpy(u->cookies[i].path, cookies[i].path);
		u->cookies[i].host_only = cookies[i].host_only;
		u->cookies[i].secure = cookies[i].secure;
		u->cookies[i].expire = cookies[i].expire;
	}
	u->cookiecnt = cookiecnt;

	// init callbacks
	u->f = (struct surl_func) {
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
void go(struct surl *url, const struct ssettings *settings, surl_callback callback) {
	int done;
	int change;
	struct surl *curl;

	debug = settings->debug;
	do {
		done = 1;
		change = 0;
		
		selectall(url);
		curl = url;
		do {
			//debugf("%d: %d\n",t,curl->state);
			const int state = get_atomic_int(&curl->state);
			if(state < SURL_S_DONE) {
				goone(curl, settings, callback);
				done = 0;
			}
			// curl->state can change inside goone
			if(state != get_atomic_int(&curl->state)) {
				change = 1;
			}
		} while ((curl = curl->next) != NULL);

		const int t = get_time_int();
		if(t > settings->timeout*1000) {
			debugf("Timeout (%d ms elapsed). The end.\n", t);
			if(settings->partial) {
				outputpartial(url, callback);
			}
			break;
		}
		if(!change && !done) {
			if (settings->impatient && t >= settings->timeout*1000-1000) {
				done = exitprematurely(url);
			}
		}
	} while(!done);
	
	if(done) {
		debugf("All successful. Took %d ms.\n", get_time_int());
	}
}
