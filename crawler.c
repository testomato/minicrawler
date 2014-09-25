#define _GNU_SOURCE // memmem(.) needs this :-(
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <ares.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "h/struct.h"
#include "h/proto.h"
#include "h/version.h"

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

/** Impement handshake over SSL non-blocking socket.
We may switch between need read/need write for several times.
SSL is blackbox this time for us.
*/
static void sec_handshake(struct surl *u) {
	assert(u->ssl);

	SSL_set_tlsext_host_name(u->ssl, u->host);

	const int t = SSL_connect(u->ssl);
    if (t == 1) {
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
    if (err == SSL_ERROR_ZERO_RETURN) {
		debugf("[%d] Connection closed (in handshake)", u->index);
		sprintf(u->error_msg, "SSL connection closed during handshake");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
    }

	debugf("[%d] Unexpected SSL error (in handshake): %d, %d\n", u->index, err, t);
	ERR_print_errors_fp(stderr);

	if (SSL_get_options(u->ssl) & SSL_OP_NO_TLSv1) {
		sprintf(u->error_msg, "Unexpected SSL error during handshake");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}
	else {
		// zkusíme ještě jednou bez TLSv1
		debugf("[%d] Trying to switch to SSLv3\n", u->index);
		u->ssl_options = u->ssl_options | SSL_OP_NO_TLSv1;
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
static ssize_t sec_read(const struct surl *u, char *buf, const size_t size) {
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
	if (err == SSL_ERROR_WANT_WRITE) {
		return SURL_IO_WRITE;
	}
	if (err == SSL_ERROR_WANT_READ) {
		return SURL_IO_READ;
	}
	return SURL_IO_ERROR;
}

/** Write some data to SSL socket.
NOTE: We must write as much as possible otherwise
select(.) would not notify us that socket is writable again.
*/
static ssize_t sec_write(const struct surl *u, const char *buf, const size_t size) {
    assert(u->ssl);

	const int t = SSL_write(u->ssl, buf, size);
	if (t > 0) {
		return (ssize_t)t;
	}

	const int err = SSL_get_error(u->ssl, t);
	if (err == SSL_ERROR_WANT_READ) {
		return SURL_IO_READ;
	}
	if (err == SSL_ERROR_WANT_WRITE) {
		return SURL_IO_WRITE;
	}
	return SURL_IO_ERROR;
}

/** callback funkce, kterou zavola ares
 */
static void dnscallback(void *arg, int status, int timeouts, struct hostent *hostent) {
	unsigned char *ip;
	struct surl *u;
	
	u=(struct surl *)arg;
	if (status != ARES_SUCCESS) {
		debugf("[%d] gethostbyname error: %s: %s\n", u->index, (char *) arg, ares_strerror(status));
		sprintf(u->error_msg, "%s", ares_strerror(status));
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}
	
	if (hostent->h_addr == NULL) {
		debugf("[%d] Could not resolve host\n", u->index);
		sprintf(u->error_msg, "Could not resolve host");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	ip=(unsigned char*)(hostent->h_addr);
	u->prev_ip = u->ip;
	u->ip=*(int *)ip;
	
	debugf("[%d] Resolving %s ended => %d.%d.%d.%d\n", u->index, u->host, ip[0], ip[1], ip[2], ip[3]);
	debugf("[%d] raw url => %s\n", u->index, u->rawurl);

	set_atomic_int(&u->state, SURL_S_GOTIP);
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

static int check_proto(struct surl *u);

/** primitivni parsovatko url
 */
static int simpleparseurl(struct surl *u, const char *url) {
	int r;
	char doubledot[2];

	u->port = 0;
	u->proto[0] = 0;
	u->path[0] = '/';
	u->path[1] = 0;

	r = sscanf(url, "%31[^:/?#]://%255[^:/?#]%1[:]%99d%4095[^\n#]", u->proto, u->host, doubledot, &(u->port), u->path);
	if (r < 2) {
		debugf("[%d] error: url='%s' failed to parse\n", u->index, url);
		return 0;
	} else if (r < 3) { // nematchnuli jsme dvojtečku
		const char fmt[] = "%%%d[^:]://%%%d[^/]/%%4094[^\n#]";
		char buf[256];
		sprintf(buf, fmt, I_LENGTHOF(u->proto), I_LENGTHOF(u->host));
		r = sscanf(url, buf, u->proto, u->host, u->path + 1);
		if (r < 2) {
			debugf("[%d] error: url='%s' failed to parse\n", u->index, url);
			return 0;
		}

		u->port = parse_proto(u->proto);
	} else if (r == 3) {// prázdný port
		u->port = parse_proto(u->proto);
	}

	debugf("[%d] proto='%s' host='%s' port=%d path='%s'\n", u->index, u->proto, u->host, u->port, u->path);
	return 1;
}

/** spusti preklad pres ares
 */
static void launchdns(struct surl *u) {
	if (check_proto(u) == -1) {
		return;
	}

	int t;

	debugf("[%d] Resolving %s starts\n", u->index, u->host);
	t = ares_init(&(u->aresch));
	if(t) {
		debugf("ares_init failed\n");
		exit(-1);
	}

	set_atomic_int(&u->state, SURL_S_INDNS);
	ares_gethostbyname(u->aresch,u->host,AF_INET,(ares_host_callback)&dnscallback,u);
}

/** uz je ares hotovy?
 */
static void checkdns(struct surl *u) {
	int t;
	fd_set readfds;
	fd_set writefds;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	t = ares_fds(u->aresch, &readfds, &writefds);
	if(!t) {
		return;
	}

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
		debugf("%d: Cannot connect, getsoskopt(.) returned error status: %m", u->index);
		sprintf(u->error_msg, "Failed to connect to host (%m)");
		set_atomic_int(&u->state, SURL_S_ERROR);
		close(u->sockfd);
		return;
	}

	if (result != 0) {
		debugf("%d: Cannot connect, attempt to connect failed", u->index);
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
	u->ssl = ssl;

	return 1;
}

/** uz znam IP, otevri socket
 */
static void opensocket(struct surl *u)
{
	struct sockaddr_in addr;
	int flags;

	addr.sin_family=AF_INET;
	addr.sin_port=htons(u->port);
	memcpy(&(addr.sin_addr), &(u->ip), 4);

	u->sockfd=socket(AF_INET, SOCK_STREAM, 0);
	flags = fcntl(u->sockfd, F_GETFL,0);              // Get socket flags
	fcntl(u->sockfd, F_SETFL, flags | O_NONBLOCK);   // Add non-blocking flag	

	debugf("[%d] connecting to ip: %x, port: %i (socket %d)\n", u->index, u->ip, u->port, u->sockfd);
	const int t = connect(u->sockfd, (struct sockaddr *)&addr, sizeof(addr));
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

/** neci kod na str_replace (pod free licenci)
 */
static char *str_replace( const char *string, const char *substr, const char *replacement ) {
	char *tok = NULL;
	char *newstr = NULL;
 
	tok = strstr( string, substr );
	if( tok == NULL ) return strdup( string );
	newstr = malloc( strlen( string ) - strlen( substr ) + strlen( replacement ) + 1 );
	if( newstr == NULL ) return NULL;
	memcpy( newstr, string, tok - string );
	memcpy( newstr + (tok - string), replacement, strlen( replacement ) );
	memcpy( newstr + (tok - string) + strlen( replacement ), tok + strlen( substr ), strlen( string ) - strlen( substr ) - ( tok - string ) );
	memset( newstr + strlen( string ) - strlen( substr ) + strlen( replacement ), 0, 1 );
	return newstr;
} 

/** socket bezi, posli dotaz
 * cookie header see http://tools.ietf.org/html/rfc6265 section 5.4
 */
static void genrequest(struct surl *u) {
	const char getrqfmt[] = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s\r\n";
	const char postrqfmt[] = "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n%s\r\n%s";

	char host[262];
	char agent[256];
	char cookiestring[4096];
	char customheader[4096];

	const int port = parse_proto(u->proto);
	strcpy(host, u->host);
	if (port != u->port) {
		sprintf(host + strlen(u->host), ":%d", u->port);
	}

	if (settings.customagent[0]) {
		safe_cpy(agent, settings.customagent, sizeof(agent));
	} else {
		sprintf(agent, "minicrawler/%s", VERSION);
	}

	// vytvoří si to řetězec cookies a volitelných parametrů
	cookiestring[0] = 0;
	char *p;
	for (int t = 0; t < u->cookiecnt; t++) {
		// see http://tools.ietf.org/html/rfc6265 section 5.4
		// TODO: The request-uri's path path-matches the cookie's path.
		if (
				(u->cookies[t].host_only == 1 && strcasecmp(u->host, u->cookies[t].domain) == 0 ||
					u->cookies[t].host_only == 0 && (p = strcasestr(u->host, u->cookies[t].domain)) != NULL && *(p+strlen(u->cookies[t].domain)+1) == '\0') &&
				(u->cookies[t].secure == 0 || strcmp(u->proto, "https") == 0)
		) {
			if (!cookiestring[0]) {
				sprintf(cookiestring, "Cookie: %s=%s", u->cookies[t].name, u->cookies[t].value);
			}
			else {
				sprintf(cookiestring+strlen(cookiestring), "; %s=%s", u->cookies[t].name, u->cookies[t].value);
			}
		}
	}
	if (strlen(cookiestring)) {
		sprintf(cookiestring + strlen(cookiestring), "\r\n");
	}
	if(settings.customheader[0]) {
		sprintf(customheader,"%s\r\n",settings.customheader);
		if(u->customparam[0]) {
			char *p = str_replace(customheader, "%", u->customparam);
			strcpy(customheader,p);
		}
		strcpy(cookiestring+strlen(cookiestring), customheader);
	}
	if (settings.gzip) {
		strcpy(cookiestring+strlen(cookiestring), "Accept-Encoding: gzip\r\n");
	}

	// FIXME: Check beffers length and vice verse
	free(u->request);
	if(!u->ispost) {// GET
		u->request_len = sizeof(getrqfmt) + strlen(u->path) + strlen(agent) + strlen(host) + strlen(cookiestring);
		u->request = malloc(u->request_len + 1);
		sprintf(u->request, getrqfmt, u->path, host, agent, cookiestring);
	} else { // POST
		u->request_len = sizeof(postrqfmt) + strlen(u->path) + strlen(agent) + strlen(host) + strlen(cookiestring) + strlen(u->post) + 9; // 9 - dost místa na content-length
		u->request = malloc(u->request_len + 1);
		sprintf(u->request, postrqfmt, u->path, host, agent, (int)strlen(u->post), cookiestring, u->post);
	}
	debugf("Request: [%s]", u->request);
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
		const ssize_t ret = u->f.write(u, &u->request[u->request_it], u->request_len - u->request_it);
		if (ret == SURL_IO_ERROR || ret == SURL_IO_EOF) {
			debugf("[%d] Error when writing to socket: %m\n", u->index);
			sprintf(u->error_msg, "Connection to host lost (%m)");
			set_atomic_int(&u->state, SURL_S_ERROR);
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

/** strcpy, ktere se ukonci i koncem radku
 */
static void strcpy_term(char *to, char *from) {
	for(;*from && *from != '\r' && *from != '\n';) *to++ = *from++;
	*to = 0;
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

char *trim(char *str) {
	int len = strlen(str);
	while ((str[0] == ' ' || str[0] == '\t') && str[0] != '\0') str++;
	while ((str[len-1] == ' ' || str[len-1] == '\t') && len > 0) str[--len] = '\0';
	return str;
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

	cookie.name = trim(cookie.name);
	cookie.value = trim(cookie.value);

	if (strlen(cookie.name) == 0) {
		debugf("[%d] Cookie string '%s' has empty name\n", u->index, namevalue);
		return;
	}
	
	// parse cookie attributes
	struct nv attributes[10];
	struct nv *attr;
	int att_len = 0;
	p = attributestr;
	while (p[0] != '\0') {
		if (att_len > 10) {
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
		attr->name = trim(attr->name);
		attr->value = trim(attr->value);
		
		p = q;
	}

	// process attributes
	cookie.secure = 0;
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
				attr->value++;
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
		u->cookies[t].name = cookie.name;
		u->cookies[t].value = cookie.value;
		u->cookies[t].domain = cookie.domain;
		u->cookies[t].secure = cookie.secure;
		u->cookies[t].host_only = cookie.host_only;
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
static void detecthead(struct surl *u) {
	u->status = atoi(u->buf + 9);
	u->buf[u->bufp] = 0;
	
	char *p = find_head_end(u);

	if(p == NULL) {
		debugf("[%d] cannot find end of http header?\n", u->index);
		return;
	}
	
	u->headlen = p-u->buf;
	debugf("[%d] buf='%s'\n", u->index, u->buf);
	
	p=(char*)memmem(u->buf, u->headlen, "Content-Length: ", 16)?:(char*)memmem(u->buf, u->headlen, "Content-length: ", 16)?:(char*)memmem(u->buf, u->headlen, "content-length: ", 16);
	if(p != NULL) {
		u->contentlen = atoi(p + 16);
	}
	debugf("[%d] Head, Content-Length: %d\n", u->index, u->contentlen);

	p=(char*)memmem(u->buf,u->headlen,"\nLocation: ",11)?:(char*)memmem(u->buf,u->headlen,"\nlocation: ",11);
	if(p!=NULL) {
		strcpy_term(u->location,p+11);
		debugf("[%d] Location='%s'\n",u->index,u->location);
	}

	p=(char*)memmem(u->buf,u->headlen,"\nRefresh: 0;url=",16)?:(char*)memmem(u->buf,u->headlen,"\nrefresh: 0;url=",16);
	if(p!=NULL) {
		strcpy_term(u->location,p+16);
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
}

/**
Perform simple non-blocking read.
It uses callback function that performs the reaing so it can read from both SSL and plain connections.
Length of the read data is not limited if possible.
Unread data may remain in SSL buffers and select(.) may not notify us about it,
because from its point of view they were read.
*/
ssize_t plain_read(const struct surl *u, char *buf, const size_t size) {
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
	return SURL_IO_ERROR;
}

ssize_t plain_write(const struct surl *u, const char *buf, const size_t size) {
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
	return SURL_IO_ERROR;
}


/** vypise vystup na standardni vystup
 */
static void output(struct surl *u) {
	unsigned char header[16384];

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
			u->status = -2;
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
	if (*u->charset && settings.convert_to_utf) {
		conv_charset(u);
	}
	if(settings.convert) {
		u->bufp=converthtml2text(u->buf+u->headlen, u->bufp-u->headlen)+u->headlen;
	}
	sprintf(header,"URL: %s\n",u->rawurl);
	if(u->redirectedto[0]) sprintf(header+strlen(header),"Redirected-To: %s\n",u->redirectedto);
	for (struct redirect_info *rinfo = u->redirect_info; rinfo; rinfo = rinfo->next) {
		sprintf(header+strlen(header), "Redirect-info: %s %d\n", rinfo->url, rinfo->status);
	}
	sprintf(header+strlen(header),"Status: %d\nContent-length: %d\n",u->status,u->bufp-u->headlen);

	const int url_state = get_atomic_int(&u->state);
	if (url_state <= SURL_S_RECVREPLY) {
		char timeouterr[50];
		switch (url_state) {
			case SURL_S_JUSTBORN:
				strcpy(timeouterr, "Process has not started yet"); break;
			case SURL_S_INDNS:
				strcpy(timeouterr, "Timeout while contacting DNS servers"); break;
			case SURL_S_GOTIP:
				if (u->downstart) {
					strcpy(timeouterr, "Connection timed out");
				} else {
					strcpy(timeouterr, "Waiting for download slot");
				}
				break;
			case SURL_S_CONNECT:
				strcpy(timeouterr, "Connection timed out"); break;
			case SURL_S_HANDSHAKE:
				strcpy(timeouterr, "Timeout during SSL handshake"); break;
			case SURL_S_GENREQUEST:
				strcpy(timeouterr, "Timeout while generating HTTP request"); break;
			case SURL_S_SENDREQUEST:
				strcpy(timeouterr, "Timeout while sending HTTP request"); break;
			case SURL_S_RECVREPLY:
				strcpy(timeouterr, "HTTP server timed out"); break;
		}

		sprintf(header+strlen(header), "Timeout: %d (%s); %s\n", url_state, state_to_s(url_state), timeouterr);
	}
	if (*u->error_msg) {
		sprintf(header+strlen(header), "Error-msg: %s\n", u->error_msg);
	}
	if (*u->charset) {
		sprintf(header+strlen(header), "Content-type: text/html; charset=%s\n", u->charset);
	}
	if (u->cookiecnt) {
		sprintf(header+strlen(header), "Cookies: %d\n", u->cookiecnt);
		// netscape cookies.txt format
		// @see http://www.cookiecentral.com/faq/#3.5
		for (int t = 0; t < u->cookiecnt; t++) {
			sprintf(header+strlen(header), "%s\t%d\t/\t%d\t0\t%s\t%s\n", u->cookies[t].domain, u->cookies[t].host_only/*, u->cookies[t].path*/, u->cookies[t].secure/*, u->cookies[t].expiration*/, u->cookies[t].name, u->cookies[t].value);
		}
	}
	if (u->conv_errno) {
		char err_buf[128];
#		ifdef __APPLE__
		char *err = !strerror_r(u->conv_errno, err_buf, sizeof(err_buf)) ? err_buf : "Unknown error";
#		else
		char *err = strerror_r(u->conv_errno, err_buf, sizeof(err_buf));
#		endif
		sprintf(header+strlen(header), "Conversion error: %s\n", err);
	}
	sprintf(header+strlen(header),"Downtime: %dms; %dms (ip=0x%x; %u)\n",u->lastread - u->downstart, u->downstart, u->ip, get_time_slot(u->ip));
	sprintf(header+strlen(header),"Index: %d\n\n",u->index);

	write_all(STDOUT_FILENO, header, strlen(header));
	if(settings.writehead) {
		debugf("[%d] outputting header %dB - %d %d %d %d\n",u->index,u->headlen,u->buf[u->headlen-4],u->buf[u->headlen-3],u->buf[u->headlen-2],u->buf[u->headlen-1]);
		write_all(STDOUT_FILENO, u->buf, u->headlen);
		if (0 == u->headlen) {
			write_all(STDOUT_FILENO, "\n", 1); // PHP library expects one empty line at the end of headers, in normal circumstances it is contained
						      // within u->buf[0 .. u->headlen] .
		}
	}

	write_all(STDOUT_FILENO, u->buf+u->headlen, u->bufp-u->headlen);
	write_all(STDOUT_FILENO, "\n", 1); // jinak se to vývojářům v php špatně parsuje

	if(u->chunked) debugf("[%d] bufp=%d nextchunkedpos=%d\n",u->index,u->bufp,u->nextchunkedpos);

	debugf("[%d] Outputed.\n",u->index);
	set_atomic_int(&u->state, SURL_S_OUTPUTED);
}

/** vyres presmerovani
 */
static void resolvelocation(struct surl *u) {
	char oproto[ sizeof(u->proto) ];
	char ohost[ sizeof(u->host) ];
	int oport;

	strcpy(oproto, u->proto);
	strcpy(ohost, u->host);
	oport = u->port;

	debugf("[%d] Resolve location='%s'\n", u->index, u->location);

	if (!simpleparseurl(u, u->location)) {
		strcpy(u->proto, oproto);
		strcpy(u->host, ohost);
		u->port = oport;
		if (u->location[0] == '/') {
			// relativni adresy (i kdyz by podle RFC nemely byt)
			strcpy(u->path, u->location);
		} else {
			debugf("[%d] Weird location format, assuming filename in root\n", u->index);
			strcpy(u->path, "/");
			strcpy(u->path+1, u->location);
		}

		debugf("[%d] proto = '%s' host='%s' path='%s'\n", u->index, u->proto, u->host, u->path);
	}

	if (strcmp(u->host,ohost)) {
		set_atomic_int(&u->state, SURL_S_JUSTBORN); // pokud je to jina domena, tak znovu resolvuj
	}
	else {
		u->prev_ip = u->ip;
		set_atomic_int(&u->state, SURL_S_GOTIP);	// jinak se muzes pripojit na tu puvodni IP
	}

	struct redirect_info *rinfo = malloc(sizeof(*rinfo));
	bzero(rinfo, sizeof(*rinfo));
	strcpy(rinfo->url, u->location);
	rinfo->status = u->status;
	rinfo->next = u->redirect_info;
	u->redirect_info = rinfo;
	if (--u->redirect_limit <= 0) {
		debugf("[%d] Exceeded redirects limit", u->index);
		sprintf(u->error_msg, "Too many redirects, possibly a redirect loop");
		set_atomic_int(&u->state, SURL_S_ERROR);
		return;
	}

	strcpy(u->redirectedto, u->location);
	u->status = 0;
	u->location[0] = 0;
	u->ispost = 0;
	u->bufp = 0;
	u->headlen = 0;
	u->contentlen = -1;
	u->chunked = 0;
	u->gzipped = 0;
	u->ssl_options = 0;

	if (check_proto(u) == -1) {
		return;
	}
}

/** uz mame cely vstup - bud ho vypis nebo vyres presmerovani
 */
static void finish(struct surl *u) {
	if(u->headlen==0) {
		detecthead(u);	// nespousteli jsme to predtim, tak pustme ted
	}

	if(u->location[0]) {
		resolvelocation(u);
	} else {
		set_atomic_int(&u->state, SURL_S_DONE);
		debugf("[%d] Done.\n",u->index);
	}
}

/**
Try read some data from the socket, check that we have some available place in the buffer.
*/
static ssize_t try_read(struct surl *u) {
	ssize_t left = BUFSIZE - u->bufp;
	if(left <= 0) {
		return 0;
	}

	return u->f.read(u, u->buf + u->bufp, left);
}

/** cti odpoved
 */
static void readreply(struct surl *u) {
	debugf("} bufp = %d\n", u->bufp);

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
	if (t == SURL_IO_ERROR) {
		debugf("read failed: %m");
	}
	if(t > 0) {
		u->bufp += t;
		u->lastread = get_time_int();
	}

	debugf("}1 bufp = %d; buf = [%.*s]\n", u->bufp, u->bufp, u->buf);
	if (u->headlen == 0 && find_head_end(u)) {
		detecthead(u);		// pokud jsme to jeste nedelali, tak precti hlavicku
	}
	debugf("}2 bufp = %d\n", u->bufp);

	debugf("[%d] Read %zd bytes; bufp = %d; chunked=%d\n", u->index, t, u->bufp, !!u->chunked);
	
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
		close(u->sockfd); // FIXME: Is it correct to close the connection before we read the whole reply from the server?
		debugf("[%d] Closing connection (socket %d)\n", u->index, u->sockfd);
		finish(u); // u->state is changed here
	} else {
		set_atomic_int(&u->state, SURL_S_RECVREPLY);
		set_atomic_int(&u->rw, 1<<SURL_RW_WANT_READ);
	}
}

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede systemovy select nad vsemi streamy
 */
static void selectall(void) {
	fd_set set;
	fd_set writeset;
	struct timeval timeout;	
	struct surl *curl;
	
	FD_ZERO (&set);
	FD_ZERO (&writeset);
	
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
		if(rw & 1<<SURL_RW_WANT_READ) {
			FD_SET(curl->sockfd, &set);
		}
		
		if(rw & 1<<SURL_RW_WANT_WRITE) {
			FD_SET(curl->sockfd, &writeset);
		}
	} while ((curl = curl->next) != NULL);
	switch (select(FD_SETSIZE, &set, &writeset, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "select failed: %m");
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
static void goone(struct surl *u) {
	const int state = get_atomic_int(&u->state);
	const int rw = get_atomic_int(&u->rw);

	debugf("[%d] state = [%s][%d]\n", u->index, state_to_s(state), want_io(state, rw));

	if (want_io(state, rw)) {
		return;  // select will look after this state
	}
	check_io(state, rw); // Checks that when we need some io, then the socket is in readable/writeable state

	const int tim = get_time_int();

	switch(state) {  
	case SURL_S_JUSTBORN:
		u->f.launch_dns(u);
		break;
  
	case SURL_S_INDNS:
		u->f.check_dns(u);
		break;

	case SURL_S_GOTIP:
		if ( (u->downstart = test_free_channel(u->ip, settings.delay, u->ip == u->prev_ip)) ) {
			u->f.open_socket(u);
		}
		break;
  
	case SURL_S_CONNECT:
		u->f.connect_socket(u);
		break;

	case SURL_S_HANDSHAKE:
		u->f.handshake(u);
		break;

	case SURL_S_GENREQUEST:
		u->f.gen_request(u);
		break;

	case SURL_S_SENDREQUEST:
		u->f.send_request(u);
		break;

	case SURL_S_RECVREPLY:
		u->f.recv_reply(u);
		break;
  
	case SURL_S_ERROR:
	case SURL_S_INTERNAL_ERROR:
		u->status = -1;
		output(u);
		break;

	case SURL_S_DONE:
		output(u);
		break;
	}

	if (settings.debug) {	
		const int duration = get_time_int() - tim;
		if(duration > 200) {
			debugf("[%d] State %d (->%d) took too long (%d ms)\n", u->index, state, get_atomic_int(&u->state), duration);
		}
	}
}

/** vrati 1 pokud je dobre ukoncit se predcasne
 */
static int exitprematurely(void) {
	int tim;
	int cnt = 0, notdone = 0, lastread = 0;
	struct surl *curl;
	
	tim=get_time_int();
	if(tim<settings.timeout*1000-1000) {
		return 0; // jeste je brzy
	}
	
	curl = url;
	do {
		const int url_state = get_atomic_int(&curl->state);
		if(url_state<SURL_S_DONE) {
			notdone++;
		}
		if(curl->lastread>lastread) {
			lastread=curl->lastread;
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
static void outputpartial(void) {
	struct surl *curl;

	curl = url;
	do {
		const int url_state = get_atomic_int(&curl->state);
		if(url_state <= SURL_S_RECVREPLY) {
			output(curl);
		}
	} while ((curl = curl->next) != NULL);
}

/**
Turn the state to INTERNAL ERROR with information that
we have been requested to download url with unsupported protocol.
*/
static void set_unsupported_protocol(struct surl *u) {
			debugf("Unsupported protocol: [%s]\n", u->proto);
			sprintf(u->error_msg, "Protocol [%s] not supported", u->proto);
			set_atomic_int(&u->state, SURL_S_INTERNAL_ERROR);
}

/**
Check the protocol of the destination url. If it is supported protocol,
then set all callbacks, otherwise turn the state to UNSUPPORTED PROTOCOL.
*/
static int check_proto(struct surl *u) {
	const int port = parse_proto(u->proto);
	switch (port) {
		case 80:
			u->f = (struct surl_func) {
				read:plain_read,
				write:plain_write,
				launch_dns:launchdns,
				check_dns:checkdns,
				open_socket:opensocket,
				connect_socket:connectsocket,
				handshake:empty_handshake,
				gen_request:genrequest,
				send_request:sendrequest,
				recv_reply:readreply,
			};
			break;

		case 443:
			if (settings.non_ssl) {
				set_unsupported_protocol(u);
			} else {
				u->f = (struct surl_func) {
					read:sec_read,
					write:sec_write,
					launch_dns:launchdns,
					check_dns:checkdns,
					open_socket:opensocket,
					connect_socket:connectsocket,
					handshake:sec_handshake,
					gen_request:genrequest,
					send_request:sendrequest,
					recv_reply:readreply,
				};				
			}
			break;

		default:
			set_unsupported_protocol(u);
			break;
	}
	return port;
}

/**
 * Init URL struct
 */
void init_url(struct surl *u, const char *url, const int index, struct cookie *cookies, const int cookiecnt) {
	// Init the url
	strcpy(u->rawurl, url);
	u->index = index;
	simpleparseurl(u, url);
	u->state = SURL_S_JUSTBORN;
	//debugf("[%d] born\n",i);
	u->bufp = 0;
	u->headlen = 0;
	u->contentlen = -1;
	u->cookiecnt = 0;
	u->ssl_options = 0;
	u->redirect_limit = MAX_REDIRECTS;
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

	check_proto(u);
}

/**
 * hlavni smycka
 */
void go(void) {
	int done;
	int change;
	struct surl *curl;
	do {
		done = 1;
		change = 0;
		
		selectall();
		curl = url;
		do {
			//debugf("%d: %d\n",t,curl->state);
			const int state = get_atomic_int(&curl->state);
			if(state < SURL_S_OUTPUTED) {
				goone(curl);
				done = 0;
			}
			// curl->state can change inside goone
			if(state != get_atomic_int(&curl->state)) {
				change = 1;
			}
		} while ((curl = curl->next) != NULL);

		const int t = get_time_int();
		if(t > settings.timeout*1000) {
			debugf("Timeout (%d ms elapsed). The end.\n", t);
			if(settings.partial) {
				outputpartial();
			}
			break;
		}
		if(!change && !done) {
			if(settings.impatient) {
				done = exitprematurely();
			}
			usleep(20000);
		}
	} while(!done);
	
	if(done) {
		debugf("All successful. Took %d ms.\n", get_time_int());
	}
}
