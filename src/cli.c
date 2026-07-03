#define _GNU_SOURCE // memmem(.), strchrnul needs this :-(
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <arpa/inet.h>

#include "h/config.h"
#include "h/string.h"
#include "h/minicrawler.h"

/** vypise napovedu
 */
void printusage()
{
	printf("\nminicrawler, version %s\n\nUsage:   minicrawler [options] [urloptions] url [[url2options] url2]...\n\n"
	         "Where\n"
	         "   options:\n"
	         "         -2         disable HTTP/2\n"
	         "         -6         resolve host to IPv6 address only\n"
	         "         -8         convert from page encoding to UTF-8\n"
	         "         -A STRING  custom user agent (max 255 bytes)\n"
	         "         -b STRING  cookies in the netscape/mozilla file format (max 25 cookies)\n"
	         "         -c         convert content to text format (with UTF-8 encoding)\n"
	         "         -DMILIS    set delay time in miliseconds when downloading more pages from the same IP (default is 100 ms)\n"
	         "         -g         accept gzip encoding\n"
	         "         -h         enable output of HTTP headers\n"
	         "         -i         enable impatient mode (minicrawler exits few seconds earlier if it doesn't make enough progress)\n"
	         "         -I         SSRF protection: refuse loopback/link-local/private addresses and ports other than 80/443\n"
	         "         -k         disable SSL certificate verification (allow insecure connections)\n"
	         "         -l         do not follow redirects\n"
	         "         -mINT      maximum page size in MiB (default 2 MiB)\n"
	         "         -pSTRING   password for HTTP authentication (basic or digest, max 31 bytes)\n"
#ifdef HAVE_LIBSSL
	         "         -S         disable SSL/TLS support\n"
#endif
	         "         -tSECONDS  set timeout (default is 5 seconds)\n"
	         "         -u STRING  username for HTTP authentication (basic or digest, max 31 bytes)\n"
	         "         -v         debug output (to stderr)\n"
	         "         -w STRING  write this custom header to all requests (max 4095 bytes)\n"
	         "\n   urloptions:\n"
	         "         -C STRING  parameter which replaces '%%' in the custom header\n"
	         "         -P STRING  HTTP POST parameters\n"
	         "         -X STRING  custom request HTTP method, no validation performed (max 15 bytes)\n"
	         "\n", VERSION);
}

static int writehead = 0;

/** Abort with a usage error if an option is missing its argument (i.e. it is
 *  the last token on the command line). argv[argc] is NULL, so an unguarded
 *  argv[t+1] would be a NULL dereference. */
#define NEED_ARG(t) do { \
	if ((t) + 1 >= argc) { \
		fprintf(stderr, "minicrawler: option %s requires an argument\n", argv[t]); \
		exit(1); \
	} \
} while (0)

/**
 * Appends formatted output to buf at *plen, never writing past bufsize-1 bytes
 * (buf stays NUL-terminated). On truncation *plen is pinned to bufsize-1 so all
 * subsequent appends become no-ops. Returns the number of bytes appended.
 */
static int append_fmt(char *buf, size_t bufsize, int *plen, const char *fmt, ...) {
	if (bufsize == 0 || (size_t)*plen >= bufsize - 1) {
		*plen = bufsize ? (int)(bufsize - 1) : 0;
		return 0;
	}
	va_list ap;
	va_start(ap, fmt);
	const int n = vsnprintf(buf + *plen, bufsize - *plen, fmt, ap);
	va_end(ap);
	if (n < 0) {
		return 0;
	}
	if ((size_t)n >= bufsize - *plen) {
		*plen = (int)(bufsize - 1); // truncated
		return (int)(bufsize - 1);
	}
	*plen += n;
	return n;
}

/** nacte url z prikazove radky do struktur
 */
void initurls(int argc, char *argv[], mcrawler_url **urls, mcrawler_settings *settings)
{
	mcrawler_url *url;
	long options = 0;
	char customheader[4096 - 2] = ""; // space for \r\n
	char customagent[256] = "";
	char username[32] = "";
	char password[32] = "";
	size_t maxpagesize = 0;
	mcrawler_cookie cookies[COOKIESTORAGESIZE];
	char *p, *q;
	int ccnt = 0, i = 0;

	url = (mcrawler_url *)malloc(sizeof(mcrawler_url));
	memset(url, 0, sizeof(mcrawler_url));

	for (int t = 1; t < argc; ++t) {

		// options
		if(!strcmp(argv[t], "-v")) {settings->debug=1; continue;}
		if(!strcmp(argv[t], "-S")) {options |= 1<<MCURL_OPT_NONSSL; continue;}
		if(!strcmp(argv[t], "-h")) {writehead=1; continue;}
		if(!strcmp(argv[t], "-i")) {settings->impatient=1; continue;}
		if(!strcmp(argv[t], "-I")) {options |= 1<<MCURL_OPT_BLOCK_PRIVATE_IP; continue;}
		if(!strcmp(argv[t], "-c")) {options |= 1<<MCURL_OPT_CONVERT_TO_TEXT | 1<<MCURL_OPT_CONVERT_TO_UTF8; continue;}
		if(!strcmp(argv[t], "-8")) {options |= 1<<MCURL_OPT_CONVERT_TO_UTF8; continue;}
		if(!strcmp(argv[t], "-g")) {options |= 1<<MCURL_OPT_GZIP; continue;}
		if(!strcmp(argv[t], "-k")) {options |= 1<<MCURL_OPT_INSECURE; continue;}
		if(!strcmp(argv[t], "-l")) {options |= 1<<MCURL_OPT_NOT_FOLLOW_REDIRECTS; continue;}
		if(!strncmp(argv[t], "-t", 2)) {settings->timeout = atoi(argv[t]+2); continue;}
		if(!strncmp(argv[t], "-D", 2)) {settings->delay = atoi(argv[t]+2); continue;}
		if(!strcmp(argv[t], "-w")) {NEED_ARG(t); SAFE_STRCPY(customheader, argv[t+1]); t++; continue;}
		if(!strcmp(argv[t], "-A")) {NEED_ARG(t); str_replace(customagent, sizeof(customagent), argv[t+1], "%version%", VERSION); t++; continue;}
		if(!strcmp(argv[t], "-b")) {
			NEED_ARG(t);
			p = argv[t+1];
			while (p[0] != '\0' && ccnt < COOKIESTORAGESIZE) {
				q = strchrnul(p, '\n');
				const size_t linelen = (size_t)(q - p);
				if (linelen == 0) { // skip empty lines
					p = (q[0] == '\n') ? q + 1 : q;
					continue;
				}
				// each whitespace-delimited field is at most the whole line long, +1 for NUL
				char *domain = malloc(linelen + 1);
				char *path   = malloc(linelen + 1);
				char *name   = malloc(linelen + 1);
				char *value  = malloc(linelen + 1);
				int host_only = 0, secure = 0;
				long expires = 0;
				const int matched = sscanf(p, "%s\t%d\t%s\t%d\t%ld\t%s\t%s", domain, &host_only, path, &secure, &expires, name, value);
				if (matched == 7) {
					cookies[ccnt].domain = domain;
					cookies[ccnt].host_only = host_only;
					cookies[ccnt].path = path;
					cookies[ccnt].secure = secure;
					cookies[ccnt].expires = (time_t)expires;
					cookies[ccnt].name = name;
					cookies[ccnt].value = value;
					ccnt++;
				} else {
					free(domain); free(path); free(name); free(value);
				}
				p = (q[0] == '\n') ? q + 1 : q;
			}
			t++;
			continue;
		}
		if(!strcmp(argv[t], "-6")) {options |= 1<<MCURL_OPT_IPV6; continue;}
		if(!strcmp(argv[t], "-u")) {NEED_ARG(t); SAFE_STRCPY(username, argv[t+1]); t++; continue;}
		if(!strncmp(argv[t], "-p", 2)) {SAFE_STRCPY(password, argv[t] + 2); continue;}
		if(!strcmp(argv[t], "-2")) {options |= 1<<MCURL_OPT_DISABLE_HTTP2; continue;}
		if(!strncmp(argv[t], "-m", 2)) {maxpagesize = atoi(argv[t]+2)*1024*1024UL; continue;}

		// urloptions
		if(!strcmp(argv[t], "-P")) {
			NEED_ARG(t);
			url->post = malloc(strlen(argv[t+1]) + 1);
			url->postlen = strlen(argv[t+1]);
			memcpy(url->post, argv[t+1], url->postlen);
			t++;
			continue;
		}
		if(!strcmp(argv[t], "-C")) {
			NEED_ARG(t);
			if (customheader[0]) {
				str_replace(url->customheader, sizeof(url->customheader), customheader, "%", argv[t+1]);
			}
			t++;
			continue;
		}
		if(!strcmp(argv[t], "-X")) {NEED_ARG(t); SAFE_STRCPY(url->method, argv[t+1]); t++; continue;}

		// init url
		mcrawler_init_url(url, argv[t]);
		url->index = i++;
		if (!url->method[0]) {
			strcpy(url->method, url->post ? "POST" : "GET");
		}
		for (int i = 0; i < ccnt; i++) {
			mcrawler_cp_cookie(&url->cookies[i], &cookies[i]);
		}
		url->cookiecnt = ccnt;
		strcpy(url->customagent, customagent);
		if (!url->customheader[0] && customheader[0]) {
			strcpy(url->customheader, customheader);
			strcpy(url->customheader + strlen(url->customheader), "\r\n");
		}
		strcpy(url->username, username);
		strcpy(url->password, password);
		url->options = options;
		if (maxpagesize) {
			url->maxpagesize = maxpagesize;
		}

		urls[i-1] = url;
		url = (mcrawler_url *)malloc(sizeof(mcrawler_url));
		memset(url, 0, sizeof(mcrawler_url));
	}

	urls[i] = NULL;
	free(url);

	for (int t = 0; t < ccnt; t++) {
		mcrawler_free_cookie(&cookies[t]);
	}
}

/**
 * Formats timing data for output
 */
static void format_timing(char *buf, size_t bufsize, int *plen, mcrawler_timing *timing, int state, int start) {
	const int now = timing->done;
	if (start) {
		append_fmt(buf, bufsize, plen, "Redirect=%d ms; ", (timing->dnsstart ? timing->dnsstart : timing->connectionstart ? timing->connectionstart : timing->requeststart) - start);
	}
	if (timing->dnsstart) {
		append_fmt(buf, bufsize, plen, "DNS Lookup=%d ms; ", (timing->dnsend ? timing->dnsend : now) - timing->dnsstart);
	}
	if (timing->connectionstart) {
		append_fmt(buf, bufsize, plen, "Initial connection=%d ms; ", (timing->sslstart ? timing->sslstart : (timing->requeststart ? timing->requeststart : now)) - timing->connectionstart);
	}
	if (timing->sslstart) {
		append_fmt(buf, bufsize, plen, "SSL=%d ms; ", (timing->sslend ? timing->sslend : now) - timing->sslstart);
	}
	if (timing->requeststart) {
		append_fmt(buf, bufsize, plen, "Request=%d ms; ", (timing->requestend ? timing->requestend : now) - timing->requeststart);
	}
	if (timing->requestend) {
		append_fmt(buf, bufsize, plen, "Waiting=%d ms; ", (timing->firstbyte ? timing->firstbyte : now) - timing->requestend);
	}
	if (timing->firstbyte) {
		append_fmt(buf, bufsize, plen, "Content download=%d ms; ", (timing->lastread && state > MCURL_S_RECVREPLY ? timing->lastread : now) - timing->firstbyte);
	}
	if (start || timing->connectionstart || timing->requeststart) {
		// after redirect only requeststart is available
		if (!start) {
			start = timing->connectionstart ? timing->connectionstart : timing->requeststart;
		}
		append_fmt(buf, bufsize, plen, "Total=%d ms; ", (timing->lastread && state > MCURL_S_RECVREPLY ? timing->lastread : now) - start);
	}
}

void output(mcrawler_url *u, void *arg) {
	const int url_state = u->state;

	unsigned char header[16384], *http_header, *http_body;
	char *h = (char *)header;
	const size_t hsize = sizeof(header);
	int hlen = 0;
	size_t http_header_len, http_body_len;

	mcrawler_url_header(u, &http_header, &http_header_len);
	mcrawler_url_body(u, &http_body, &http_body_len);

	append_fmt(h, hsize, &hlen, "URL: %s", u->rawurl);
	if (u->redirectedto != NULL) {
		append_fmt(h, hsize, &hlen, "\nRedirected-To: %s", u->redirectedto);
	}
	for (mcrawler_redirect_info *rinfo = u->redirect_info; rinfo; rinfo = rinfo->next) {
		append_fmt(h, hsize, &hlen, "\nRedirect-info: %s %d; ", rinfo->url, rinfo->status);
		format_timing(h, hsize, &hlen, &rinfo->timing, MCURL_S_DOWNLOADED, 0);
	}
	append_fmt(h, hsize, &hlen, "\nStatus: %d\nContent-length: %zd\n", u->status, http_body_len);

	if (url_state <= MCURL_S_RECVREPLY) {
		char timeouterr[50];
		switch (url_state) {
			case MCURL_S_JUSTBORN:
				strcpy(timeouterr, "Process has not started yet"); break;
			case MCURL_S_PARSEDURL:
				strcpy(timeouterr, "Timeout while contacting DNS servers"); break;
			case MCURL_S_INDNS:
				strcpy(timeouterr, "Timeout while resolving host"); break;
			case MCURL_S_GOTIP:
				if (u->timing.connectionstart) {
					strcpy(timeouterr, "Connection timed out");
				} else {
					strcpy(timeouterr, "Waiting for download slot");
				}
				break;
			case MCURL_S_CONNECT:
				strcpy(timeouterr, "Connection timed out"); break;
			case MCURL_S_HANDSHAKE:
				strcpy(timeouterr, "Timeout during SSL handshake"); break;
			case MCURL_S_GENREQUEST:
				strcpy(timeouterr, "Timeout while generating HTTP request"); break;
			case MCURL_S_SENDREQUEST:
				strcpy(timeouterr, "Timeout while sending HTTP request"); break;
			case MCURL_S_RECVREPLY:
				strcpy(timeouterr, "HTTP server timed out"); break;
		}

		append_fmt(h, hsize, &hlen, "Timeout: %d (%s); %s\n", url_state, mcrawler_state_to_s(url_state), timeouterr);
	}
	if (*u->error_msg) {
		append_fmt(h, hsize, &hlen, "Error-msg: %s\n", u->error_msg);
	}
	if (u->contenttype && *u->contenttype) {
		append_fmt(h, hsize, &hlen, "Content-type: %s", u->contenttype);
		if (*u->charset) {
			append_fmt(h, hsize, &hlen, "; charset=%s\n", u->charset);
		} else {
			append_fmt(h, hsize, &hlen, "\n");
		}
	}
	if (u->wwwauthenticate && *u->wwwauthenticate) {
		append_fmt(h, hsize, &hlen, "WWW-Authenticate: %s\n", u->wwwauthenticate);
	}
	if (u->cookiecnt) {
		append_fmt(h, hsize, &hlen, "Cookies: %d\n", u->cookiecnt);
		// netscape cookies.txt format
		// @see http://www.cookiecentral.com/faq/#3.5
		for (int t = 0; t < u->cookiecnt; t++) {
			append_fmt(h, hsize, &hlen, "%s\t%d\t%s\t%d\t%ld\t%s\t%s\n", u->cookies[t].domain, u->cookies[t].host_only, u->cookies[t].path, u->cookies[t].secure, u->cookies[t].expires, u->cookies[t].name, u->cookies[t].value);
		}
	}

	// downtime
	int downtime;
	if (url_state == MCURL_S_DOWNLOADED) {
		downtime = u->timing.lastread ? u->timing.lastread : u->timing.done - u->downstart;
	} else if (u->downstart) {
		downtime = u->timing.done - u->downstart;
	} else {
		downtime = u->timing.done;
	}
	append_fmt(h, hsize, &hlen, "Downtime: %dms; %dms", downtime, u->downstart);
	if (u->addr != NULL) {
		char straddr[INET6_ADDRSTRLEN];
		inet_ntop(u->addr->type, u->addr->ip, straddr, sizeof(straddr));
		append_fmt(h, hsize, &hlen, " (ip=%s)", straddr);
	}
	append_fmt(h, hsize, &hlen, "\nTiming: ");
	format_timing(h, hsize, &hlen, &u->timing, url_state, u->downstart);
	append_fmt(h, hsize, &hlen, "\nIndex: %d\n\n", u->index);

	write_all(STDOUT_FILENO, header, hlen);
	if (writehead) {
		write_all(STDOUT_FILENO, http_header, http_header_len);
		if (0 == u->headlen) {
			write_all(STDOUT_FILENO, (unsigned char*)"\n", 1); // PHP library expects one empty line at the end of headers, in normal circumstances it is contained
						      // within u->buf[0 .. u->headlen] .
		}
	}

	write_all(STDOUT_FILENO, http_body, http_body_len);
	write_all(STDOUT_FILENO, (unsigned char *)"\n", 1); // jinak se to vývojářům v php špatně parsuje
}
