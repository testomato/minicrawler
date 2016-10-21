#define _GNU_SOURCE
#include <string.h>
#include "h/config.h"
#include "h/proto.h"

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
	u->maxpagesize = DEFAULT_MAX_PAGE_SIZE;
	if (url && strlen(url) > MAXURLSIZE) {
		*(char*)mempcpy(u->rawurl, url, MAXURLSIZE) = 0;
		sprintf(u->error_msg, "URL is too long");
		u->status = MCURL_S_JUSTBORN - MCURL_S_ERROR;
		u->state = MCURL_S_ERROR;
	} else if (url) {
		strcpy(u->rawurl, url);
	}

	// init callbacks
	mcrawler_url_func f = get_url_callbacks();
	u->f = (mcrawler_url_func*)malloc(sizeof(mcrawler_url_func));
	memcpy(u->f, &f, sizeof(mcrawler_url_func));
}

/**
 * Sets the url to initial state
 */
void mcrawler_reset_url(mcrawler_url *u) {
	reset_url(u);
	u->state = MCURL_S_PARSEDURL;
}

void mcrawler_url_header(mcrawler_url *u, unsigned char **header, size_t *headlen) {
	*header = buf_p(u);
	*headlen = u->headlen;
}

void mcrawler_url_body(mcrawler_url *u, unsigned char **body, size_t *bodylen) {
	*body = buf_p(u) + u->headlen;
	*bodylen = buf_len(u) - u->headlen;
}

char *mcrawler_version() {
	return VERSION;
}
