#include "h/minicrawler.h"
#include "h/config.h"
#include "url/minicrawler-url.h"


void mcrawler_free_cookie(mcrawler_cookie *cookie) {
	if (cookie->name) free(cookie->name);
	if (cookie->value) free(cookie->value);
	if (cookie->domain) free(cookie->domain);
	if (cookie->path) free(cookie->path);
}

void mcrawler_free_url(mcrawler_url *url) {
	if (url->uri) {
		mcrawler_url_free_url(url->uri);
		free(url->uri);
	}
	if (url->path) free(url->path);
	if (url->post) free(url->post);
	if (url->redirectedto) free(url->redirectedto);
	for (int i = 0; i < url->cookiecnt; i++) {
		mcrawler_free_cookie(&url->cookies[i]);
	}
	if (url->contenttype) free(url->contenttype);
	if (url->wwwauthenticate) free(url->wwwauthenticate);
	if (url->request) free(url->request);

	mcrawler_redirect_info *rinfo = url->redirect_info;
	while (rinfo) {
		mcrawler_redirect_info *next = rinfo->next;
		free(rinfo->url);
		free(rinfo);
		rinfo = next;
	}

	if (url->addr) free_addr(url->addr);
	if (url->prev_addr) free_addr(url->prev_addr);
	if (url->f) free(url->f);
}
