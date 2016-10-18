#include "h/minicrawler.h"
#include "h/config.h"
#include "url/minicrawler-url.h"


void free_addr(mcrawler_addr *addr) {
	while (addr) {
		mcrawler_addr *next = addr->next;
		free(addr);
		addr = next;
	}
}

void cp_cookie(mcrawler_cookie *dst, const mcrawler_cookie *src) {
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
	dst->expires = src->expires;
}

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
