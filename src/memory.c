#include "h/minicrawler.h"
#include "h/config.h"


void mcrawler_free_cookie(mcrawler_cookie *cookie) {
	if (cookie->name) free(cookie->name);
	if (cookie->value) free(cookie->value);
	if (cookie->domain) free(cookie->domain);
	if (cookie->path) free(cookie->path);
}
