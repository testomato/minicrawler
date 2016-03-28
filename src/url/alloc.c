#include <string.h>
#include <stdlib.h>

#include "minicrawler-url.h"

static inline char *empty(size_t size) {
	char *e = (char *)malloc(size);
	*e = 0;
	return e;
}

static inline unsigned int next_power2(unsigned int v) {
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

void append_c(char **p_buf, size_t *buf_sz, int *pos, const char c) {
	if (*pos + 1 + 1 > *buf_sz) {
		*buf_sz = next_power2(*pos + 1 + 1);
		*p_buf = realloc(*p_buf, *buf_sz);
	}
	(*p_buf)[(*pos)++] = c;
	(*p_buf)[*pos] = 0;
}

void append_s(char **p_buf, size_t *buf_sz, int *pos, const char *s) {
	size_t len = strlen(s);
	if (*pos + len + 1 > *buf_sz) {
		*buf_sz = next_power2(*pos + len + 1);
		*p_buf = realloc(*p_buf, *buf_sz);
	}
	strcpy(*p_buf + *pos, s);
	*pos += len;
}

// scheme
static size_t sizeof_scheme = 8;
static size_t sizeof_username = 2;
static size_t sizeof_password = 16;
static size_t sizeof_path = 8;
static size_t sizeof_path0 = 16;
static size_t sizeof_query = 64;
static size_t sizeof_fragment = 2;

void init_url(mcrawler_url_url *url) {
	memset(url, 0, sizeof(*url));
	url->scheme = empty(sizeof_scheme);
	url->username = empty(sizeof_username);
	url->path = (char **)malloc(sizeof_path * sizeof(char *));
	url->path[0] = NULL;
	url->path_len = 0;
}

void replace_scheme(mcrawler_url_url *url, const char *scheme) {
	size_t scheme_len = strlen(scheme);
	if (scheme_len + 1 > sizeof_scheme) {
		sizeof_scheme = scheme_len + 1;
		url->scheme = (char *)realloc(url->scheme, sizeof_scheme);
	}
	strcpy(url->scheme, scheme);
}

void replace_username(mcrawler_url_url *url, const char *username) {
	size_t username_len = strlen(username);
	if (username_len + 1 > sizeof_username) {
		sizeof_username = username_len + 1;
		url->username = (char *)realloc(url->username, sizeof_username);
	}
	strcpy(url->username, username);
}

void append_username(mcrawler_url_url *url, int *pos, const char *s) {
	append_s(&url->username, &sizeof_username, pos, s);
}

void init_password(mcrawler_url_url *url) {
	url->password = empty(sizeof_password);
}

void append_password(mcrawler_url_url *url, int *pos, const char *s) {
	append_s(&url->password, &sizeof_password, pos, s);
}

void append_path(mcrawler_url_url *url, const char *s) {
	if (url->path_len + 2 > sizeof_path) {
		sizeof_path = next_power2(url->path_len + 2);
		url->path = realloc(url->path, sizeof_path * sizeof(char *));
	}
	if (url->path_len == 0) {
		size_t len = strlen(s);
		if (len + 1 > sizeof_path0) {
			sizeof_path0 = len + 1;
		}
		url->path[url->path_len] = empty(sizeof_path0);
		strcpy(url->path[url->path_len], s);
	} else {
		url->path[url->path_len] = strdup(s);
	}
	url->path[++url->path_len] = NULL;
}

void do_pop_path(mcrawler_url_url *url) {
	if (url->path_len > 0) {
		free(url->path[--url->path_len]);
		url->path[url->path_len] = NULL;
	}
}

void replace_path(mcrawler_url_url *url, const char **path) {
	int len = 0;
	const char **p = path;
	while (*p++) len++;
	if (len + 1 > sizeof_path) {
		sizeof_path = len + 1;
		url->path = realloc(url->path, sizeof_path * sizeof(char *));
	}
	for (int i = 0; i < len; i++) {
		if (i < url->path_len) {
			free(url->path[i]);
		}
		url->path[i] = strdup(path[i]);
	}
	url->path[len] = NULL;
	url->path_len = len;
}

void append_path0_c(mcrawler_url_url *url, const char c) {
	int pos = strlen(url->path[0]);
	append_c(&url->path[0], &sizeof_path0, &pos, c);
}

void append_path0_s(mcrawler_url_url *url, const char *s) {
	int pos = strlen(url->path[0]);
	append_s(&url->path[0], &sizeof_path0, &pos, s);
}

void init_query(mcrawler_url_url *url) {
	url->query = empty(sizeof_query);
}

void append_query_c(mcrawler_url_url *url, int *pos, const char c) {
	append_c(&url->query, &sizeof_query, pos, c);
}

void append_query_s(mcrawler_url_url *url, int *pos, const char *s) {
	append_s(&url->query, &sizeof_query, pos, s);
}

void init_fragment(mcrawler_url_url *url) {
	url->fragment = empty(sizeof_fragment);
}

void append_fragment(mcrawler_url_url *url, const char c) {
	int pos = strlen(url->fragment);
	append_c(&url->fragment, &sizeof_fragment, &pos, c);
}

void mcrawler_url_free_url(mcrawler_url_url *url) {
	free(url->scheme);
	free(url->username);
	free(url->password);
	free(url->query);
	free(url->fragment);
	free(url->object);
	if (url->path) {
		char *part, **p = url->path;
		while ((part = *p++)) {
			free(part);
		}
	}
	free(url->path);
	if (url->host) {
		free(url->host->domain);
	}
	free(url->host);
}
