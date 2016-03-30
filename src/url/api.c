#include "../h/config.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "minicrawler-url.h"
#include "../h/string.h"

// The href attribute’s getter must return the serialization of context object’s url.
char * mcrawler_url_get_href(mcrawler_url_url *url) {
	return mcrawler_url_serialize_url(url, 0);
}

// The protocol attribute’s getter must return context object url’s scheme, followed by ":".
char * mcrawler_url_get_protocol(mcrawler_url_url *url) {
	size_t len = strlen(url->scheme);
	char *protocol = malloc(len + 2);
	strcpy(protocol, url->scheme);
	strcpy(protocol + len, ":");
	return protocol;
}

// The username attribute’s getter must return context object’s url’s username.
char * mcrawler_url_get_username(mcrawler_url_url *url) {
	return strdup(url->username);
}
 
// The password attribute’s getter must run these steps:
char * mcrawler_url_get_password(mcrawler_url_url *url) {
	// If context object’s url’s password is null, return the empty string.
	// Return context object’s url’s password.
	return strdup(url->password ? url->password : "");
}

// The host attribute’s getter must run these steps:
char * mcrawler_url_get_host(mcrawler_url_url *url) {
	// Let url be context object’s url.
	// If url’s host is null, return the empty string.
	if (!url->host) {
		return strdup("");
	// If url’s port is null, return url’s host, serialized.
	} else if (!url->port_not_null) {
		return strdup(url->host->domain);
	// Return url’s host, serialized, followed by ":" and url’s port, serialized.
	} else {
		size_t len = strlen(url->host->domain);
		char *host = malloc(len + 7);
		strcpy(host, url->host->domain);
		sprintf(host + len, ":%d", url->port);
		return host;
	}
}

// The hostname attribute’s getter must run these steps:
char * mcrawler_url_get_hostname(mcrawler_url_url *url) {
	// If context object’s url’s host is null, return the empty string.
	// Return context object’s url’s host, serialized.
	return strdup(url->host ? url->host->domain : "");
}

// The port attribute’s getter must run these steps:
char * mcrawler_url_get_port(mcrawler_url_url *url) {
	// If context object’s url’s port is null, return the empty string.
	if (!url->port_not_null) {
		return strdup("");
	// Return context object’s url’s port, serialized.
	} else {
		char *port = malloc(6);
		sprintf(port, "%d", url->port);
		return port;
	}
}

// The pathname attribute’s getter must run these steps:
char * mcrawler_url_get_pathname(mcrawler_url_url *url) {
	char *path = mcrawler_url_serialize_path_and_query(url);
	*(strchrnul(path, '?')) = 0;
	return path;
}

// The search attribute’s getter must run these steps:
char * mcrawler_url_get_search(mcrawler_url_url *url) {
	// If context object’s url’s query is either null or the empty string, return the empty string.
	if (!url->query || !url->query[0]) {
		return strdup("");
	// Return "?", followed by context object’s url’s query.
	} else {
		char *search = malloc(strlen(url->query) + 2);
		search[0] = '?';
		strcpy(search + 1, url->query);
		return search;
	}
}

// The hash attribute’s getter must run these steps:
char * mcrawler_url_get_hash(mcrawler_url_url *url) {
	// If context object’s url’s fragment is either null or the empty string, return the empty string.
	if (!url->fragment || !url->fragment[0]) {
		return strdup("");
	// Return "#", followed by context object’s url’s fragment.
	} else {
		char *hash = malloc(strlen(url->fragment + 2));
		hash[0] = '#';
		strcpy(hash + 1, url->fragment);
		return hash;
	}
}
