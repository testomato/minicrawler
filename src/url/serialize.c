#include "../h/config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "minicrawler-url.h"
#include "alloc.h"


char *mcrawler_url_serialize_ipv6(mcrawler_url_host *host, char *dest) {
	char straddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, host->ipv6, straddr, sizeof(straddr));
	return strcpy(dest, straddr);
}

char *mcrawler_url_serialize_ipv4(mcrawler_url_host *host, char *dest) {
	char straddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, host->ipv4, straddr, sizeof(straddr));
	return strcpy(dest, straddr);
}

char *mcrawler_url_serialize_path_and_query(mcrawler_url_url *url) {
	char *part, **p = url->path;
	size_t pathlen = 0;

	if (url->cannot_be_a_base_url) {
		pathlen = strlen(url->path[0]);
	} else {
		while ((part = *p++)) {
			pathlen += strlen(part) + 1;
		}
	}
	char *path = malloc(pathlen + (url->query ? strlen(url->query) + 1 : 0) + 1);

	int pathp = 0;
	path[pathp]  = '\0';

	// If url’s cannot-be-a-base-URL flag is set, append the first string in url’s path to output.
	if (url->cannot_be_a_base_url) {
		strcpy(path, url->path[0]);
		pathp += strlen(path);
	// Otherwise, append "/", followed by the strings in url’s path (including empty strings), separated from each other by "/", to output.
	} else {
		p = url->path;
		while ((part = *p++)) {
			path[pathp++] = '/';
			strcpy(path + pathp, part);
			pathp += strlen(part);
		}
	}
	// If url’s query is non-null, append "?", followed by url’s query, to output.
	if (url->query) {
		path[pathp++] = '?';
		strcpy(path + pathp, url->query);
	}

	return path;
}

char *mcrawler_url_serialize_url(mcrawler_url_url *url, int exclude_fragment) {
	// Let output be url’s scheme and ":" concatenated.
	int outp = 0;
	size_t outsz = 128;
	char *output = malloc(outsz);
	append_s(&output, &outsz, &outp, url->scheme);
	append_c(&output, &outsz, &outp, ':');
	// If url’s host is non-null:
	if (url->host) {
		// Append "//" to output.
		append_s(&output, &outsz, &outp, "//");
		// If url’s username is not the empty string or url’s password is non-null, run these substeps:
		if (url->username[0] || url->password) {
			// Append url’s username to output.
			append_s(&output, &outsz, &outp, url->username);
			// If url’s password is non-null, append ":", followed by url’s password, to output.
			if (url->password) {
				append_c(&output, &outsz, &outp, ':');
				append_s(&output, &outsz, &outp, url->password);
			}
			// Append "@" to output.
			append_c(&output, &outsz, &outp, '@');
		}
		// Append url’s host, serialized, to output.
		append_s(&output, &outsz, &outp, url->host->domain);
		// If url’s port is non-null, append ":" followed by url’s port, serialized, to output.
		if (url->port_not_null) {
			char pstr[7]; // port is < 2^16
			sprintf(pstr, ":%d", url->port);
			append_s(&output, &outsz, &outp, pstr);
		}
	// Otherwise, if url’s host is null and url’s scheme is "file", append "//" to output.
	} else if (!url->host && !strcmp(url->scheme, "file")) {
		append_s(&output, &outsz, &outp, "//");
	}
	char *path = mcrawler_url_serialize_path_and_query(url);
	append_s(&output, &outsz, &outp, path);
	free(path);
	// If the exclude fragment flag is unset and url’s fragment is non-null, append "#", followed by url’s fragment, to output.
	if (!exclude_fragment && url->fragment) {
		append_c(&output, &outsz, &outp, '#');
		append_s(&output, &outsz, &outp, url->fragment);
	}
	// Return output.
	return output;
}
