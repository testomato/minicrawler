#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "json/json.h"
#include "../src/url/minicrawler-urlparser.h"

const char *encode(char *input) {
	struct JSON_Value *val = JSON_Value_New_String(input);
	const char *encoded = JSON_Encode(val, 0, 0);
	JSON_Value_Free(val);
	return encoded;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		exit(1);
	}

	char *input = argv[1];
	char *base = NULL;
	if (argc > 2) {
		base = argv[2];
	}
	
	mcrawler_parser_url url, *base_url = NULL;

	if (base) {
		base_url = (mcrawler_parser_url *)malloc(sizeof(mcrawler_parser_url));
		if (mcrawler_parser_parse(base_url, base, NULL) == MCRAWLER_PARSER_FAILURE) {
			printf("{\"input\": %s, \"base\": %s, \"failure\": true}", encode(input), encode(base));
			exit(0);
		}
	} else {
		base = strdup("");
	}

	if (mcrawler_parser_parse(&url, input, base_url) == MCRAWLER_PARSER_FAILURE) {
		printf("{\"input\": %s, \"base\": %s, \"failure\": true}", encode(input), encode(base));
		exit(0);
	}

	// see https://url.spec.whatwg.org/#api
	char *href = mcrawler_parser_serialize(&url, 0);
	char protocol[strlen(url.scheme) + 2];
	strcpy(protocol, url.scheme); strcat(protocol, ":");
	char *password = url.password ? url.password : strdup("");
	char *hostname = url.host ? url.host->domain : strdup("");
	char *host;
	if (url.host) {
		host = malloc(strlen(url.host->domain) + 7);
		strcpy(host, url.host->domain);
		if (url.port_not_null) {
			sprintf(host + strlen(url.host->domain), ":%d", url.port);
		}
	} else {
		host = strdup("");
	}
	char port[6] = "";
	if (url.port_not_null) {
		sprintf(port, "%d", url.port);
	}
	char *path = mcrawler_parser_serialize_path_and_query(&url);
	*(strchrnul(path, '?')) = 0;
	char query[url.query ? strlen(url.query) + 2 : 1];
	if (url.query && url.query[0]) {
		strcpy(query, "?"); strcat(query, url.query);
	} else {
		query[0] = 0;
	}
	char fragment[url.fragment ? strlen(url.fragment) + 2 : 1];
	if (url.fragment && url.fragment[0]) {
		strcpy(fragment, "#"); strcat(fragment, url.fragment);
	} else {
		fragment[0] = 0;
	}

	printf("{\"input\": %s, \"base\": %s, \"href\": %s, \"protocol\": %s, \"username\": %s, \"password\": %s, \"host\": %s, \"hostname\": %s, \"port\": %s, \"pathname\": %s, \"search\": %s, \"hash\": %s}", encode(input), encode(base), encode(href), encode(protocol), encode(url.username), encode(password), encode(host), encode(hostname), encode(port), encode(path), encode(query), encode(fragment));

 
	exit(0);
}

