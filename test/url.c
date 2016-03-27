#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "json/json.h"
#include "../src/url/minicrawler-url.h"

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
	
	mcrawler_url_url url, *base_url = NULL;

	if (base) {
		base_url = (mcrawler_url_url *)malloc(sizeof(mcrawler_url_url));
		if (mcrawler_url_parse(base_url, base, NULL) == MCRAWLER_URL_FAILURE) {
			printf("{\"input\": %s, \"base\": %s, \"failure\": true}", encode(input), encode(base));
			exit(0);
		}
	} else {
		base = strdup("");
	}

	if (mcrawler_url_parse(&url, input, base_url) == MCRAWLER_URL_FAILURE) {
		printf("{\"input\": %s, \"base\": %s, \"failure\": true}", encode(input), encode(base));
		exit(0);
	}

	char *href = mcrawler_url_get_href(&url);
	char *protocol = mcrawler_url_get_protocol(&url);
	char *username = mcrawler_url_get_username(&url);
	char *password = mcrawler_url_get_password(&url);
	char *hostname = mcrawler_url_get_hostname(&url);
	char *host = mcrawler_url_get_host(&url);
	char *port = mcrawler_url_get_port(&url);
	char *pathname = mcrawler_url_get_pathname(&url);
	char *search = mcrawler_url_get_search(&url);
	char *hash = mcrawler_url_get_hash(&url);

	printf("{\"input\": %s, \"base\": %s, \"href\": %s, \"protocol\": %s, \"username\": %s, \"password\": %s, \"host\": %s, \"hostname\": %s, \"port\": %s, \"pathname\": %s, \"search\": %s, \"hash\": %s}", encode(input), encode(base), encode(href), encode(protocol), encode(username), encode(password), encode(host), encode(hostname), encode(port), encode(pathname), encode(search), encode(hash));

 
	exit(0);
}
