/*
 * libFuzzer harness for the WHATWG URL parser (libminicrawler-url).
 *
 * The URL parser is a primary attack surface: it parses fully untrusted input
 * and its output guards a zero-margin invariant (host -> domain[256], see the
 * security review / issue #20). This harness exercises parse + all getters +
 * free so ASan/UBSan can catch OOB, UAF, leaks, and UB.
 *
 * Build (clang):
 *   clang -g -O1 -std=c++14 -fsanitize=address,undefined,fuzzer \
 *       test/fuzz_url.c src/url/parse.cc src/url/serialize.c \
 *       src/url/api.c src/url/alloc.c -licuuc -o fuzz_url
 *   ./fuzz_url -max_len=8192 corpus/
 *
 * Seed the corpus from test/urltestdata.json inputs for faster coverage.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/url/minicrawler-url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// The parser expects a NUL-terminated C string.
	char *input = (char *)malloc(size + 1);
	if (!input) {
		return 0;
	}
	memcpy(input, data, size);
	input[size] = '\0';

	mcrawler_url_url url;
	if (mcrawler_url_parse(&url, input, NULL) == MCRAWLER_URL_SUCCESS) {
		// Exercise every getter (each mallocs a serialized component) and
		// free it, so the whole serialize path is fuzzed too.
		free(mcrawler_url_get_href(&url));
		free(mcrawler_url_get_protocol(&url));
		free(mcrawler_url_get_username(&url));
		free(mcrawler_url_get_password(&url));
		free(mcrawler_url_get_hostname(&url, NULL));
		free(mcrawler_url_get_host(&url, NULL));
		free(mcrawler_url_get_port(&url));
		free(mcrawler_url_get_pathname(&url));
		free(mcrawler_url_get_search(&url));
		free(mcrawler_url_get_hash(&url));
		mcrawler_url_free_url(&url);
	}

	free(input);
	return 0;
}
