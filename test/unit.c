/*
 * Unit / regression tests for libminicrawler internals.
 *
 * These lock in the security fixes from the review (issues #5–#19): each test
 * targets a specific defect and asserts the fixed behaviour. Output is TAP so it
 * plugs into the same automake test driver as test/run.
 *
 * Only non-static, linkable entry points are exercised here (parsehead, eatchunk,
 * setcookie/set_cookies_header, unserialize, str_replace). The remaining fixes
 * (output() bounding, SSRF policy, TLS floor) are covered by the CLI and
 * integration tests.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "../src/h/proto.h"   // pulls in struct.h -> minicrawler.h
#include "../src/h/string.h"

static int test_no = 0;
static int failures = 0;

static void ok(int cond, const char *desc) {
	printf("%s %d - %s\n", cond ? "ok" : "not ok", ++test_no, desc);
	if (!cond) failures++;
}

/* ---- parsehead callback ---- */
static int cb_count;
static char last_value[256];
static void count_cb(const char *name, char *value, void *data) {
	(void)name; (void)data;
	cb_count++;
	strncpy(last_value, value, sizeof(last_value) - 1);
	last_value[sizeof(last_value) - 1] = 0;
}

/* ---- #9: str_replace must never overflow its destination ---- */
static void test_str_replace(void) {
	char dst[8];

	memset(dst, 0x7f, sizeof(dst));
	str_replace(dst, sizeof(dst), "hello%", "%", "WORLD");
	ok(strlen(dst) <= sizeof(dst) - 1 && dst[sizeof(dst) - 1] == 0, "#9 str_replace bounds expanded output");

	memset(dst, 0x7f, sizeof(dst));
	str_replace(dst, sizeof(dst), "this-is-a-very-long-string", "z", "y"); // no match
	ok(strlen(dst) <= sizeof(dst) - 1, "#9 str_replace bounds non-matching copy");

	char small[4];
	str_replace(small, sizeof(small), "", "%", "verylongreplacement");
	ok(strlen(small) <= sizeof(small) - 1, "#9 str_replace bounds huge replacement");
}

/* ---- #6/#7: parsehead must not abort and must not use a stack VLA ---- */
static void test_parsehead(void) {
	int status;

	// #6: status "000" -> atoi == 0, previously assert(*status > 0) aborted
	status = -1;
	const char *h000 = "HTTP/1.1 000 Weird\r\nX-A: 1\r\n\r\n";
	ok(parsehead((const unsigned char *)h000, strlen(h000), &status, count_cb, NULL, 0) != 0,
		"#6 HTTP status 000 rejected without abort");

	// #6: non-numeric status
	status = -1;
	const char *hxyz = "HTTP/1.1 xyz\r\nX-A: 1\r\n\r\n";
	ok(parsehead((const unsigned char *)hxyz, strlen(hxyz), &status, count_cb, NULL, 0) != 0,
		"#6 non-numeric HTTP status rejected without abort");

	// valid head still parses
	status = -1; cb_count = 0; last_value[0] = 0;
	const char *hok = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
	int r = parsehead((const unsigned char *)hok, strlen(hok), &status, count_cb, NULL, 0);
	ok(r == 0 && status == 200 && cb_count >= 1, "#6 valid head parses (status 200)");

	// #7: multi-MB head must be handled on the heap (no crash / stack clash)
	const size_t big = 2 * 1024 * 1024;
	char *hbig = malloc(big + 64);
	int n = sprintf(hbig, "HTTP/1.1 200 OK\r\n");
	memset(hbig + n, 'A', big);          // one huge unterminated "header" line
	memcpy(hbig + n + big, "\r\n\r\n", 4);
	status = -1;
	r = parsehead((const unsigned char *)hbig, n + big + 4, &status, count_cb, NULL, 0);
	ok(r == 0 && status == 200, "#7 multi-MB head parsed without stack VLA / crash");
	free(hbig);
}

/* ---- #6: eatchunk must not abort on an empty chunk-size line ---- */
static void test_eatchunk(void) {
	mcrawler_url *u = calloc(1, sizeof(*u));
	// response body region begins with CRLF where a chunk size is expected
	buf_write(u, (const unsigned char *)"\r\n0\r\n\r\n", 7);
	u->headlen = 0;
	u->nextchunkedpos = 0;
	ok(eatchunk(u) == 0, "#6 empty chunk-size line stops instead of aborting");
	buf_free(u);
	free(u);
}

/* ---- #11: cookie domain matching needs a label boundary ---- */
static mcrawler_url *make_cookie_url(const char *hostname) {
	mcrawler_url *u = calloc(1, sizeof(*u));
	strncpy(u->hostname, hostname, sizeof(u->hostname) - 1);
	strcpy(u->proto, "http");
	u->path = strdup("/");
	u->index = 0;
	return u;
}

static void free_cookie_url(mcrawler_url *u) {
	for (int i = 0; i < u->cookiecnt; i++) mcrawler_free_cookie(&u->cookies[i]);
	free(u->path);
	free(u);
}

static void test_cookie_domain(void) {
	char c1[] = "s=1; Domain=evil.com";
	char c2[] = "s=1; Domain=evil.com";
	char c3[] = "s=1; Domain=com";

	// suffix without label boundary must be rejected on store
	mcrawler_url *u = make_cookie_url("notevil.com");
	setcookie(u, c1);
	ok(u->cookiecnt == 0, "#11 Domain=evil.com not stored for host notevil.com");
	free_cookie_url(u);

	// genuine subdomain is accepted
	u = make_cookie_url("www.evil.com");
	setcookie(u, c2);
	ok(u->cookiecnt == 1, "#11 Domain=evil.com stored for host www.evil.com");

	// and once stored it is sent back for that host
	if (u->cookiecnt == 1) {
		char out[256]; size_t len = 0;
		set_cookies_header(u, out, &len);
		ok(len > 0, "#11 stored cookie is sent to matching host");
	} else {
		ok(0, "#11 stored cookie is sent to matching host");
	}
	free_cookie_url(u);

	// dot-less domain (public suffix): the Domain attribute is rejected, so the
	// cookie falls back to host-only for the request host instead of becoming a
	// cross-TLD domain cookie matching every *.com host.
	u = make_cookie_url("evil.com");
	setcookie(u, c3);
	ok(u->cookiecnt == 1 && u->cookies[0].host_only == 1 && strcmp(u->cookies[0].domain, "evil.com") == 0,
		"#11 Domain=com (no embedded dot) does not create a cross-TLD cookie");
	free_cookie_url(u);
}

/* ---- #10: unserialize must reject a malformed blob, not corrupt memory ---- */
static void test_unserialize(void) {
	unsigned char junk[128];
	memset(junk, 0xAB, sizeof(junk));
	mcrawler_url *u = calloc(1, sizeof(*u));
	int r = mcrawler_url_unserialize(u, junk, sizeof(junk));
	ok(r != 0, "#10 unserialize rejects a garbage blob without crashing");
	free(u);
}

int main(void) {
	// count of ok() calls below
	printf("1..13\n");
	test_str_replace();   // 3
	test_parsehead();     // 4
	test_eatchunk();      // 1
	test_cookie_domain(); // 4
	test_unserialize();   // 1
	return failures ? 1 : 0;
}
