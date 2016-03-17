#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "h/proto.h"

/**
 * http://tools.ietf.org/html/rfc6265#section-5.2.3
 * http://tools.ietf.org/html/rfc6265#section-5.3 4.-6.
 */
char *store_cookie_domain(const struct nv *attr, mcrawler_cookie *cookie) {
	if (strlen(attr->value) == 0) {
		debugf("Empty value for domain attribute... ignoring\n");
		return NULL;
	}

	char *value = attr->value;

	// ignore leading '.'
	if (value[0] == '.') {
		value++;
	}

	// TODO: ignore public suffixes, see 5.3 5.

	if (cookie->domain) free(cookie->domain);
	cookie->domain = malloc(strlen(value)+1);
	strcpy(cookie->domain, value);
	cookie->host_only = 0;

	return value;
}

/**
 * http://tools.ietf.org/html/rfc6265#section-5.1.1
 */
time_t parse_cookie_date(char *date) {
	char *date_token, *p, *q;
	char delimiter[] = "\x9\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x3B\x3C\x3D\x3E\x3F\x40\x5B\x5C\x5D\x5E\x5F\x60\x7B\x7C\x7D\x7E";
	int found_time = 0, found_dayofmonth = 0, found_month = 0, found_year = 0;
	int n, year;
	struct tm tm;

	date_token = strtok(date, delimiter);
	while (date_token) {
		n = strtol(date_token, &p, 10);
		if (!found_time) {
			if (*p == ':' && p - date_token <= 2) {
				tm.tm_hour = n;
				p++;
				tm.tm_min = strtol(p, &q, 10);
				if (*q == ':' && q > p && q - p <= 2) {
					q++;
					tm.tm_sec = strtol(q, &p, 10);
					if (p > q && p - q <= 2) {
						found_time = 1;
						goto next;
					}
				}
			}
		}

		if (!found_dayofmonth) {
			if (p > date_token && p - date_token <= 2) {
				tm.tm_mday = n;
				found_dayofmonth = 1;
				goto next;
			}
		}

		if (!found_month) {
			if (!strncasecmp("jan", date_token, 3)) {tm.tm_mon = 0; found_month = 1;}
			if (!strncasecmp("feb", date_token, 3)) {tm.tm_mon = 1; found_month = 1;}
			if (!strncasecmp("mar", date_token, 3)) {tm.tm_mon = 2; found_month = 1;}
			if (!strncasecmp("apr", date_token, 3)) {tm.tm_mon = 3; found_month = 1;}
			if (!strncasecmp("may", date_token, 3)) {tm.tm_mon = 4; found_month = 1;}
			if (!strncasecmp("jun", date_token, 3)) {tm.tm_mon = 5; found_month = 1;}
			if (!strncasecmp("jul", date_token, 3)) {tm.tm_mon = 6; found_month = 1;}
			if (!strncasecmp("aug", date_token, 3)) {tm.tm_mon = 7; found_month = 1;}
			if (!strncasecmp("sep", date_token, 3)) {tm.tm_mon = 8; found_month = 1;}
			if (!strncasecmp("oct", date_token, 3)) {tm.tm_mon = 9; found_month = 1;}
			if (!strncasecmp("nov", date_token, 3)) {tm.tm_mon = 10; found_month = 1;}
			if (!strncasecmp("dec", date_token, 3)) {tm.tm_mon = 11; found_month = 1;}
			if (found_month) {
				goto next;
			}
		}

		if (!found_year) {
			if (p - date_token >= 2 && p - date_token <= 4) {
				year = n;
				found_year = 1;
				goto next;
			}
		}

next:
		date_token = strtok(NULL, delimiter);
	}

	if (!found_time || !found_dayofmonth || !found_month || !found_year) {
		return -1;
	}

	if (year >= 70 && year <= 99) year += 1900;
	if (year >= 0 && year <= 69) year += 2000;

	// 5.2.1
	//  If the expiry-time is earlier than the earliest date the user agent
	//  can represent, the user agent MAY replace the expiry-time with the
	//  earliest representable date.
	if (year < 1970) {year = 1970; tm.tm_mday = 1; tm.tm_mon = 0; tm.tm_hour = 0; tm.tm_min = 0; tm.tm_sec = 0;}

	tm.tm_year = year - 1900;
	tm.tm_isdst = 0;

	return timegm(&tm);
}
