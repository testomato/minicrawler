#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "h/string.h"
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

size_t cookies_header_max_size(mcrawler_url *u) {
	size_t cookies_size = 0;
	for (int i = 0; i < u->cookiecnt; i++) cookies_size += 3 + strlen(u->cookies[i].name) + strlen(u->cookies[i].value);
	return cookies_size;
}

void set_cookies_header(mcrawler_url *u, char *buf, size_t *p_len) {
	size_t len = 0;
	int s;

	for (int t = 0; t < u->cookiecnt; t++) {
		char *p, c;
		// see http://tools.ietf.org/html/rfc6265 section 5.4
		if (
				((u->cookies[t].host_only == 1 && strcasecmp(u->hostname, u->cookies[t].domain) == 0) || // The cookie's host-only-flag is true and the canonicalized request-host is identical to the cookie's domain.
					(u->cookies[t].host_only == 0 && (p = strcasestr(u->hostname, u->cookies[t].domain)) && *(p+strlen(u->cookies[t].domain)) == 0)) && //  Or: The cookie's host-only-flag is false and the canonicalized request-host domain-matches the cookie's domain.
				(!strncmp(u->path, u->cookies[t].path, strlen(u->cookies[t].path)) && (u->cookies[t].path[strlen(u->cookies[t].path)-1] == '/' || (c = u->path[strlen(u->cookies[t].path)]) == '/' || c == '?' || c == 0)) && // The request-uri's path path-matches the cookie's path.
				(u->cookies[t].secure == 0 || strcmp(u->proto, "https") == 0) //  If the cookie's secure-only-flag is true, then the request- uri's scheme must denote a "secure" protocol
		) {
			if (len) {
				strcpy(buf + len, "; ");
				len += 2;
			}
			s = sprintf(buf + len, "%s=%s", u->cookies[t].name, u->cookies[t].value);
			if (s > 0) len += s;
		}
	}
	*p_len = len;
}

// The user agent MUST evict all expired cookies from the cookie store
// if, at any time, an expired cookie exists in the cookie store.
void remove_expired_cookies(mcrawler_url *u) {
	time_t tim = time(NULL);
	for (int t = 0; t < u->cookiecnt;) {
		if (tim > u->cookies[t].expires) {
			debugf("[%d] Cookie %s expired. Deleting\n", u->index, u->cookies[t].name);
			mcrawler_free_cookie(&u->cookies[t]);
			u->cookiecnt--;
			if (t < u->cookiecnt) {
				memmove(&u->cookies[t], &u->cookies[t+1], (u->cookiecnt-t)*sizeof(*u->cookies));
			}
		} else {
			t++;
		}
	}
}

/** 
 * zapíše si do pole novou cookie (pokud ji tam ještě nemá; pokud má, tak ji nahradí)
 * see http://tools.ietf.org/html/rfc6265 section 5.2 and 5.3
 */
void setcookie(mcrawler_url *u, char *str) {
	mcrawler_cookie cookie;
	struct nv attributes[10];
	int att_len = 0;
	char *namevalue, *attributestr;
	char *p, *q;
	int i;

	memset(&cookie, 0, sizeof(mcrawler_cookie));
	cookie.expires = -1;
	memset(attributes, 0, sizeof(attributes));

	namevalue = str;
	p = strchrnul(str, ';');
	if (*p == ';') {
		*p = 0;
		attributestr = p + 1;
	} else {
		attributestr = p; // attribute string is empty
	}

	// parse name and value
	if ((p = strchr(namevalue, '=')) == NULL) {
		debugf("[%d] Cookie string '%s' lacks a '=' character\n", u->index, namevalue);
		goto fail;
	}
	*p = 0; p++;

	cookie.name = malloc(strlen(namevalue) + 1);
	cookie.value = malloc(strlen(p) + 1);
	strcpy(cookie.name, namevalue);
	strcpy(cookie.value, p);

	trim(cookie.name);
	trim(cookie.value);

	if (strlen(cookie.name) == 0) {
		debugf("[%d] Cookie string '%s' has empty name\n", u->index, namevalue);
		goto fail;
	}
	
	// parse cookie attributes
	struct nv *attr;
	p = attributestr;
	while (*p) {
		if (att_len > 9) {
			debugf("[%d] Cookie string '%s%s' has more 10 attributes (not enough memory)... skipping the rest\n", u->index, namevalue, attributestr);
			break;
		}

		attr = attributes + att_len++;

		attr->name = p;
		p = strchrnul(p, ';');
		if (*p) {
			*p = 0; p++;
		}
		if ((q = strchr(attr->name, '='))) {
			*q = 0;
			attr->value = q + 1;
		} else { // value is empty
			attr->value = attr->name + strlen(attr->name);
		}
		trim(attr->name);
		trim(attr->value);
	}

	// process attributes
	for (i = 0; i < att_len; i++) {
		attr = attributes + i;

		// The Expires Attribute
		if (!strcasecmp(attr->name, "Expires")) {
			time_t expires = parse_cookie_date(attr->value);
			if (expires < 0) {
				debugf("[%d] Failed to parse cookie date from '%s'\n", u->index, attr->value);
			} else {
				cookie.expires = expires;
			}

			continue;
		}

		// The Max-Age Attribute
		if (!strcasecmp(attr->name, "Max-Age")) {
			char *p;
			int max_age = strtol(attr->value, &p, 10);
			if (*p != 0) {
				debugf("[%d] Invalid Max-Age attribute '%s'\n", u->index, attr->value);
				continue;
			}
			if (max_age <= 0) {
				cookie.expires = (time_t)(0);
			} else {
				cookie.expires = time(NULL) + (time_t)max_age;
			}

			continue;
		}

		// The Domain Attribute
		if (!strcasecmp(attr->name, "Domain")) {
			store_cookie_domain(attr, &cookie);

			continue;
		}

		// The Path Attribute
		if (!strcasecmp(attr->name, "Path")) {
			if (cookie.path) {
				free(cookie.path);
				cookie.path = NULL;
			}
			if (attr->value[0] == '/') {
				cookie.path = malloc(strlen(attr->value) + 1);
				strcpy(cookie.path, attr->value);
			}

			continue;
		}

		// The Secure Attribute
		if (!strcasecmp(attr->name, "Secure")) {
			cookie.secure = 1;

			continue;
		}
	}

	if (!cookie.domain) {
		cookie.domain = malloc(strlen(u->hostname) +1);
		strcpy(cookie.domain, u->hostname);
		cookie.host_only = 1;
	} else {
		// match request host
		if ((p = strcasestr(u->hostname, cookie.domain)) == NULL || *(p+strlen(cookie.domain)) != 0) {
			debugf("[%d] Domain '%s' in cookie string does not match request host '%s'... ignoring\n", u->index, cookie.domain, u->hostname);
			goto fail;
		}
	}

	if (cookie.expires < 0) {
		cookie.expires = LONG_MAX;
	}

	if (!cookie.path) {
		// default-path, see http://tools.ietf.org/html/rfc6265#section-5.1.4
		char *p = strchrnul(u->path, '?');
		assert(p > u->path);
		cookie.path = malloc(p - u->path + 1);
		*(char *)mempcpy(cookie.path, u->path, p - u->path) = 0;
		p = strrchr(cookie.path, '/');
		if (p > cookie.path) {
			*p = 0;
		} else {
			*(p + 1) = 0;
		}
	}


	int t;
	for (t = 0; t<u->cookiecnt; ++t) {
		if(!strcasecmp(cookie.name,u->cookies[t].name) && !strcasecmp(cookie.domain,u->cookies[t].domain) && !strcmp(cookie.path,u->cookies[t].path)) {
			break;
		}
	}

	if (t<u->cookiecnt) { // už tam byla
		mcrawler_free_cookie(&u->cookies[t]);
		debugf("[%d] Changed cookie\n",u->index);
	} else {
		u->cookiecnt++;
	}

	if (t < sizeof(u->cookies)/sizeof(*u->cookies)) {
		u->cookies[t] = cookie;
		debugf("[%d] Storing cookie #%d: name='%s', value='%s', domain='%s', path='%s', host_only=%d, secure=%d\n",u->index,t,cookie.name,cookie.value,cookie.domain,cookie.path,cookie.host_only,cookie.secure);
		return;
	} else {
		u->cookiecnt--;
		debugf("[%d] Not enough memory for storing cookies\n",u->index);
	}

fail:
	mcrawler_free_cookie(&cookie);
}
