#define _GNU_SOURCE
#include <string.h>

#include "h/config.h"
#include "h/string.h"
#include "h/proto.h"
#include "h/digcalc.h"

#ifdef HAVE_LIBSSL
#include <openssl/md5.h>
#endif

/**
 * http://tools.ietf.org/html/rfc2617#section-2
 */
void basicauth(mcrawler_url *u, struct challenge *ch) {
	*strchrnul(u->username, ':') = 0; // dobledot not allowed in unserid

	char userpass[strlen(u->username) + strlen(u->password) + 1 + 1]; // one for : and one for 0
	sprintf(userpass, "%s:%s", u->username, u->password);
	u->authorization = malloc(base64_len(strlen(userpass)) + 1 + 6); // 6 for "Basic"
	strcpy(u->authorization, "Basic ");
	base64(u->authorization + 6, userpass, strlen(userpass));
}

#ifdef HAVE_LIBSSL
/**
 * http://tools.ietf.org/html/rfc2617#section-3
 */
void digestauth(mcrawler_url *u, struct challenge *ch) {
	char *nonce = NULL, *alg = NULL, *qop = NULL, *opaq = NULL;
	char nonce_count[] = "00000001";
	char cnonce[] = "97jGn565ggO9jsp";
	HASHHEX HA1, HEntity, response;
	size_t authlen;

	for (int i = 0; i < 10 && ch->params[i].name != NULL; i++) {
		if (!strcmp("nonce", ch->params[i].name)) nonce = ch->params[i].value;
		if (!strcmp("algorithm", ch->params[i].name)) alg = ch->params[i].value;
		if (!strcmp("qop", ch->params[i].name)) {
			qop = ch->params[i].value;
			// take the first value
			*strchrnul(qop, ',') = 0;
		}
		if (!strcmp("opaque", ch->params[i].name)) opaq = ch->params[i].value;
	}

	if (!nonce) {
		debugf("[%d] digest auth error: missing nonce\n", u->index);
		return;
	}
	if (!alg) alg = strdup("MD5");
	if (!qop) qop = strdup("");

	*strchrnul(u->username, ':') = 0; // dobledot not allowed in unserid

	if (!strcasecmp("auth-int", qop)) {
		unsigned char *buf;
		size_t len;
		buf_get(u, 1, &buf, &len);
		MD5_CTX context;
		MD5_Init(&context);
		MD5_Update(&context, buf, len);
		MD5_Final(HEntity, &context);
	}

	DigestCalcHA1(alg, u->username, ch->realm, u->password, nonce, cnonce, HA1);
	DigestCalcResponse(HA1, nonce, nonce_count, cnonce, qop, u->method, u->path, HEntity, response);

	if (*qop) {
		char authformat[] = "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=%s, cnonce=\"%s\", qop=%s, nc=%s";
		authlen = strlen(authformat) + strlen(u->username) + strlen(ch->realm) + strlen(nonce) + strlen(u->path) + HASHHEXLEN + strlen(alg) + strlen(cnonce) + strlen(qop) + strlen(nonce_count);
		u->authorization = malloc(authlen + 1);
		sprintf(u->authorization, authformat, u->username, ch->realm, nonce, u->path, response, alg, cnonce, qop, nonce_count);
	} else {
		char authformat[] = "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=%s";
		authlen = strlen(authformat) + strlen(u->username) + strlen(ch->realm) + strlen(nonce) + strlen(u->path) + HASHHEXLEN + strlen(alg);
		u->authorization = malloc(authlen + 1);
		sprintf(u->authorization, authformat, u->username, ch->realm, nonce, u->path, response, alg);
	}
	if (opaq) {
		char opaqfmt[] = ", opaque=\"%s\"";
		u->authorization = realloc(u->authorization, authlen + strlen(opaq) + strlen(opaqfmt) + 1);
		sprintf(u->authorization + authlen, opaqfmt, opaq);
	}
}
#endif

/**
 * Z hlavičky WWW-Authenitcate vyparsuje právě jednu neprázndou challenge
 */
void parse_single_challenge(mcrawler_url *u, char **pp, struct challenge *ch) {
	char *param, *value, *p = *pp;
	int params_len = 0;

	while (*p == ',') p++; // skip empty challenges

	ch->scheme = p;
	p = strchr(p, ' ');
	if (!p) {
		debugf("[%d] single auth challenge '%s' without any params\n", u->index, *pp);
		*pp = p;
		return;
	}
	*p = 0; p++;

	while (1) {
		while (*p == ' ' || *p == '\t' || *p == ',') p++;
		if (!*p) break;

		param = p;
		p = strpbrk(p, " =");
		if (!p) {
			debugf("[%d] error parsing auth challenge: scheme should be terminated by space and param by '=' ('%s')'\n", u->index, param);
			break;
		}
		if (*p == ' ') { // start of a new challenge
			*pp = param;
			return;
		}
		*p = 0; p++;
		if (*p == '"') { // quoted string
			value = p + 1;
			while (*(++p) && *p != '"') {
				if (*p == '\\') { // quoted pair
					memmove(p, p+1, strlen(p));
				}
			}
			if (!*p) {
				debugf("[%d] error parsing auth challenge: unterminated quoted string '%s'\n", u->index, value);
				break;
			}
		} else {
			value = p;
			p = strpbrk(p, " \t,");
			if (p == NULL) {
				p = value + strlen(value);
			}
		}
		if (*p) {
			*p = 0; p++;
		}

		if (!strcasecmp(param, "realm")) {
			ch->realm = value;
		} else {
			if (params_len > 9) {
				debugf("[%d] error parsing auth challenge: not enough memory for params\n", u->index);
				break;
			} else {
				ch->params[params_len].name = param;
				ch->params[params_len].value = value;
				params_len++;
			}
		}
	}

	*pp = p;
}

/**
 * HTTP Authentication
 * @see http://tools.ietf.org/html/rfc2617
 */
void parse_authchallenge(mcrawler_url *u, char *challenge) {
	struct challenge challenges[3];
	int i = 0;

	char *p = challenge;
	memset(challenges, 0, sizeof(challenges));

	while (p && *p) {
		if (i < 3) {
			parse_single_challenge(u, &p, &challenges[i]);
			i++;
		} else {
			debugf("[%d] error parsing auth challenge: not enough memory for challenges\n", u->index);
			break;
		}
	}

	if (u->authorization) {
		free(u->authorization);
		u->authorization = NULL;
	}

	int can_basic = -1, can_digest = -1;

	for (i = 0; i < 3 && challenges[i].scheme != NULL; i++) {
		if (!strcasecmp(challenges[i].scheme, "basic")) {
			can_basic = i;
#ifdef HAVE_LIBSSL
		} else if (!strcasecmp(challenges[i].scheme, "digest")) {
			if (challenges[i].realm == NULL) {
				debugf("[%d] missing realm for digest auth scheme\n", u->index);
			} else {
				can_digest = i;
			}
#endif
		} else {
			debugf("[%d] unsupported auth scheme '%s'\n", u->index, challenges[i].scheme);
		}
	}

	if (can_digest > -1) {
		digestauth(u, &challenges[can_digest]);
	} else if (can_basic > -1) {
		basicauth(u, &challenges[can_basic]);
	} else {
		sprintf(u->error_msg, "No supported HTTP authentication scheme");
	}
}
