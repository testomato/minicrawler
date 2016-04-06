#include <assert.h>

#include "h/config.h"
#include "h/proto.h"

/**  Tries to find the end of a head in the server's reply.
 *   It works in a way that it finds a sequence of characters of the form: m{\r*\n\r*\n} 
 */
unsigned char *find_head_end(unsigned char *s, const size_t len) {
	unsigned nn = 0;
	size_t i;
	for (i = 0; i < len && nn < 2; ++i) {
		if (s[i] == '\r') {
			;
		} else if (s[i] == '\n') {
			++nn;
		} else {
			nn = 0;
		}
	}
	return nn == 2 ? &s[i] : NULL;
}


/**
 * @see https://www.ietf.org/rfc/rfc2616.txt
 */
int parsehead(const unsigned char *s, const size_t len, int *status, header_callback header_callback, void *data, int index) {
	char buf[len + 1];
	char *p = buf, *q;
	char *name, *value;

	memcpy(buf, s, len);
	buf[len] = 0;

	if (status != NULL) {
		if (strncmp("HTTP/1.0", p, 8) && strncmp("HTTP/1.1", p, 8)) {
			debugf("[%d] Unsupported protocol\n", index);
			return 1;
		}

		p += 9;
		*status = atoi(p);
		assert(*status > 0);

		p = strchr(p, '\n');
		assert(p != 0); // we know, there are two newlines somewhere
	}

	while (1) {
		while (*p == '\r' || *p == '\n') p++;
		if (*p == 0) break;

		name = p;
		p = strpbrk(p, "\r\n:");
		assert(p != 0);
		if (*p != ':') {
			debugf("[%d] Header name terminator ':' not found\n", index);
			continue;
		}
		*p = 0; p++;

		while (*p == ' ' || *p == '\t') p++;
		value = p;
		while (1) {
			while (*p != '\r' && *p != '\n') p++;
			q = p;
			while (*q == '\r' || *q == '\n') q++;
			if (*q == ' ' || *q == '\t') { // value continues
				memmove(p, q, strlen(q) + 1);
			} else {
				break;
			}
		}

		*p = 0; p++;

		header_callback(name, value, data);
	}

	return 0;
}  

/** sezere to radku tam, kde ceka informaci o delce chunku
 *  jedinou vyjimkou je, kdyz tam najde 0, tehdy posune i contentlen, aby dal vedet, ze jsme na konci
 *  @return 0 je ok, -1 pokud tam neni velikost chunku zapsana cela
 */
int eatchunked(mcrawler_url *u) {
	int t,i;
	unsigned char hex[10];
	int size;
	int movestart;

	// čte velikost chunku
	for (t=u->nextchunkedpos, i=0; u->buf[t] != '\r' && u->buf[t] != '\n' && t < u->bufp; t++) {
		if (i < 9) {
			hex[i++] = u->buf[t];
		}
	}
	t += 2; // eat CRLF
	if (t > u->bufp) {
		debugf("[%d] Missing end of chunksize!", u->index);
		return -1;
	}

	assert(i > 0);
	hex[i] = 0;
	size = strtol((char *)hex, NULL, 16);

	debugf("[%d] Chunksize at %d (buffer %d): '%s' (=%d)\n", u->index, u->nextchunkedpos, u->bufp, hex, size);

	movestart = u->nextchunkedpos;
	if (u->nextchunkedpos != u->headlen) {
		movestart -= 2; // CRLF before chunksize
	}
	assert(t <= u->bufp);
	memmove(u->buf+movestart, u->buf+t, u->bufp-t);		// cely zbytek posun
	u->bufp -= (t-movestart);					// ukazatel taky
	
	u->nextchunkedpos = movestart+size+2;			// 2 more for CRLF
	
	if (size == 0) {
		// a to je konec, pratele! ... taaadydaaadydaaa!
		debugf("[%d] Chunksize=0 (end)\n", u->index);
		// zbytek odpovedi zahodime
		u->bufp = movestart;
		u->contentlen = movestart - u->headlen;
	}
	
	return 0;
}
