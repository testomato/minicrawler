#include "h/config.h"
#include "h/proto.h"

void mcrawler_url_header(mcrawler_url *u, unsigned char **header, size_t *headlen) {
	*header = buf_p(u);
	*headlen = u->headlen;
}

void mcrawler_url_body(mcrawler_url *u, unsigned char **body, size_t *bodylen) {
	*body = buf_p(u) + u->headlen;
	*bodylen = buf_len(u) - u->headlen;
}
