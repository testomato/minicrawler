#include "h/config.h"
#include "h/proto.h"

#ifdef HAVE_LIBNGHTTP2
#include <nghttp2/nghttp2.h>

int http2_session_send(mcrawler_url *u) {
	int rv;

	http2_session_data *session_data = (http2_session_data *)u->http2_session;
	rv = nghttp2_session_send(session_data->session);
	if (rv != 0) {
		debugf("[%d] HTTP2 fatal error: %s", u->index, nghttp2_strerror(rv));
		sprintf(u->error_msg, "HTTP2 error (%.200s)", nghttp2_strerror(rv));
		return -1;
	}
	return 0;
}

#endif
