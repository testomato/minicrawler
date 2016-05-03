#include "h/config.h"
#include "h/minicrawler.h"

const char *mcrawler_state_to_s(const enum mcrawler_url_s x) {
	switch (x) {
		case MCURL_S_JUSTBORN:
			return "MCURL_S_JUSTBORN";
		case MCURL_S_PARSEDURL:
			return "MCURL_S_PARSEDURL";
		case MCURL_S_INDNS:
			return "MCURL_S_INDNS";
		case MCURL_S_GOTIP:
			return "MCURL_S_GOTIP";
		case MCURL_S_CONNECT:
			return "MCURL_S_CONNECT";
		case MCURL_S_HANDSHAKE:
			return "MCURL_S_HANDSHAKE";
		case MCURL_S_GENREQUEST:
			return "MCURL_S_GENREQUEST";
		case MCURL_S_SENDREQUEST:
			return "MCURL_S_SENDREQUEST";
		case MCURL_S_RECVREPLY:
			return "MCURL_S_RECVREPLY";
		case MCURL_S_DOWNLOADED:
			return "MCURL_S_DOWNLOADED";
		case MCURL_S_ERROR:
			return "MCURL_S_ERROR";
		case MCURL_S_DONE:
			return "MCURL_S_DONE";
	}
	return "";
}

