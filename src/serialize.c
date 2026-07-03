#include "h/config.h"

#include "h/string.h"
#include "h/proto.h"
#include "tpl/tpl.h"

#define URL_VARS \
	char *rawurl; \
	char *method; \
	char *customagent; \
	char *customheader; \
	char *username; \
	char *password; \
	char *error_msg; \
	char *charset; \
	tpl_bin post, request, buf; \
	mcrawler_cookie cookie; \
	mcrawler_redirect_info redirect_info;

#define URL_TPL_MAP \
	tn = tpl_map( \
		"issBssssBIiisssssiBiS(iiiiiiiiiii)A(S(ssssiiI))A(S(si$(iiiiiiiiiii)))", \
			&url->index, \
			&rawurl, \
			&method, \
			&post, \
			&customagent, \
			&customheader, \
			&username, \
			&password, \
			&request, \
			&url->options, \
			&url->state, \
			&url->status, \
			&error_msg, \
			&url->redirectedto, \
			&url->contenttype, \
			&charset, \
			&url->wwwauthenticate, \
			&url->headlen, \
			&buf, \
			&url->downstart, \
			&url->timing, \
			&cookie, \
			&redirect_info \
	);

/**
 * Returns pointer to memory, that need to be freed by free()
 */
void *mcrawler_url_serialize(mcrawler_url *url, void **buffer, int *buffer_size) {
	tpl_node *tn;
	URL_VARS;

	rawurl = url->rawurl;
	method = url->method;
	customagent = url->customagent;
	customheader = url->customheader;
	username = url->username;
	password = url->password;
	error_msg = url->error_msg;
	charset = url->charset;

	post.sz = url->postlen;
	post.addr = url->post;

	request.sz = url->request_len;
	request.addr = url->request;

	buf.sz = buf_len(url);
	buf.addr = buf_p(url);

	URL_TPL_MAP;
	if (!tn) {
		*buffer = NULL;
		*buffer_size = 0;
		return NULL;
	}

	tpl_pack(tn, 0);

	for (int i = 0; i < url->cookiecnt; i++) {
		cookie = url->cookies[i];
		tpl_pack(tn, 1);
	}
	for (mcrawler_redirect_info *rinfo = url->redirect_info; rinfo; rinfo = rinfo->next) {
		redirect_info = *rinfo;
		tpl_pack(tn, 2);
	}

	tpl_dump(tn, TPL_MEM, buffer, buffer_size);
	tpl_free(tn);
	return *buffer;
}

/**
 */
int mcrawler_url_unserialize(mcrawler_url *url, void *buffer, int buffer_size) {
	tpl_node *tn;
	URL_VARS;

	URL_TPL_MAP;
	if (!tn) {
		return 1;
	}

	// A crafted blob must not be able to corrupt memory: validate the tpl load,
	// bound every string copy to its fixed destination, and clamp the cookie count.
	if (tpl_load(tn, TPL_MEM, buffer, buffer_size) != 0) {
		tpl_free(tn);
		return 1;
	}
	if (tpl_unpack(tn, 0) <= 0) {
		tpl_free(tn);
		return 1;
	}

	safe_strncpy(url->rawurl, rawurl ? rawurl : "", sizeof(url->rawurl)); free(rawurl);
	safe_strncpy(url->method, method ? method : "", sizeof(url->method)); free(method);
	safe_strncpy(url->customagent, customagent ? customagent : "", sizeof(url->customagent)); free(customagent);
	safe_strncpy(url->customheader, customheader ? customheader : "", sizeof(url->customheader)); free(customheader);
	safe_strncpy(url->username, username ? username : "", sizeof(url->username)); free(username);
	safe_strncpy(url->password, password ? password : "", sizeof(url->password)); free(password);
	safe_strncpy(url->error_msg, error_msg ? error_msg : "", sizeof(url->error_msg)); free(error_msg);
	safe_strncpy(url->charset, charset ? charset : "", sizeof(url->charset)); free(charset);

	url->post = post.addr;
	url->postlen = post.sz;

	url->request = request.addr;
	url->request_len = request.sz;

	buf_write(url, buf.addr, buf.sz);
	free(buf.addr);

	int ccnt = tpl_Alen(tn, 1);
	if (ccnt < 0) {
		ccnt = 0;
	} else if (ccnt > COOKIESTORAGESIZE) {
		debugf("unserialize: cookie count %d exceeds storage, clamping to %d\n", ccnt, COOKIESTORAGESIZE);
		ccnt = COOKIESTORAGESIZE;
	}
	url->cookiecnt = ccnt;
	for (int i = 0; i < ccnt; i++) {
		tpl_unpack(tn, 1);
		url->cookies[i] = cookie;
	}

	mcrawler_redirect_info **current = &url->redirect_info;
	while (tpl_unpack(tn, 2) > 0) {
		*current = malloc(sizeof(mcrawler_redirect_info));
		**current = redirect_info;
		current = &(*current)->next;
	}
	*current = NULL;

	tpl_free(tn);
	return 0;
}

void *mcrawler_urls_serialize(mcrawler_url **urls, mcrawler_settings *settings, void **buffer, int *buffer_size) {
	tpl_node *tn;
	tpl_bin url_buf;

	tn = tpl_map("S(iiii)A(B)", settings, &url_buf);
	if (!tn) {
		*buffer = NULL;
		*buffer_size = 0;
		return NULL;
	}

	tpl_pack(tn, 0);
	for (int i = 0; urls[i] != NULL; i++) {
		mcrawler_url_serialize(urls[i], &url_buf.addr, (int *)&url_buf.sz);
		tpl_pack(tn, 1);
		free(url_buf.addr);
	}

	tpl_dump(tn, TPL_MEM, buffer, buffer_size);
	tpl_free(tn);
	return *buffer;
}

int mcrawler_urls_unserialize(mcrawler_url ***urls, mcrawler_settings **settings, void *buffer, int buffer_size, void *(*alloc_func)(size_t size)) {
	tpl_node *tn;
	tpl_bin url_buf;

	if (alloc_func == NULL) alloc_func = malloc;

	*settings = (mcrawler_settings *)alloc_func(sizeof(mcrawler_settings));
	mcrawler_init_settings(*settings);

	tn = tpl_map("S(iiii)A(B)", *settings, &url_buf);
	if (!tn) {
		return 1;
	}

	if (tpl_load(tn, TPL_MEM, buffer, buffer_size) != 0) {
		tpl_free(tn);
		return 1;
	}
	tpl_unpack(tn, 0);

	int len = tpl_Alen(tn, 1);
	if (len < 0) {
		len = 0;
	} else if (len > buffer_size) {
		// a valid blob needs at least a few bytes per url, so the element count
		// can never exceed the blob size; reject an absurd count from a bad blob
		debugf("urls_unserialize: url count %d exceeds blob size %d, rejecting\n", len, buffer_size);
		tpl_free(tn);
		return 1;
	}
	*urls = (mcrawler_url **)malloc((len + 1) * sizeof(mcrawler_url *));

	for (int i = 0; i < len; i++) {
		(*urls)[i] = (mcrawler_url *)alloc_func(sizeof(mcrawler_url));
		memset((*urls)[i], 0, sizeof(mcrawler_url));
		mcrawler_init_url((*urls)[i], NULL);
		tpl_unpack(tn, 1);
		if (mcrawler_url_unserialize((*urls)[i], url_buf.addr, (int)url_buf.sz) != 0) {
			// malformed per-url sub-blob: stop here rather than handing back a
			// zero-initialised url as if it were valid
			free(url_buf.addr);
			(*urls)[i] = NULL;
			tpl_free(tn);
			return 1;
		}
		free(url_buf.addr);
	}
	(*urls)[len] = NULL;

	tpl_free(tn);
	return 0;
}
