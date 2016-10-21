#include "h/config.h"

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

	tpl_load(tn, TPL_MEM, buffer, buffer_size);
	tpl_unpack(tn, 0);

	strcpy(url->rawurl, rawurl); free(rawurl);
	strcpy(url->method, method); free(method);
	strcpy(url->customagent, customagent); free(customagent);
	strcpy(url->customheader, customheader); free(customheader);
	strcpy(url->username, username); free(username);
	strcpy(url->password, password); free(password);
	strcpy(url->error_msg, error_msg); free(error_msg);
	strcpy(url->charset, charset); free(charset);

	url->post = post.addr;
	url->postlen = post.sz;

	url->request = request.addr;
	url->request_len = request.sz;

	buf_write(url, buf.addr, buf.sz);
	free(buf.addr);

	url->cookiecnt = tpl_Alen(tn, 1);
	for (int i = 0; i < url->cookiecnt; i++) {
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

	tpl_load(tn, TPL_MEM, buffer, buffer_size);
	tpl_unpack(tn, 0);

	int len = tpl_Alen(tn, 1);
	*urls = (mcrawler_url **)malloc((len + 1) * sizeof(mcrawler_url *));

	for (int i = 0; i < len; i++) {
		(*urls)[i] = (mcrawler_url *)alloc_func(sizeof(mcrawler_url));
		memset((*urls)[i], 0, sizeof(mcrawler_url));
		mcrawler_init_url((*urls)[i], NULL);
		tpl_unpack(tn, 1);
		mcrawler_url_unserialize((*urls)[i], url_buf.addr, (int)url_buf.sz);
		free(url_buf.addr);
	}
	(*urls)[len] = NULL;

	tpl_free(tn);
	return 0;
}
