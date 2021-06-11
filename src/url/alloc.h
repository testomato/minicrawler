void append_c(char **p_buf, size_t *buf_sz, int *pos, const char c);
void append_s(char **p_buf, size_t *buf_sz, int *pos, const char *s);

void init_url(mcrawler_url_url *url);

void replace_scheme(mcrawler_url_url *url, const char *scheme);

void replace_username(mcrawler_url_url *url, const char *username);
void append_username(mcrawler_url_url *url, int *pos, const char *s);

void init_password(mcrawler_url_url *url);
void append_password(mcrawler_url_url *url, int *pos, const char *s);

void append_path(mcrawler_url_url *url, const char *s);
void do_pop_path(mcrawler_url_url *url);
void replace_path(mcrawler_url_url *url, const char **path);
void append_path0_c(mcrawler_url_url *url, const char c);
void append_path0_s(mcrawler_url_url *url, const char *s);

void init_query(mcrawler_url_url *url);
void append_query_c(mcrawler_url_url *url, int *pos, const char c);
void append_query_s(mcrawler_url_url *url, int *pos, const char *s);

void init_fragment(mcrawler_url_url *url);
void append_fragment(mcrawler_url_url *url, const char c);
void append_fragment_s(mcrawler_url_url *url, const char *s);

