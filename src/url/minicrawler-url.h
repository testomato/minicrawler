enum {
	MCRAWLER_URL_SUCCESS,
	MCRAWLER_URL_FAILURE
};

typedef enum {
	MCRAWLER_URL_HOST_NONE = 0,
	MCRAWLER_URL_HOST_DOMAIN = 1,
	MCRAWLER_URL_HOST_IPV4 = 2,
	MCRAWLER_URL_HOST_IPV6 = 3
} mcrawler_url_host_type;

typedef struct {
	char *domain;
	unsigned char ipv4[4];
	unsigned char ipv6[16];
	mcrawler_url_host_type type;
} mcrawler_url_host;

typedef struct mcrawler_url_url {
	char *scheme;
	char *username;
	char *password;
	mcrawler_url_host *host;
	unsigned int port;
	int port_not_null;
	char **path;
	unsigned int path_len;
	char *query;
	char *fragment;
	int cannot_be_a_base_url;
	void *object;
} mcrawler_url_url;

int mcrawler_url_parse(mcrawler_url_url *url, const char *input, const mcrawler_url_url *base);
int mcrawler_url_parse_host(mcrawler_url_host *host, const char *input);
int mcrawler_url_parse_ipv6(mcrawler_url_host *host, const char *input);
int mcrawler_url_parse_ipv4(mcrawler_url_host *host, const char *input);
void mcrawler_url_free_url(mcrawler_url_url *url);

char *mcrawler_url_serialize_ipv6(mcrawler_url_host *host);
char *mcrawler_url_serialize_ipv4(mcrawler_url_host *host);
char *mcrawler_url_serialize_path_and_query(mcrawler_url_url *url);
char *mcrawler_url_serialize_url(mcrawler_url_url *url, int exclude_fragment);


char *mcrawler_url_get_href(mcrawler_url_url *url);
char *mcrawler_url_get_protocol(mcrawler_url_url *url);
char *mcrawler_url_get_username(mcrawler_url_url *url);
char *mcrawler_url_get_password(mcrawler_url_url *url);
char *mcrawler_url_get_host(mcrawler_url_url *url);
char *mcrawler_url_get_hostname(mcrawler_url_url *url);
char *mcrawler_url_get_port(mcrawler_url_url *url);
char *mcrawler_url_get_pathname(mcrawler_url_url *url);
char *mcrawler_url_get_search(mcrawler_url_url *url);
char *mcrawler_url_get_hash(mcrawler_url_url *url);
