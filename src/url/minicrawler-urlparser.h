enum {
	MCRAWLER_PARSER_SUCCESS,
	MCRAWLER_PARSER_FAILURE
};

typedef enum {
	MCRAWLER_PARSER_HOST_NONE = 0,
	MCRAWLER_PARSER_HOST_DOMAIN = 1,
	MCRAWLER_PARSER_HOST_IPV4 = 2,
	MCRAWLER_PARSER_HOST_IPV6 = 3
} mcrawler_parser_url_host_type;

typedef struct {
	char *domain;
	unsigned char ipv4[4];
	unsigned char ipv6[16];
	mcrawler_parser_url_host_type type;
} mcrawler_parser_url_host;

typedef struct mcrawler_parser_url {
	char *scheme;
	char *username;
	char *password;
	mcrawler_parser_url_host *host;
	unsigned int port;
	int port_not_null;
	char **path;
	char *query;
	char *fragment;
	int non_relative;
	void *object;
} mcrawler_parser_url;

int mcrawler_parser_parse(mcrawler_parser_url *url, const char *input, mcrawler_parser_url *base);
int mcrawler_parser_parse_host(mcrawler_parser_url_host *host, const char *input);
int mcrawler_parser_parse_ipv6(mcrawler_parser_url_host *host, const char *input);
int mcrawler_parser_parse_ipv4(mcrawler_parser_url_host *host, const char *input);
void mcrawler_parser_free_url(mcrawler_parser_url *url);
char *mcrawler_parser_serialize_ipv6(mcrawler_parser_url_host *host);
char *mcrawler_parser_serialize_ipv4(mcrawler_parser_url_host *host);
char *mcrawler_parser_serialize_path_and_query(mcrawler_parser_url *url);
char *mcrawler_parser_serialize(mcrawler_parser_url *url, int exclude_fragment);
