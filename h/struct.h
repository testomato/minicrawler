

struct surl {
	char rawurl[256];
 
	char host[256];
	int port;
	char path[256];
 
	int state;
 
	// adns:
//	void *my_adns_context;                                                                                                                   
//        struct adns__query *my_adns_query;      

	// udns
	struct dns_ctx *ctx;
 
};