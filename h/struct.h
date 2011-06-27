

struct surl {
	int index;
	char rawurl[256];
 
	char host[256];
	int port;
	char path[256];
 
	int state;
	int lastread;		// cas posledniho uspesneho cteni
 
	// ares
	struct ares_channeldata *aresch;
	
	// network
	int sockfd;
	int ip;
	
	// obsah
	UC buf[BUFSIZE];
	int bufp;
	int headlen;
	int contentlen;
	int status;		// http navratovy kod
 
};