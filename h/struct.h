

struct surl {
	int index;
	char rawurl[256];
 
	char host[256];
	int port;
	char path[256];
	
	char location[256];	// presne to co je v hlavicce Location - pro ucely redirect
	char redirectedto[256];	// co nakonec hlasime ve vystupu v hlavicce
 
	int state;
	int lastread;		// cas posledniho uspesneho cteni
 
	// ares
	struct ares_channeldata *aresch;
	
	// network
	int sockfd;
	int ip;
	
	// obsah
	char buf[BUFSIZE];
	int bufp;
	int headlen;
	int contentlen;
	int status;		// http navratovy kod
 
};