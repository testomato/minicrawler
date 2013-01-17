

struct nv {
    char *name, *value;
};

struct surl {
	int index;
	char rawurl[1024];
 
	char proto[32];
	char host[256];
	int port;
	char path[1024];
	char post[4096];

	// hlavicky	
	char location[1024];	// presne to co je v hlavicce Location - pro ucely redirect
	char redirectedto[1024];	// co nakonec hlasime ve vystupu v hlavicce
	int chunked;		// 1  pokud transfer-encoding: chunked
	int nextchunkedpos;
	struct nv cookies[20];	// nekolik cookie, kazda ma name ([0]) a value ([1])
	int cookiecnt;
	char customparam[256];		// parametr do custom headeru
	char charset[32];
 
	int state;
	int lastread;		// cas posledniho uspesneho cteni
	int downstart;		// time downloading start
	// ares
	struct ares_channeldata *aresch;
	
	// network
	int sockfd;
	int ip;
	int prev_ip;
	
	// obsah
	char buf[BUFSIZE];
	int bufp;
	int headlen;
	int contentlen;
	int status;		// http navratovy kod
	char error_msg[256];

	// errno
 	int conv_errno;		// set in case of wrong conversion
};

struct ssettings {
	int debug;
	int timeout;
	int writehead;
	int impatient;
	int partial;
	int convert;		// 1 pokud se má konvertovat do textu
	int convert_to_utf;     // 1 pokud se ma konvertovat do utf8
	int delay;		// zpozdeni pri stahovani ze stejne ip, default je 100ms
	char customagent[256];
	char customheader[4096];
};
