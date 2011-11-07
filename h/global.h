
#define UC unsigned char
#define US unsigned short
#define UI unsigned int


#define S_JUSTBORN	1
#define S_INDNS		2
#define S_GOTIP		3
#define S_CONNECTING	4
#define S_CONNECTED	5
#define S_GETREPLY	6
#define S_READYREPLY	7
#define S_DONE		10
#define S_ERROR		20

#define BUFSIZE (700*1024)

#define debugf(...)   {if(settings.debug) fprintf(stderr, __VA_ARGS__);}
