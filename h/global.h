
#define UC unsigned char
#define US unsigned short
#define UI unsigned int


#define S_JUSTBORN	1
#define S_INDNS		2
#define S_GOTIP		3
#define S_CONNECTED	4
#define S_GETREPLY	5
#define S_READYREPLY	6
#define S_DONE		10
#define S_ERROR		20

#define BUFSIZE (200*1024)

#define debugf(...)   {if(debug) fprintf(stderr, __VA_ARGS__);}
