#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

struct surl url[100];

/** primitivni parsovatko url
 */
void simpleparseurl(struct surl *u)
{
	u->port=80;

	sscanf(u->rawurl, "http://%[^/]/%99[^\n]", u->host, u->path);

/*	sscanf(u->rawurl, "http://%99[^:]:%99d/%99[^\n]", u->host, &(u->port), u->path);*/

/*	 printf("host = \"%s\"\n", u->host);
	printf("port = \"%d\"\n", u->port);
	printf("path = \"%s\"\n", u->path);*/
}


/** nacte url z prikazove radky do struktur
 */
void initurls(int argc, char *argv[])
{
	int t;
 
	for(t=0;t<argc-1;t++) {
		strcpy(url[t].rawurl,argv[t+1]);
		simpleparseurl(&url[t]);
		url[t].state=S_JUSTBORN;
		url[t].index=t;
		}

	strcpy(url[t].rawurl,""); // ukoncovaci znacka
}

/** a jedeeeem...
 */
int main(int argc, char *argv[])
{
	if(argc<2) {printf("\nUsage:   minicrawler url [url2] [url3] [...]\n\n");exit(-1);}

	initurls(argc,argv);
	go();
 
	exit(0);
}

