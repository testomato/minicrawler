#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"
#include "h/version.h"

struct surl url[100];

struct ssettings settings;

/** primitivni parsovatko url
 */
void simpleparseurl(struct surl *u)
{
	u->port=0;
	u->path[0]='/';

	sscanf(u->rawurl, "http://%99[^:]:%99d%99[^\n]", u->host, &(u->port), u->path);

	if(u->port==0) {sscanf(u->rawurl, "http://%[^/]/%s", u->host, u->path+1);u->port=80;}

	debugf("[%d] host='%s' port=%d path='%s'\n",u->index,u->host,u->port,u->path);
//	printf("host = \"%s\"\n", u->host);
//	printf("port = \"%d\"\n", u->port);
//	printf("path = \"%s\"\n", u->path);
}


/** nacte url z prikazove radky do struktur
 */
void initurls(int argc, char *argv[])
{
	int t;
	int i=0;
 
	for(t=1;t<argc;t++) {
		if(!strcmp(argv[t],"-d")) {settings.debug=1;continue;}
		if(!strcmp(argv[t],"-h")) {settings.writehead=1;continue;}
		if(!strcmp(argv[t],"-i")) {settings.impatient=1;continue;}
		if(!strcmp(argv[t],"-p")) {settings.partial=1;continue;}
		if(!strcmp(argv[t],"-c")) {settings.convert=1;continue;}
		if(!strcmp(argv[t],"-8")) {settings.convert_to_utf=1;continue;}
		if(!strncmp(argv[t],"-t",2)) {settings.timeout=atoi(argv[t]+2);continue;}
		if(!strncmp(argv[t],"-D",2)) {settings.delay=atoi(argv[t]+2);debugf("Delay time: %d\n",settings.delay);continue;}
		if(!strncmp(argv[t],"-w",2)) {strcpy(settings.customheader,argv[t+1]);t++;debugf("Custom header for all: %s\n",settings.customheader);continue;}

		if(!strcmp(argv[t],"-P")) {strcpy(url[i].post,argv[t+1]);t++;debugf("[%d] POST: %s\n",i,url[i].post);continue;}
		if(!strncmp(argv[t],"-C",2)) {strcpy(url[i].customparam,argv[t+1]);t++;debugf("[%d] Custom param: %s\n",i,url[i].customparam);continue;}
		
		strcpy(url[i].rawurl,argv[t]);
		url[i].index=i;
		simpleparseurl(&url[i]);
		url[i].state=S_JUSTBORN;
		//debugf("[%d] born\n",i);
		url[i].bufp=0;
		url[i].contentlen=-1;
		url[i].cookiecnt=0;
		i++;
		}

	strcpy(url[i].rawurl,""); // ukoncovaci znacka
}

/** zpracuje signál (vypíše ho a ukončí program s -1)
 */
void sighandler(int signum)
{
	debugf("Caught signal %d\n",signum);
	exit(-1);
}


/** vypise napovedu
 */
void printusage()
{
	printf("\nminicrawler, version %s\n\nUsage:   minicrawler [-d] [-h] [i] [-tSECONDS] url [url2] [url3] [...]\n\n"
	         "Where:   -d         enables debug messages (to stderr)\n"
	         "         -tSECONDS  sets timeout (default is 5 seconds)\n"
	         "         -h         enables output of headers\n"
	         "         -i         enables impatient mode (minicrawler exits few seconds earlier if it doesn't make enough progress\n"
	         "         -p         outputs also partially downloaded urls\n"
	         "         -w STRING  write this custom header to all requests\n"
	         "         -C STRING  parameter which replaces '%%' in the custom header\n"
	         "         -c         convert to text format\n"
	         "         -8         convert from page encoding to utf-8\n"
	         "         -DMILIS    set delay time in miliseconds when downloading more pages from the same IP\n"
	         "\n",VERSION);
}

/** a jedeeeem...
 */
int main(int argc, char *argv[])
{
	if(argc<2) {printusage();exit(-1);}
	
	signal(SIGUSR1,sighandler);
	signal(SIGPIPE,sighandler);
//	signal(SIGSEGV,sighandler);

	settings.timeout=5;
	settings.delay=100;
	
	initurls(argc,argv);
	go();
 
	exit(0);
}

