#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#include "h/cli.h"
#include "h/minicrawler.h"

struct ssettings settings;

void sighandler(int signum)
{
	fprintf(stderr, "Caught signal %d\n", signum);
	exit(signum);
}

int main(int argc, char *argv[]) {
	if(argc < 2) {
		printusage();
		exit(1);
	}
	
	signal(SIGUSR1,sighandler);
	signal(SIGPIPE,sighandler);
//	signal(SIGSEGV,sighandler);

	settings.timeout=DEFAULT_TIMEOUT;
	settings.delay=DEFAULT_DELAY;
	
	struct surl *url;
	url = initurls(argc, argv);
	go(url);
 
	exit(0);
}
