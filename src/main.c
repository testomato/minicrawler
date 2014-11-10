#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "h/cli.h"

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
	
	struct surl *url;
	struct ssettings settings;
	memset(&settings, 0, sizeof(struct ssettings));
	settings.timeout = DEFAULT_TIMEOUT;
	settings.delay = DEFAULT_DELAY;

	initurls(argc, argv, &url, &settings);
	go(url, &settings);
 
	exit(0);
}
