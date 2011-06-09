#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ares.h>
#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"


/** callback funkce, kterou zavola ares
 */
void *dnscallback(void *arg, int status, int timeouts, struct hostent *hostent)
{
	UC *ip;
	struct surl *u;
	
	if(status!=0) printf("error: dnscallback with non zero status!\n");
	
	ip=(UC*)(hostent->h_addr);
	u=(struct surl *)arg;
	
	printf("[%d] Resolving %s ended => %d.%d.%d.%d\n",u->index,u->host,ip[0],ip[1],ip[2],ip[3]);
	
	u->state=S_GOTIP;
}


/** spusti preklad pres adns
 */
void launchdns(struct surl *u)
{
	int t;
	
	printf("[%d] Resolving %s starts\n",u->index,u->host);
	
	t=ares_init(&(u->aresch));
	if(t) {printf("ares_init failed\n");exit(-1);}

	ares_gethostbyname(u->aresch,u->host,AF_INET,(ares_host_callback)&dnscallback,u);

	u->state=S_INADNS;
}

/** uz je adns hotove?
 */
void checkdns(struct surl *u)
{
	int t;
	UC buf[1024];
	fd_set readfds;
	fd_set writefds;
	struct timeval tv, *tvp;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	t=ares_fds(u->aresch,&readfds,&writefds);
	if(!t) return;

	ares_process(u->aresch,&readfds,&writefds); // pri uspechu zavola callback sama
}       

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede jeden krok pro dane url
 */
void goone(struct surl *u)
{
	switch(u->state) {
  
	case S_JUSTBORN:
		launchdns(u);
		break;
  
	case S_INADNS:
		checkdns(u);
  
	}
  
}

/** hlavni smycka
 */
void go()
{
	int t;

	
	while(1) {
		for(t=0;url[t].rawurl[0];t++) {
			//printf("%d: %d\n",t,url[t].state);
			goone(&url[t]);
		}
		
	//printf("\n"); 
	usleep(5000);
	}
}