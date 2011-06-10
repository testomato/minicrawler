#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ares.h>
#include <sys/types.h>          
#include <sys/socket.h>

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
	u->ip=*(int *)ip;
	
	printf("[%d] Resolving %s ended => %d.%d.%d.%d\n",u->index,u->host,ip[0],ip[1],ip[2],ip[3]);
	
	u->state=S_GOTIP;
}


/** spusti preklad pres ares
 */
void launchdns(struct surl *u)
{
	int t;
	
	printf("[%d] Resolving %s starts\n",u->index,u->host);
	
	t=ares_init(&(u->aresch));
	if(t) {printf("ares_init failed\n");exit(-1);}

	ares_gethostbyname(u->aresch,u->host,AF_INET,(ares_host_callback)&dnscallback,u);

	u->state=S_INDNS;
}

/** uz je ares hotovy?
 */
void checkdns(struct surl *u)
{
	int t;
	fd_set readfds;
	fd_set writefds;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	t=ares_fds(u->aresch,&readfds,&writefds);
	if(!t) return;

	ares_process(u->aresch,&readfds,&writefds); // pri uspechu zavola callback sama
}       

/** uz znam IP, otevri socket
 */
void opensocket(struct surl *u)
{
	struct sockaddr_in addr;
	int t;

	addr.sin_family=AF_INET;
	addr.sin_port=htons(80);
	memcpy(&(addr.sin_addr),&(u->ip),4);

	u->sockfd=socket(AF_INET,SOCK_STREAM,0);
	t=connect(u->sockfd,(struct sockaddr *)&addr,sizeof(addr));
	if(t) printf("%d: connect failed\n",u->index);

	u->state=S_CONNECTED;
}

/** socket bezi, posli dotaz
 */
void sendhttpget(struct surl *u)
{
	UC buf[1024];
	int t;
	
	sprintf(buf,"GET %s HTTP/1.1\nHost: %s\n\n",u->path,u->host);
	//printf(buf);
	
	t=write(u->sockfd,buf,strlen(buf));
	printf("[%d] Written %d bytes\n",u->index,t);
	
	u->state=S_GETREPLY;
}

/** cti odpoved
 */
void readreply(struct surl *u)
{
	UC buf[1024];
	int t;
	int left;

//	if(feof(u->sockfd)) {close(u->sockfd);u->state=DONE;}

	left=BUFSIZE-u->bufp;
	if(left<=0) return;
	if(left>4096) left=4096;
	t=read(u->sockfd,u->buf+u->bufp,left);
	
	printf("[%d] Read %d bytes\n",u->index,t);
	buf[60]=0;
	
	if(t<left) {close(u->sockfd);u->state=S_DONE;printf("[%d] done.\n",u->index);}
	else u->state=S_GETREPLY;
	//printf("%s",buf);
	
}

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede systemovy select nad vsemi streamy, ktere jsou ve stavu GETREPLY (a pripadne je prehodi do READYREPLY)
 */
void selectall()
{
	int t;
	fd_set set;
	struct timeval timeout;	
	
	FD_ZERO (&set);
	timeout.tv_sec = 0;
	timeout.tv_usec = 50000;	
	
	for(t=0;url[t].rawurl[0];t++) {
		if(url[t].state!=S_GETREPLY) continue;
		FD_SET (url[t].sockfd, &set);
	}
	
	t=select (FD_SETSIZE,&set, NULL, NULL, &timeout);
	if(!t) return; // nic
	//printf("select status: %d\n",t);
	
	for(t=0;url[t].rawurl[0];t++) {
		if(!FD_ISSET(url[t].sockfd,&set)) continue;
		printf("[%d] is ready for reading\n",t);
		url[t].state=S_READYREPLY;
	}
	
}


/** provede jeden krok pro dane url
 */
void goone(struct surl *u)
{
	//printf("[%d]: %d\n",u->index,u->state);

	switch(u->state) {
  
	case S_JUSTBORN:
		launchdns(u);
		break;
  
	case S_INDNS:
		checkdns(u);
		break;

	case S_GOTIP:
		opensocket(u);
		break;
  
	case S_CONNECTED:
		sendhttpget(u);
		break;
  
	case S_GETREPLY:
		// nic, z tohohle stavu mne dostane select
		break;
  

	case S_READYREPLY:
		readreply(u);
		break;
	}
  
}

/** hlavni smycka
 */
void go()
{
	int t;
	int done;

	do {
		done=1;
		selectall();
		for(t=0;url[t].rawurl[0];t++) {
			//printf("%d: %d\n",t,url[t].state);
			if(url[t].state!=S_DONE) {goone(&url[t]);done=0;}
		}
		
		//printf("\n"); 
		usleep(50000);
	} while(!done);
}

