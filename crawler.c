#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <ares.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

/** callback funkce, kterou zavola ares
 */
void *dnscallback(void *arg, int status, int timeouts, struct hostent *hostent)
{
	UC *ip;
	struct surl *u;
	
	u=(struct surl *)arg;
	if(status!=0) {debugf("[%d] error: dnscallback with non zero status! - status=%d\n",u->index,status);u->state=S_ERROR;return;}
	
	ip=(UC*)(hostent->h_addr);
	u->ip=*(int *)ip;
	
	debugf("[%d] Resolving %s ended => %d.%d.%d.%d\n",u->index,u->host,ip[0],ip[1],ip[2],ip[3]);
	
	u->state=S_GOTIP;
}


/** spusti preklad pres ares
 */
void launchdns(struct surl *u)
{
	int t;
	
	debugf("[%d] Resolving %s starts\n",u->index,u->host);
	
	t=ares_init(&(u->aresch));
	if(t) {debugf("ares_init failed\n");exit(-1);}

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
	int flags;

	addr.sin_family=AF_INET;
	addr.sin_port=htons(u->port);
	memcpy(&(addr.sin_addr),&(u->ip),4);

	u->sockfd=socket(AF_INET,SOCK_STREAM,0);
	flags=fcntl(u->sockfd,F_GETFL,0);              // Get socket flags
	fcntl(u->sockfd,F_SETFL,flags | O_NONBLOCK);   // Add non-blocking flag	
	
	t=connect(u->sockfd,(struct sockaddr *)&addr,sizeof(addr));
	if(t) {
		if(errno==115) u->state=S_CONNECTING; // 115 je v pohode (operation in progress)
		else {debugf("%d: connect failed (%d, %s)\n",u->index,errno,strerror(errno));u->state=S_ERROR;}
		}
	else u->state=S_CONNECTED;
}

/** socket bezi, posli dotaz
 */
void sendhttpget(struct surl *u)
{
	UC buf[1024];
	int t;
	
	if(!u->post[0]) // GET
		sprintf(buf,"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",u->path,u->host);
	else { // POST
		sprintf(buf,"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s\r\n\r\n",
			u->path,u->host,(int)strlen(u->post),u->post);
	}
	 
	//debugf(buf);
	
	t=write(u->sockfd,buf,strlen(buf));
	if(t<strlen(buf)) {debugf("[%d] Error - written %d bytes, wanted %d bytes\n",u->index,t,(int)strlen(buf));}
	else debugf("[%d] Written %d bytes\n",u->index,t);
	
	u->state=S_GETREPLY;
}

/** strcpy, ktere se ukonci i koncem radku
 */
void strcpy_term(char *to, char *from)
{
	for(;*from&&*from!='\r'&&*from!='\n';) *to++=*from++;
	*to=0;
}

/** sezere to radku tam, kde ceka informaci o delce chunku
 *  jedinou vyjimkou je, kdyz tam najde 0, tehdy posune i contentlen, aby dal vedet, ze jsme na konci
 */
void eatchunked(struct surl *u,int first)
{
	int t,i;
	UC hex[10];
	int size;
	int movestart;
	
	for(t=u->nextchunkedpos,i=0;u->buf[t]!='\r'&&t<u->bufp;t++) {
		if(i<9) hex[i++]=u->buf[t];
		}
	if(u->buf[t]=='\r') t++;
	if(u->buf[t]=='\n') t++;
		
	hex[i]=0;
	size=strtol(hex,NULL,16);
		
	debugf("[%d] Chunksize at %d (now %d): '%s' (=%d)\n",u->index,u->nextchunkedpos,u->bufp,hex,size);

	movestart=u->nextchunkedpos;
	if(!first) movestart-=2;
	memmove(u->buf+movestart,u->buf+t,u->bufp-t);		// cely zbytek posun
	u->bufp-=(t-movestart);					// ukazatel taky
	
	u->nextchunkedpos=movestart+size+2;			// o 2 vic kvuli odradkovani na konci chunku
	
	if(size==0) {debugf("[%d] Chunksize=0 (end)\n",u->index);u->contentlen=u->bufp-u->headlen;}	// a to je konec, pratele! ... taaadydaaadydaaa!
}

/** pozná status a hlavičku http požadavku
 */
void detecthead(struct surl *u)
{
	char *p;

	u->status=atoi(u->buf+9);
	u->buf[u->bufp]=0;
	
	p=strstr(u->buf,"\r\n\r\n");
	if(p) p+=4;
	
	if(p==NULL) {p=strstr(u->buf,"\n\n");if(p) p+=2;}
	
	if(p==NULL) {debugf("[%d] cannot find end of http header?\n",u->index);return;}
	
	u->headlen=p-u->buf;
	
	p=(char*)memmem(u->buf,u->headlen,"Content-Length: ",16);
	if(p!=NULL) u->contentlen=atoi(p+16);
	
	p=(char*)memmem(u->buf,u->headlen,"\nLocation: ",11);
	if(p!=NULL) {strcpy_term(u->location,p+11);debugf("[%d] Location='%s'\n",u->index,u->location);}
	
	p=(char*)memmem(u->buf,u->headlen,"Transfer-Encoding: chunked",26);
	if(p!=NULL) {u->chunked=1;u->nextchunkedpos=u->headlen;debugf("[%d] Chunked!\n",u->index);}
	
	debugf("[%d] status=%d, headlen=%d, content-length=%d\n",u->index,u->status,u->headlen,u->contentlen);
	
	if(u->chunked) eatchunked(u,1);
}

/** vypise vystup na standardni vystup
 */
void output(struct surl *u)
{
	UC header[1024];
	
	sprintf(header,"URL: %s\n",u->rawurl);
	if(u->redirectedto[0]) sprintf(header+strlen(header),"Redirected-To: %s\n",u->redirectedto);
	sprintf(header+strlen(header),"Status: %d\nContent-length: %d\n\n",u->status,u->bufp-u->headlen);

	write(STDOUT_FILENO,header,strlen(header));
	if(settings.writehead) write(STDOUT_FILENO,u->buf,u->headlen);
	write(STDOUT_FILENO,u->buf+u->headlen,u->bufp-u->headlen);
	
	if(u->chunked) debugf("[%d] bufp=%d nextchunkedpos=%d\n",u->index,u->bufp,u->nextchunkedpos);
	
	debugf("[%d] Outputed.\n",u->index);
	
	u->state=S_DONE;
	debugf("[%d] Done.\n",u->index);
}

/** vyres presmerovani
 */
void resolvelocation(struct surl *u)
{
	char lhost[256];
	char lpath[256]="/";

	debugf("[%d] Resolve location='%s'\n",u->index,u->location);
	
	if(u->location[0]=='/') {strcpy(lhost,u->host);strcpy(lpath,u->location);} // relativni adresy (i kdyz by podle RFC nemely byt)
	else sscanf(u->location, "http://%[^/]/%s", lhost, lpath+1);
	
	debugf("[%d] Lhost='%s' Lpath='%s'\n",u->index,lhost,lpath);

	if(strcmp(u->host,lhost)) u->state=S_JUSTBORN;	// pokud je to jina domena, tak znovu resolvuj
	else u->state=S_GOTIP;		// jinak se muzes pripojit na tu puvodni IP
	
	strcpy(u->path,lpath);		// bez tam
	strcpy(u->host,lhost);		// bez tam
	strcpy(u->redirectedto,u->location);
	u->location[0]=0;
	u->post[0]=0;
	u->headlen=0;
	u->contentlen=-1;
	u->bufp=0;
}

/** uz mame cely vstup - bud ho vypis nebo vyres presmerovani
 */
void finish(struct surl *u)
{
	if(u->headlen==0) detecthead(u);	// nespousteli jsme to predtim, tak pustme ted

	if(u->location[0]) resolvelocation(u);
	else output(u);
}

/** cti odpoved
 */
void readreply(struct surl *u)
{
	UC buf[1024];
	int t;
	int left;

	left=BUFSIZE-u->bufp;
	if(left<=0) return;
	if(left>4096) left=4096;
	t=read(u->sockfd,u->buf+u->bufp,left);
	if(t>0) {
		u->bufp+=t;
		u->lastread=gettimeint();
		if(u->headlen==0) detecthead(u);		// pokud jsme to jeste nedelali, tak precti hlavicku
		}
	
	
	debugf("[%d] Read %d bytes\n",u->index,t);
	//buf[60]=0; // wtf?
	
	if(t>0&&u->chunked) {
		while(u->bufp>u->nextchunkedpos) eatchunked(u,0);	// pokud jsme presli az pres chunked hlavicku, tak ji sezer
		}
	
	if(t<=0||(u->contentlen!=-1&&u->bufp>=u->headlen+u->contentlen)) {close(u->sockfd);finish(u);}
	else u->state=S_GETREPLY;
	//debugf("%s",buf);
	
}

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede systemovy select nad vsemi streamy, ktere jsou ve stavu GETREPLY (a pripadne je prehodi do READYREPLY)
 */
void selectall()
{
	int t;
	fd_set set;
	fd_set writeset;
	struct timeval timeout;	
	
	FD_ZERO (&set);
	FD_ZERO (&writeset);
	timeout.tv_sec = 0;
	timeout.tv_usec = 20000;	
	
	for(t=0;url[t].rawurl[0];t++) {
		if(url[t].state==S_GETREPLY) {
			//debugf("[%d] into read select...\n",t);
			FD_SET (url[t].sockfd, &set);
			}
		
		if(url[t].state==S_CONNECTING) {
			//debugf("[%d] into read write select...\n",t);
			FD_SET (url[t].sockfd, &writeset);
			}
	}
	
	t=select (FD_SETSIZE,&set, &writeset, NULL, &timeout);
	if(!t) return; // nic
	//debugf("select status: %d\n",t);
	
	for(t=0;url[t].rawurl[0];t++) {
		if(FD_ISSET(url[t].sockfd,&set)&&url[t].state==S_GETREPLY) {
			//debugf("[%d] is ready for reading\n",t);
			url[t].state=S_READYREPLY;
			}
		if(FD_ISSET(url[t].sockfd,&writeset)&&url[t].state==S_CONNECTING) {
			//debugf("[%d] is ready for writing\n",t);
			url[t].state=S_CONNECTED;
			}
		
	}
	
}


/** provede jeden krok pro dane url
 */
void goone(struct surl *u)
{
	int tim,state;
	//debugf("[%d]: %d\n",u->index,u->state);

	tim=gettimeint();

	state=u->state;
	switch(state) {
  
	case S_JUSTBORN:
		launchdns(u);
		break;
  
	case S_INDNS:
		checkdns(u);
		break;

	case S_GOTIP:
		opensocket(u);
		break;
  
	case S_CONNECTING:
		// nic, z tohohle stavu mne dostane select
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
	
	tim=gettimeint()-tim;
	if(tim>200) debugf("[%d] State %d (->%d) took too long (%d ms)\n",u->index,state,u->state,tim);
  
}

/** vrati 1 pokud je dobre ukoncit se predcasne
 */
int exitprematurely()
{
	int tim;
	int t;
	int notdone=0, lastread=0;
	
	tim=gettimeint();
	if(tim<settings.timeout*1000-1000) return 0; // jeste je brzy
	
	for(t=0;url[t].rawurl[0];t++) {
		if(url[t].state<S_DONE) notdone++;
		if(url[t].lastread>lastread) lastread=url[t].lastread;
	}
	
	debugf("[-] impatient: %d not done, last read at %d ms (now %d)\n",notdone,lastread,tim);
	
	if(t>=5&&notdone==1&&(tim-lastread)>400) {debugf("[-] Forcing premature end 1!\n");return 1;}
	if(t>=20&&notdone<=2&&(tim-lastread)>400) {debugf("[-] Forcing premature end 2!\n");return 1;}
	
	return 0;
}

/** vypise obsah vsech dosud neuzavrenych streamu
 */
void outputpartial()
{
	int t;

	for(t=0;url[t].rawurl[0];t++) {
		if(url[t].state==S_GETREPLY) output(&url[t]);
	
	}
}

/** hlavni smycka
 */
void go()
{
	int t;
	int done;
	int change;
	int state;

	do {
		done=1;
		change=0;
		
		selectall();
		for(t=0;url[t].rawurl[0];t++) {
			//debugf("%d: %d\n",t,url[t].state);
			state=url[t].state;
			if(url[t].state<S_DONE) {goone(&url[t]);done=0;}
			if(state!=url[t].state) change=1;
		}
		
		t=gettimeint();
		if(t>settings.timeout*1000) {debugf("Timeout (%d ms elapsed). The end.\n",t);if(settings.partial) outputpartial();break;}
		
		if(!change&&!done) {
			if(settings.impatient) done=exitprematurely();
			usleep(20000);
			}
	} while(!done);
	
	if(done) debugf("All successful. Took %d ms.\n",gettimeint());
}

