#define _GNU_SOURCE // memmem(.) needs this :-(
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

static void set_atomic_int(int *ptr, const int val)
{
	*(volatile int*)ptr = val;
	asm volatile ("" : : : "memory");  // memory barrier
}

static int get_atomic_int(int *ptr)
{
	return *(volatile int*)ptr;
}

/** callback funkce, kterou zavola ares
 */
static void dnscallback(void *arg, int status, int timeouts, struct hostent *hostent)
{
	UC *ip;
	struct surl *u;
	
	u=(struct surl *)arg;
	if(status!=0) {debugf("[%d] error: dnscallback with non zero status! - status=%d\n",u->index,status);set_atomic_int(&u->state, S_ERROR);return;}
	
	ip=(UC*)(hostent->h_addr);
	u->ip=*(int *)ip;
	
	debugf("[%d] Resolving %s ended => %d.%d.%d.%d\n",u->index,u->host,ip[0],ip[1],ip[2],ip[3]);
	debugf("[%d] raw url => %s\n", u->index, u->rawurl);

	set_atomic_int(&u->state, S_GOTIP);
}


/** spusti preklad pres ares
 */
static void launchdns(struct surl *u)
{
	int t;
	
	debugf("[%d] Resolving %s starts\n",u->index,u->host);
	
	t=ares_init(&(u->aresch));
	if(t) {debugf("ares_init failed\n");exit(-1);}

	set_atomic_int(&u->state, S_INDNS);
	ares_gethostbyname(u->aresch,u->host,AF_INET,(ares_host_callback)&dnscallback,u);
}

/** uz je ares hotovy?
 */
static void checkdns(struct surl *u)
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
static void opensocket(struct surl *u)
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
		if(errno==115) {
			set_atomic_int(&u->state, S_CONNECTING); // 115 je v pohode (operation in progress)
		}
		else {
			debugf("%d: connect failed (%d, %s)\n",u->index,errno,strerror(errno));
			set_atomic_int(&u->state, S_ERROR);}
		}
	else {
		set_atomic_int(&u->state, S_CONNECTED);
	}
}

/** neci kod na str_replace (pod free licenci)
 */
static char *str_replace( const char *string, const char *substr, const char *replacement ) {
	char *tok = NULL;
	char *newstr = NULL;
 
	tok = strstr( string, substr );
	if( tok == NULL ) return strdup( string );
	newstr = malloc( strlen( string ) - strlen( substr ) + strlen( replacement ) + 1 );
	if( newstr == NULL ) return NULL;
	memcpy( newstr, string, tok - string );
	memcpy( newstr + (tok - string), replacement, strlen( replacement ) );
	memcpy( newstr + (tok - string) + strlen( replacement ), tok + strlen( substr ), strlen( string ) - strlen( substr ) - ( tok - string ) );
	memset( newstr + strlen( string ) - strlen( substr ) + strlen( replacement ), 0, 1 );
	return newstr;
} 

/** socket bezi, posli dotaz
 */
static void sendhttpget(struct surl *u)
{
	char buf[1024];
	int t;
	char cookiestring[4096];
	char customheader[4096];
	char *p;

	// vytvoří si to řetězec cookies a volitelných parametrů
	cookiestring[0]=0;
	for(t=0;t<u->cookiecnt;t++) {
		if(t==0) sprintf(cookiestring,"Cookie: %s=%s",u->cookies[t][0],u->cookies[t][1]);
		else sprintf(cookiestring+strlen(cookiestring),"; %s=%s",u->cookies[t][0],u->cookies[t][1]);
	}
	if(settings.customheader) {
		sprintf(customheader,"%s\r\n",settings.customheader);
		if(u->customparam[0]) {p=str_replace(customheader,"%",u->customparam);strcpy(customheader,p);}
		debugf("[%d] Customheader: %s",u->index,customheader);
		strcpy(cookiestring+strlen(cookiestring),customheader);
	} 
	if(t) sprintf(cookiestring+strlen(cookiestring),"\r\n");
	
	if(!u->post[0]) {// GET
		sprintf(buf,"GET %s HTTP/1.1\r\nUser-Agent: minicrawler/1\r\nHost: %s\r\n%s\r\n",u->path,u->host,cookiestring);
		//debugf("GET %s HTTP/1.1\r\nUser-Agent: minicrawler/1\r\nHost: %s\r\n",u->path,u->host);
		//debugf("%s\r\n",cookiestring);
	} else { // POST
		sprintf(buf,"POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: minicrawler/1\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s\r\n%s\r\n",
			u->path,u->host,(int)strlen(u->post),u->post,cookiestring);
	}
	 
	//debugf(buf);
	
	t=write(u->sockfd,buf,strlen(buf));
	if(t<strlen(buf)) {debugf("[%d] Error - written %d bytes, wanted %d bytes\n",u->index,t,(int)strlen(buf));}
	else debugf("[%d] Written %d bytes\n",u->index,t);
	
	set_atomic_int(&u->state, S_GETREPLY);
}

/** strcpy, ktere se ukonci i koncem radku
 */
static void strcpy_term(char *to, char *from)
{
	for(;*from&&*from!='\r'&&*from!='\n';) *to++=*from++;
	*to=0;
}

/** strcpy, které se ukončí i konkrétním znakem
 * vrátí délku řetězce (bez ukončovacího znaku)
 */
static int strcpy_endchar(char *to, char *from, char endchar)
{
	int len=0;
	for(;*from&&*from!=endchar;len++) *to++=*from++;
	*to=0;
	return len;
}

/** sezere to radku tam, kde ceka informaci o delce chunku
 *  jedinou vyjimkou je, kdyz tam najde 0, tehdy posune i contentlen, aby dal vedet, ze jsme na konci
 *  @return 0 je ok, -1 pokud tam neni velikost chunku zapsana cela
 */
static int eatchunked(struct surl *u,int first)
{
	int t,i;
	UC hex[10];
	int size;
	int movestart;

	// čte velikost chunku	
	for(t=u->nextchunkedpos,i=0;u->buf[t]!='\r'&&t<u->bufp;t++) {
		if(i<9) hex[i++]=u->buf[t];
		}
	if(t>=u->bufp) {debugf("[%d] Incorrectly ended chunksize!",u->index);return -1;}
	if(u->buf[t]=='\r') t++;
	if(u->buf[t]=='\n') t++;

	if(i==0) debugf("[%d] Warning: empty string for chunksize\n",u->index);		
	hex[i]=0;
	size=strtol(hex,NULL,16);
		
	debugf("[%d] Chunksize at %d (now %d): '%s' (=%d)\n",u->index,u->nextchunkedpos,u->bufp,hex,size);

	movestart=u->nextchunkedpos;
	if(!first&&movestart!=u->headlen) {/*debugf("eating %d %d at %d\n",u->buf[movestart-2],u->buf[movestart-1],movestart);*/movestart-=2;} // ten headlen je kvuli adventura.cz - moooc divne
	memmove(u->buf+movestart,u->buf+t,u->bufp-t);		// cely zbytek posun
	u->bufp-=(t-movestart);					// ukazatel taky
	
	u->nextchunkedpos=movestart+size+2;			// o 2 vic kvuli odradkovani na konci chunku
	
	if(size==0) {debugf("[%d] Chunksize=0 (end)\n",u->index);u->contentlen=u->bufp-u->headlen;}	// a to je konec, pratele! ... taaadydaaadydaaa!
	
	return 0;
}

/** zapíše si do pole novou cookie (pokud ji tam ještě nemá; pokud má, tak ji nahradí)
 * kašleme na cestu a na dobu platnosti cookie (to by mělo být pro účely minicrawleru v pohodě)
 */
static void setcookie(struct surl *u,char *str)
{
	char name[256];
	char value[256];
	int t;

	t=strcpy_endchar(name,str,'=');	
	strcpy_endchar(value,str+t+1,';');
	
	
	for(t=0;t<u->cookiecnt;t++) if(!strcmp(name,u->cookies[t][0])) break;
	
	if(t<u->cookiecnt) { // už tam byla
		if(!strcmp(u->cookies[t][1],value)) {debugf("[%d] Received same cookie #%d: '%s' = '%s'\n",u->index,t,name,value);}
		else {
			strcpy(u->cookies[t][1],value);
			debugf("[%d] Changed cookie #%d: '%s' = '%s'\n",u->index,t,name,value);
		}
	} else { // nová
		strcpy(u->cookies[t][0],name);
		strcpy(u->cookies[t][1],value);
		u->cookiecnt++;
		debugf("[%d] Added new cookie #%d: '%s' = '%s'\n",u->index,t,name,value);
	}
}

static void find_content_type(struct surl *u)
{
	static const char content_type[] = "\nContent-Type:";
	static const char charset[] = " charset=";
	char *p_ct = (char*) memmem(u->buf, u->headlen, content_type, sizeof(content_type) - 1);
	if(!p_ct)
		return;
	char *end;
	for (end = &p_ct[sizeof(content_type) - 1]; end < &u->buf[u->headlen] && *end != '\n' && *end != '\r'; ++end);
	char *p_charset = (char*) memmem(&p_ct[sizeof(content_type) - 1], end - &p_ct[sizeof(content_type) - 1], charset, sizeof(charset) - 1);
	if (!p_charset)
		return;
	char *p_charset_end = &p_charset[sizeof(charset) - 1];
	if (sizeof(u->charset) > end - p_charset_end) {
		*(char*)mempcpy(u->charset, p_charset_end, end - p_charset_end) = 0;
		debugf("charset='%s'\n", u->charset);
	}
}

/** pozná status a hlavičku http požadavku
 */
static void detecthead(struct surl *u)
{
	char *p;

	u->status=atoi(u->buf+9);
	u->buf[u->bufp]=0;
	
	p=strstr(u->buf,"\r\n\r\n");
	if(p) p+=4;
	
	if(p==NULL) {p=strstr(u->buf,"\n\n");if(p) p+=2;}
	
	if(p==NULL) {debugf("[%d] cannot find end of http header?\n",u->index);return;}
	
	u->headlen=p-u->buf;
	//debugf("[%d] headlen=%d\n",u->index,u->headlen);
	//debugf("'%s'\n",u->buf);
	
	p=(char*)memmem(u->buf,u->headlen,"Content-Length: ",16);
	if(p!=NULL) u->contentlen=atoi(p+16);
	
	p=(char*)memmem(u->buf,u->headlen,"\nLocation: ",11);
	if(p!=NULL) {strcpy_term(u->location,p+11);debugf("[%d] Location='%s'\n",u->index,u->location);}
	
	p=(char*)memmem(u->buf,u->headlen,"\nSet-Cookie: ",13);
	if(p!=NULL) {setcookie(u,p+13);}
	
	p=(char*)memmem(u->buf,u->headlen,"Transfer-Encoding: chunked",26);
	if(p!=NULL) {u->chunked=1;u->nextchunkedpos=u->headlen;debugf("[%d] Chunked!\n",u->index);}

	find_content_type(u);

	debugf("[%d] status=%d, headlen=%d, content-length=%d, charset=%s\n",u->index,u->status,u->headlen,u->contentlen, u->charset);
	
	if(u->chunked&&u->bufp>u->nextchunkedpos) eatchunked(u,1);
}

/** vypise vystup na standardni vystup
 */
static void output(struct surl *u)
{
	UC header[4096];

	if (!*u->charset) {
		unsigned charset_len = 0;
		char *charset = detect_charset_from_html(u->buf + u->headlen, u->bufp - u->headlen, &charset_len);
		if (charset && charset_len < sizeof(u->charset)) {
			*(char*)mempcpy(u->charset, charset, charset_len) = 0;
		}
	}
	if(settings.convert) {
		u->bufp=converthtml2text(u->buf+u->headlen, u->bufp-u->headlen)+u->headlen;
	}
	if (*u->charset && settings.convert_to_utf) {
		conv_charset(u);
	}

	sprintf(header,"URL: %s\n",u->rawurl);
	if(u->redirectedto[0]) sprintf(header+strlen(header),"Redirected-To: %s\n",u->redirectedto);
	sprintf(header+strlen(header),"Status: %d\nContent-length: %d\n",u->status,u->bufp-u->headlen);
	if (*u->charset)
		sprintf(header+strlen(header), "Content-type: text/html; charset=%s\n", u->charset);
	if (u->conv_errno) {
		char err_buf[128];
		char *err = strerror_r(u->conv_errno, err_buf, sizeof(err_buf));
		sprintf(header+strlen(header), "Conversion error: %s\n", err);
	}
	sprintf(header+strlen(header),"Index: %d\n\n",u->index);

	write(STDOUT_FILENO,header,strlen(header));
	if(settings.writehead) {
		debugf("[%d] outputting header %dB - %d %d %d %d\n",u->index,u->headlen,u->buf[u->headlen-4],u->buf[u->headlen-3],u->buf[u->headlen-2],u->buf[u->headlen-1]);
		write(STDOUT_FILENO,u->buf,u->headlen);
	}

	write(STDOUT_FILENO,u->buf+u->headlen,u->bufp-u->headlen);
	write(STDOUT_FILENO,"\n",1); // jinak se to vývojářům v php špatně parsuje

	if(u->chunked) debugf("[%d] bufp=%d nextchunkedpos=%d\n",u->index,u->bufp,u->nextchunkedpos);

	debugf("[%d] Outputed.\n",u->index);

	set_atomic_int(&u->state, S_DONE);
	debugf("[%d] Done.\n",u->index);
}

/** vyres presmerovani
 */
static void resolvelocation(struct surl *u)
{
	char lhost[256];
	char lpath[256]="/";

	debugf("[%d] Resolve location='%s'\n",u->index,u->location);

	if(!strncmp(u->location,"http://",7)) sscanf(u->location, "http://%[^/]/%s", lhost, lpath+1);
	else if(u->location[0]=='/') {strcpy(lhost,u->host);strcpy(lpath,u->location);} // relativni adresy (i kdyz by podle RFC nemely byt)
	else {debugf("[%d] Weird location format, assuming filename in root\n",u->index);strcpy(lhost,u->host);lpath[0]='/';strcpy(lpath+1,u->location);}
	
	debugf("[%d] Lhost='%s' Lpath='%s'\n",u->index,lhost,lpath);

	if(strcmp(u->host,lhost)) set_atomic_int(&u->state, S_JUSTBORN); // pokud je to jina domena, tak znovu resolvuj
	else set_atomic_int(&u->state, S_GOTIP);	// jinak se muzes pripojit na tu puvodni IP
	
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
static void finish(struct surl *u)
{
	if(u->headlen==0) detecthead(u);	// nespousteli jsme to predtim, tak pustme ted

	if(u->location[0]) resolvelocation(u);
	else output(u);
}

/** cti odpoved
 */
static void readreply(struct surl *u)
{
	UC buf[1024];
	int t,i;
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
		//debugf("debug: bufp=%d nextchunkedpos=%d",u->bufp,u->nextchunkedpos);
		while(u->bufp>u->nextchunkedpos) {
			i=eatchunked(u,0);	// pokud jsme presli az pres chunked hlavicku, tak ji sezer
			if(i==-1) break;
			}
		}
	
	if(t<=0||(u->contentlen!=-1&&u->bufp>=u->headlen+u->contentlen)) {close(u->sockfd);finish(u);}
	else set_atomic_int(&u->state, S_GETREPLY);
	//debugf("%s",buf);
	
}

//---------------------------------------------------------------------------------------------------------------------------------------------

/** provede systemovy select nad vsemi streamy, ktere jsou ve stavu GETREPLY (a pripadne je prehodi do READYREPLY)
 */
static void selectall(void)
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
		const int url_state = get_atomic_int(&url[t].state);
		if(url_state==S_GETREPLY) {
			//debugf("[%d] into read select...\n",t);
			FD_SET (url[t].sockfd, &set);
			}
		
		if(url_state==S_CONNECTING) {
			//debugf("[%d] into read write select...\n",t);
			FD_SET (url[t].sockfd, &writeset);
			}
	}
	
	t=select(FD_SETSIZE, &set, &writeset, NULL, &timeout);
	if(!t) return; // nic
	//debugf("select status: %d\n",t);
	
	for(t=0;url[t].rawurl[0];t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(FD_ISSET(url[t].sockfd,&set)&&url_state==S_GETREPLY) {
			//debugf("[%d] is ready for reading\n",t);
			set_atomic_int(&url[t].state, S_READYREPLY);
			}
		if(FD_ISSET(url[t].sockfd,&writeset)&&url_state==S_CONNECTING) {
			//debugf("[%d] is ready for writing\n",t);
			set_atomic_int(&url[t].state, S_CONNECTED);
			}
		
	}
}


/** provede jeden krok pro dane url
 */
static void goone(struct surl *u)
{
	int tim, state;
	//debugf("[%d]: %d\n",u->index,u->state);

	tim=gettimeint();

	state=get_atomic_int(&u->state);
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
	if(tim>200) debugf("[%d] State %d (->%d) took too long (%d ms)\n",u->index,state,get_atomic_int(&u->state),tim);
  
}

/** vrati 1 pokud je dobre ukoncit se predcasne
 */
static int exitprematurely(void)
{
	int tim;
	int t;
	int notdone=0, lastread=0;
	
	tim=gettimeint();
	if(tim<settings.timeout*1000-1000) return 0; // jeste je brzy
	
	for(t=0;url[t].rawurl[0];t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(url_state<S_DONE) notdone++;
		if(url[t].lastread>lastread) lastread=url[t].lastread;
	}
	
	debugf("[-] impatient: %d not done, last read at %d ms (now %d)\n",notdone,lastread,tim);
	
	if(t>=5&&notdone==1&&(tim-lastread)>400) {debugf("[-] Forcing premature end 1!\n");return 1;}
	if(t>=20&&notdone<=2&&(tim-lastread)>400) {debugf("[-] Forcing premature end 2!\n");return 1;}
	
	return 0;
}

/** vypise obsah vsech dosud neuzavrenych streamu
 */
static void outputpartial(void)
{
	int t;

	for(t=0;url[t].rawurl[0];t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(url_state==S_GETREPLY) output(&url[t]);
	
	}
}

/** hlavni smycka
 */
void go(void)
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
			state=get_atomic_int(&url[t].state);
			if(state<S_DONE) {goone(&url[t]);done=0;} // url[t].state can change inside goone
			if(state!=get_atomic_int(&url[t].state)) change=1;
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

