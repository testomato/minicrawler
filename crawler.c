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
#include <assert.h>

#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

static void set_atomic_int(int *ptr, const int val)
{
	*(volatile int*)ptr = val;
	asm volatile ("" : : : "memory");  // memory barrier
}

static int get_atomic_int(const int* const ptr)
{
	return *(volatile const int* const)ptr;
}

/** callback funkce, kterou zavola ares
 */
static void dnscallback(void *arg, int status, int timeouts, struct hostent *hostent)
{
	unsigned char *ip;
	struct surl *u;
	
	u=(struct surl *)arg;
	if(status!=0) {debugf("[%d] error: dnscallback with non zero status! - status=%d\n",u->index,status);set_atomic_int(&u->state, SURL_S_ERROR);return;}
	
	ip=(unsigned char*)(hostent->h_addr);
	u->prev_ip = u->ip;
	u->ip=*(int *)ip;
	
	debugf("[%d] Resolving %s ended => %d.%d.%d.%d\n", u->index, u->host, ip[0], ip[1], ip[2], ip[3]);
	debugf("[%d] raw url => %s\n", u->index, u->rawurl);

	set_atomic_int(&u->state, SURL_S_GOTIP);
}


static int check_proto(struct surl *u)
{
	if (0 == strcmp(u->proto, "https")) {
		return 443;
	}
	if (0 == strcmp(u->proto, "http")) {
		return 80;
	}

	debugf("Unsupported protocol: [%s]\n", u->proto);
	u->status = 999;
	sprintf(u->error_msg, "Protocol [%s] not supported", u->proto);
	set_atomic_int(&u->state, SURL_S_INTERNAL_ERROR);

	return -1;
}

/** spusti preklad pres ares
 */
static void launchdns(struct surl *u)
{
	if (check_proto(u) == -1) {
		return;
	}

	int t;

	debugf("[%d] Resolving %s starts\n",u->index,u->host);
	t = ares_init(&(u->aresch));
	if(t) {debugf("ares_init failed\n");exit(-1);}

	set_atomic_int(&u->state, SURL_S_INDNS);
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

	t = ares_fds(u->aresch, &readfds, &writefds);
	if(!t) {
		return;
	}

	ares_process(u->aresch, &readfds, &writefds); // pri uspechu zavola callback sama
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
	memcpy(&(addr.sin_addr), &(u->ip), 4);

	u->sockfd=socket(AF_INET, SOCK_STREAM, 0);
	flags=fcntl(u->sockfd, F_GETFL,0);              // Get socket flags
	fcntl(u->sockfd, F_SETFL, flags | O_NONBLOCK);   // Add non-blocking flag	
	
	t = connect(u->sockfd,(struct sockaddr *)&addr,sizeof(addr));
	if(t) {
		if(errno == EINPROGRESS) {
			set_atomic_int(&u->state, SURL_S_CONNECTING); // 115 je v pohode (operation in progress)
		}
		else {
			debugf("%d: connect failed (%d, %s)\n", u->index, errno, strerror(errno));
			set_atomic_int(&u->state, SURL_S_ERROR);}
		}
	else {
		set_atomic_int(&u->state, SURL_S_CONNECTED);
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
	char agent[256];
	char cookiestring[4096];
	char customheader[4096];
//	char *p;

        if (*settings.customagent) {
            strcpy(agent, settings.customagent);
        } else {
            strcpy(agent, "minicrawler/1");
        }

	// vytvoří si to řetězec cookies a volitelných parametrů
	cookiestring[0] = 0;
	for(int t = 0; t < u->cookiecnt; t++) {
		if(0 == t) {
			sprintf(cookiestring, "Cookie: %s=%s", u->cookies[t].name, u->cookies[t].value);
		}
		else {
			sprintf(cookiestring+strlen(cookiestring), "; %s=%s", u->cookies[t].name, u->cookies[t].value);
		}
	}
	if (strlen(cookiestring)) {
		sprintf(cookiestring + strlen(cookiestring), "\r\n");
	}
	if(settings.customheader) {
		sprintf(customheader,"%s\r\n",settings.customheader);
		if(u->customparam[0]) {
			char *p = str_replace(customheader, "%", u->customparam);
			strcpy(customheader,p);
		}
		debugf("[%d] Customheader: %s", u->index, customheader);
		strcpy(cookiestring+strlen(cookiestring), customheader);
	} 
	if(u->cookiecnt) {
		sprintf(cookiestring+strlen(cookiestring), "\r\n");
	}
	
	if(!u->post[0]) {// GET
		sprintf(u->request, "GET %s HTTP/1.1\r\nUser-Agent: %s\r\nHost: %s\r\n%s\r\n", u->path, agent, u->host, cookiestring);
	} else { // POST
		sprintf(u->request, "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s\r\n%s\r\n", u->path, u->host, agent, (int)strlen(u->post), u->post, cookiestring);
	}

	const size_t t = write_all(u->sockfd, u->request, strlen(u->request));
	if(t < strlen(u->request)) {
		debugf("[%d] Error - written %d bytes, wanted %d bytes\n",u->index,(int)t,(int)strlen(u->request));
	}
	else {
		debugf("[%d] Written %d bytes\n",u->index,(int)t);
	}

	set_atomic_int(&u->state, SURL_S_GETREPLY);
}

/** strcpy, ktere se ukonci i koncem radku
 */
static void strcpy_term(char *to, char *from)
{
	for(;*from&&*from!='\r'&&*from!='\n';) *to++=*from++;
	*to=0;
}

/** sezere to radku tam, kde ceka informaci o delce chunku
 *  jedinou vyjimkou je, kdyz tam najde 0, tehdy posune i contentlen, aby dal vedet, ze jsme na konci
 *  @return 0 je ok, -1 pokud tam neni velikost chunku zapsana cela
 */
static int eatchunked(struct surl *u,int first)
{
	int t,i;
	unsigned char hex[10];
	int size;
	int movestart;

	// čte velikost chunku	
	for(t=u->nextchunkedpos,i=0;u->buf[t]!='\r'&&t<u->bufp;t++) {
		if(i<9) hex[i++]=u->buf[t];
		}
	if(t>=u->bufp) {debugf("[%d] Incorrectly ended chunksize!",u->index);return -1;}
	if(t < u->bufp && u->buf[t]=='\r') t++;
	if(t < u->bufp && u->buf[t]=='\n') t++;

	if(i==0) debugf("[%d] Warning: empty string for chunksize\n",u->index);		
	hex[i]=0;
	size=strtol(hex,NULL,16);
		
	debugf("[%d] Chunksize at %d (now %d): '%s' (=%d)\n",u->index,u->nextchunkedpos,u->bufp,hex,size);

	movestart=u->nextchunkedpos;
	if(!first&&movestart!=u->headlen) {/*debugf("eating %d %d at %d\n",u->buf[movestart-2],u->buf[movestart-1],movestart);*/movestart-=2;} // ten headlen je kvuli adventura.cz - moooc divne
	assert(t <= u->bufp);
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
        const int name_len = strchrnul(str, '=') - str; //strcpy_endchar(NULL, str, '=');
        const int value_len = str[name_len] ? strchrnul(&str[name_len + 1], ';') - &str[name_len + 1] : 0; //strcpy_endchar(NULL, str + name_len + 1, ';');
	char name[name_len + 1];
	char value[value_len + 1];
	*(char*)mempcpy(name, str, name_len) = 0;
	*(char*)mempcpy(value, &str[name_len + 1], value_len) = 0;

	int t;
	for(t=0;t<u->cookiecnt;t++) if(!strcmp(name,u->cookies[t].name)) break;

	if(t<u->cookiecnt) { // už tam byla
		if(!strcmp(u->cookies[t].value,value)) {debugf("[%d] Received same cookie #%d: '%s' = '%s'\n",u->index,t,name,value);}
		else {
			strcpy(u->cookies[t].value,value);
			debugf("[%d] Changed cookie #%d: '%s' = '%s'\n",u->index,t,name,value);
		}
	} else if (u->cookiecnt < sizeof(u->cookies)/sizeof(*u->cookies)) { // nová
/*                assert(u->cookiecnt < sizeof(u->cookies)/sizeof(*u->cookies));
                assert(name_len < sizeof(u->cookies[t][0]) - 1);
                assert(value_len < sizeof(u->cookies[t][1]) - 1);*/
		u->cookies[t].name = malloc(name_len + 1);
		u->cookies[t].value = malloc(value_len + 1);
		*(char*)mempcpy(u->cookies[t].name, name, name_len) = 0;
		*(char*)mempcpy(u->cookies[t].value, value, value_len) = 0;
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
	debugf("[%d] Head, Content-Length: %d\n", u->index, u->contentlen);
	
	p=(char*)memmem(u->buf,u->headlen,"\nLocation: ",11)?:(char*)memmem(u->buf,u->headlen,"\nlocation: ",11); // FIXME: handle http headers case-insensitive!!
	if(p!=NULL) {strcpy_term(u->location,p+11);debugf("[%d] Location='%s'\n",u->index,u->location);}
	
	p=(char*)memmem(u->buf,u->headlen,"\nSet-Cookie: ",13);
	if(p!=NULL) {setcookie(u,p+13);}
	
	p=(char*)memmem(u->buf,u->headlen,"Transfer-Encoding: chunked", 26)?:(char*)memmem(u->buf,u->headlen,"transfer-encoding: chunked", 26);
	if(p!=NULL) {u->chunked=1;u->nextchunkedpos=u->headlen;debugf("[%d] Chunked!\n",u->index);}

	find_content_type(u);

	debugf("[%d] status=%d, headlen=%d, content-length=%d, charset=%s\n",u->index,u->status,u->headlen,u->contentlen, u->charset);
	
	if(u->chunked&&u->bufp>u->nextchunkedpos) eatchunked(u,1);
}

/** vypise vystup na standardni vystup
 */
static void output(struct surl *u)
{
	unsigned char header[4096];

	if (!*u->charset) {
		unsigned charset_len = 0;
		char *charset = detect_charset_from_html(u->buf + u->headlen, u->bufp - u->headlen, &charset_len);
		if (charset && charset_len < sizeof(u->charset)) {
			*(char*)mempcpy(u->charset, charset, charset_len) = 0;
		}
	}
	if (!*u->charset) {
		strcpy(u->charset, "unknown");
	}
	if (*u->charset && settings.convert_to_utf) {
		conv_charset(u);
	}
	if(settings.convert) {
		u->bufp=converthtml2text(u->buf+u->headlen, u->bufp-u->headlen)+u->headlen;
	}
	sprintf(header,"URL: %s\n",u->rawurl);
	if(u->redirectedto[0]) sprintf(header+strlen(header),"Redirected-To: %s\n",u->redirectedto);
	for (struct redirect_info *rinfo = u->redirect_info; rinfo; rinfo = rinfo->next) {
		sprintf(header+strlen(header), "Redirect-info: %s %d\n", rinfo->url, rinfo->status);
	}
	sprintf(header+strlen(header),"Status: %d\nContent-length: %d\n",u->status,u->bufp-u->headlen);
	if (*u->error_msg) {
		sprintf(header+strlen(header), "Error-msg: %s\n", u->error_msg);
	}
	if (*u->charset) {
		sprintf(header+strlen(header), "Content-type: text/html; charset=%s\n", u->charset);
	}
	if (u->conv_errno) {
		char err_buf[128];
#		ifdef __APPLE__
		char *err = !strerror_r(u->conv_errno, err_buf, sizeof(err_buf)) ? err_buf : "Unknown error";
#		else
		char *err = strerror_r(u->conv_errno, err_buf, sizeof(err_buf));
#		endif
		sprintf(header+strlen(header), "Conversion error: %s\n", err);
	}
	sprintf(header+strlen(header),"Downtime: %dms; %dms (ip=0x%x; %u)\n",u->lastread - u->downstart, u->downstart, u->ip, get_time_slot(u->ip));
	sprintf(header+strlen(header),"Index: %d\n\n",u->index);

	write_all(STDOUT_FILENO, header, strlen(header));
	if(settings.writehead) {
		debugf("[%d] outputting header %dB - %d %d %d %d\n",u->index,u->headlen,u->buf[u->headlen-4],u->buf[u->headlen-3],u->buf[u->headlen-2],u->buf[u->headlen-1]);
		write_all(STDOUT_FILENO, u->buf, u->headlen);
		if (0 == u->headlen) {
			write_all(STDOUT_FILENO, "\n", 1); // PHP library expects one empty line at the end of headers, in normal circumstances it is contained
						      // within u->buf[0 .. u->headlen] .
		}
	}

	write_all(STDOUT_FILENO, u->buf+u->headlen, u->bufp-u->headlen);
	write_all(STDOUT_FILENO, "\n", 1); // jinak se to vývojářům v php špatně parsuje

	if(u->chunked) debugf("[%d] bufp=%d nextchunkedpos=%d\n",u->index,u->bufp,u->nextchunkedpos);

	debugf("[%d] Outputed.\n",u->index);

	set_atomic_int(&u->state, SURL_S_DONE);
	debugf("[%d] Done.\n",u->index);
}


static int resolvelocation_url_with_proto(struct surl *u, char *lproto, char *lhost, char *lpath, const int i_lproto_size, const int i_lhost_size, const int i_lpath_size)
{
	assert(0 == strcmp(lpath, "/"));

	const char fmt[] = "%%%d[^:]://%%%d[^/]/%%%ds";
	char buf[256];
	sprintf(buf, fmt, i_lproto_size, i_lhost_size, i_lpath_size - 1);

	switch (sscanf(u->location, buf, lproto, lhost, &lpath[1])) {
		case 2:
		case 3:
			return 1;
		default:
			return 0;
	}
}


static int resolvelocation_url_no_proto(struct surl *u, char *lproto, char *lhost, char *lpath, const int i_lproto_size, const int i_lhost_size, const int i_lpath_size)
{
	assert(0 == strcmp(lpath, "/"));

	const char fmt[] = "%%%d[^/]/%%%ds";
	char buf[256];
	sprintf(buf, fmt, i_lhost_size, i_lpath_size - 1);

	switch ( sscanf(u->location, buf, lhost, &lpath[1])) {
		case 1:
		case 2:
			strcpy(lproto, u->proto);
			return 1;
		default:
			return 0;
	}
}



/** vyres presmerovani
 */
static void resolvelocation(struct surl *u)
{
	char lproto[ sizeof(u->proto) ] = "http";
	char lhost[ sizeof(u->host) ];
	char lpath[ sizeof(u->path) ] = "/";

	debugf("[%d] Resolve location='%s'\n",u->index, u->location);

	// FIXME: simpleparseurl(...) should be used here
	const char fmt[] = "%%%d[^:]://%%%d[^/]/%%%ds";
	char buf[256];
	sprintf(buf, fmt, I_LENGTHOF(lproto), I_LENGTHOF(lhost), I_LENGTHOF(lpath) - 1);

//	if(2 <= sscanf(u->location, buf, lproto, lhost, lpath + 1)) {
	if (resolvelocation_url_with_proto(u, lproto, lhost, lpath, I_LENGTHOF(lproto), I_LENGTHOF(lhost), I_LENGTHOF(lpath))) {
//	} else if (resolvelocation_url_no_proto(u, lproto, lhost, lpath, I_LENGTHOF(lproto), I_LENGTHOF(lhost), I_LENGTHOF(lpath))) {
 	} else if(u->location[0] == '/') {
		strcpy(lproto, u->proto);
		strcpy(lhost, u->host);
		strcpy(lpath, u->location);
		// relativni adresy (i kdyz by podle RFC nemely byt)
	} else {
		debugf("[%d] Weird location format, assuming filename in root\n", u->index);
		strcpy(lproto, u->proto);
		strcpy(lhost, u->host);
		strcpy(lpath, "/");
		strcpy(lpath+1, u->location);
	}
	
	debugf("[%d] Lproto = '%s' Lhost='%s' Lpath='%s'\n", u->index, lproto, lhost, lpath);

       	if (strcmp(u->host,lhost)) {
		set_atomic_int(&u->state, SURL_S_JUSTBORN); // pokud je to jina domena, tak znovu resolvuj
	}
	else {
		set_atomic_int(&u->state, SURL_S_GOTIP);	// jinak se muzes pripojit na tu puvodni IP
	}

	struct redirect_info *rinfo = malloc(sizeof(*rinfo));
	bzero(rinfo, sizeof(*rinfo));
	strcpy(rinfo->url, u->location);
	rinfo->status = u->status;
	rinfo->next = u->redirect_info;
	u->redirect_info = rinfo;

	strcpy(u->proto, lproto);
	strcpy(u->path, lpath);		// bez tam
	strcpy(u->host, lhost);		// bez tam
	strcpy(u->redirectedto, u->location);
	u->location[0] = 0;
	u->post[0] = 0;
	u->headlen = 0;
	u->contentlen = -1;
	u->bufp = 0;

	if (check_proto(u) == -1) {
		return;
	}
}

/** uz mame cely vstup - bud ho vypis nebo vyres presmerovani
 */
static void finish(struct surl *u)
{
	if(u->headlen==0) {
		detecthead(u);	// nespousteli jsme to predtim, tak pustme ted
	}

	if(u->location[0]) {
		resolvelocation(u);
	} else {
		output(u);
	}
}

/** cti odpoved
 */
static void readreply(struct surl *u)
{
	unsigned char buf[1024];
	int t,i;
	int left;

	left=BUFSIZE-u->bufp;
	if(left<=0) {
		return;
	}
	if(left>4096) {
		left=4096;
	}

	t=read(u->sockfd,u->buf+u->bufp,left);

	if(t>0) {
		u->bufp+=t;
		u->lastread=get_time_int();
		if(u->headlen==0) detecthead(u);		// pokud jsme to jeste nedelali, tak precti hlavicku
	}
	
	
	debugf("[%d] Read %d bytes; chunked=%d\n", u->index, t, !!u->chunked);
	//buf[60]=0; // wtf?
	
	if(t>0 && u->chunked) {
		//debugf("debug: bufp=%d nextchunkedpos=%d",u->bufp,u->nextchunkedpos);
		while(u->bufp > u->nextchunkedpos) {
			i = eatchunked(u,0);	// pokud jsme presli az pres chunked hlavicku, tak ji sezer
			if(i == -1) break;
		}
	}
	
	if(t <= 0 || (u->contentlen != -1 && u->bufp >= u->headlen + u->contentlen)) {
		close(u->sockfd);
		finish(u);
	} else {
		set_atomic_int(&u->state, SURL_S_GETREPLY);
	}
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
	
	for(t=0; url[t].rawurl[0]; t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(url_state == SURL_S_GETREPLY) {
//			debugf("Adding %d into read select...\n", url[t].sockfd);
			FD_SET (url[t].sockfd, &set);
		}
		
		if(url_state == SURL_S_CONNECTING) {
//			debugf("Adding %d into write select...\n", url[t].sockfd);
			FD_SET (url[t].sockfd, &writeset);
		}
	}
	
	t = select(FD_SETSIZE, &set, &writeset, NULL, &timeout);
	if(!t) {
		return; // nic
	}
	for(t=0;url[t].rawurl[0];t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(FD_ISSET(url[t].sockfd, &set) && url_state == SURL_S_GETREPLY) {
			set_atomic_int(&url[t].state, SURL_S_READYREPLY);
		}
		if(FD_ISSET(url[t].sockfd, &writeset) && url_state == SURL_S_CONNECTING) {
			set_atomic_int(&url[t].state, SURL_S_CONNECTED);
		}
		
	}
}


/** provede jeden krok pro dane url
 */
static void goone(struct surl *u)
{
	const int tim=get_time_int();
	const int state=get_atomic_int(&u->state);

	switch(state) {  
	case SURL_S_JUSTBORN:
		launchdns(u);
		break;
  
	case SURL_S_INDNS:
		checkdns(u);
		break;

	case SURL_S_GOTIP:
		if ( (u->downstart = test_free_channel(u->ip, settings.delay, u->ip == u->prev_ip)) ) {
			opensocket(u);
		}
		break;
  
	case SURL_S_CONNECTING:
		// nic, z tohohle stavu mne dostane select
		break;
		
	case SURL_S_CONNECTED:
		sendhttpget(u);
		break;
  
	case SURL_S_GETREPLY:
		// nic, z tohohle stavu mne dostane select
		break;

	case SURL_S_READYREPLY:
		readreply(u);
		break;

	case SURL_S_INTERNAL_ERROR:
		output(u);
		break;
	}

	if (settings.debug) {	
		const int duration = get_time_int() - tim;
		if(duration > 200) {
			debugf("[%d] State %d (->%d) took too long (%d ms)\n", u->index, state, get_atomic_int(&u->state), duration);
		}
	}
}

/** vrati 1 pokud je dobre ukoncit se predcasne
 */
static int exitprematurely(void)
{
	int tim;
	int t;
	int notdone=0, lastread=0;
	
	tim=get_time_int();
	if(tim<settings.timeout*1000-1000) {
		return 0; // jeste je brzy
	}
	
	for(t=0;url[t].rawurl[0];t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(url_state<SURL_S_DONE) {
			notdone++;
		}
		if(url[t].lastread>lastread) {
			lastread=url[t].lastread;
		}
	}
	
	debugf("[-] impatient: %d not done, last read at %d ms (now %d)\n",notdone,lastread,tim);
	
	if(t>=5 && notdone==1 && (tim-lastread) > 400) {
		debugf("[-] Forcing premature end 1!\n");
		return 1;
	}
	if(t>=20 && notdone<=2 && (tim-lastread) > 400) {
		debugf("[-] Forcing premature end 2!\n");
		return 1;
	}
	
	return 0;
}

/** vypise obsah vsech dosud neuzavrenych streamu
 */
static void outputpartial(void)
{
	int t;

	for(t=0; url[t].rawurl[0]; t++) {
		const int url_state = get_atomic_int(&url[t].state);
		if(url_state==SURL_S_GETREPLY) {
			output(&url[t]);
		}
	}
}

/**
 * hlavni smycka
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
			if(state < SURL_S_DONE) {
				goone(&url[t]);
				done=0;
			}
			// url[t].state can change inside goone
			if(state != get_atomic_int(&url[t].state)) {
				change = 1;
			}
		}

		t=get_time_int();
		if(t>settings.timeout*1000) {
			debugf("Timeout (%d ms elapsed). The end.\n",t);
			if(settings.partial) outputpartial();
			break;
		}
		if(!change && !done) {
			if(settings.impatient) {
				done=exitprematurely();
			}
			usleep(20000);
		}
	} while(!done);
	
	if(done) debugf("All successful. Took %d ms.\n",get_time_int());
}

