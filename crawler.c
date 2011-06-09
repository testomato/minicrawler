#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <udns.h>
#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

//struct adns__state *my_adns_state;

/** spusti preklad pres adns
 */
void launchdns(struct surl *u)
{
	struct dns_rr_a4 *answer;
	struct in_addr *ip;
	int ipint;
	char *ipchar;

	printf("chci resolvovat %s\n",u->host);
	
//	adns_submit(my_adns_state,"",adns_r_a,0,&(u->my_adns_context),&(u->my_adns_query));
	dns_init(u->ctx,1);

/*      struct dns_query *                                                                                                                        
       dns_submit_a4(ctx, const char *name, int flags,                                                                                           
          dns_query_a4_fn *cbck, data);                                                                                                          
       struct dns_rr_a4 *                                                                                                                        
       dns_resolve_a4(ctx, const char *name, int flags);*/

	answer=dns_resolve_a4(u->ctx,u->host,0);
	printf("status=%d",dns_status(u->ctx));
	if(answer==NULL) {printf("NULL");exit(-1);}
	printf("hu - %d",answer);
//	ip=&(answer->dnsa4_addr[0]);
	ipint=(int)(answer->dnsa4_addr[0].s_addr);
	ipchar=(char*)ipchar;
	printf("ha - %d\n",answer->dnsa4_addr[0]);
	printf("hip - %d.%d.%d.%d\n",ipchar[0],ipchar[1],ipchar[2],ipchar[3]);

	u->state=S_INADNS;
}

/** uz je adns hotove?
 */
void checkdns(struct surl *u)
{
	int t;

//	struct adns_answer **my_adns_answer;

	printf("Uz jsi?\n");
/*int adns_check(adns_state ads,
       adns_query *query_io,
       adns_answer **answer_r,
       void **context_r);*/
       
//       t=adns_check(my_adns_state,&u->my_adns_query,my_adns_answer,u->my_adns_context);
       
//       printf("%d status is %d\n",t,(*my_adns_answer)->adns_status);
       
//       u->state=S_GOTIP;
       
       
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

/** pusti adns
 */
void initadns()
{
//	struct adns_initflags myflags;

//	adns_init(&my_adns_state,0,0);
}

/** hlavni smycka
 */
void go()
{
	int t;
	
	initadns();
	
	while(1) {
		for(t=0;url[t].rawurl[0];t++) {
			//printf("%d: %d\n",t,url[t].state);
			goone(&url[t]);
		}
		
	//printf("\n"); 
	usleep(500000);
	}
}