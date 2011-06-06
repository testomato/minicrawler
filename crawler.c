#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

/** provede jeden krok pro dane url
 */
void goone(struct surl *u)
{
	switch(u->state) {
  
  
  
  
  
	}
  
}

/** hlavni smycka
 */
void go()
{
	int t;

	while(1) {
		for(t=0;url[t].rawurl[0];t++) {
			printf("%d: %d\n",t,url[t].state);
			goone(&url[t]);
		}
		
	printf("\n"); 
	usleep(50);
	}
}