#define _GNU_SOURCE // memmem(.), strchrnul needs this :-(
#include <string.h>

#include "h/minicrawler.h"
#include "h/version.h"
#include "h/proto.h"

/** vypise napovedu
 */
void printusage()
{
	printf("\nminicrawler, version %s\n\nUsage:   minicrawler [options] [urloptions] url [[url2options] url2]...\n\n"
	         "Where\n"
	         "   options:\n"
	         "         -d         enable debug messages (to stderr)\n"
	         "         -tSECONDS  set timeout (default is 5 seconds)\n"
	         "         -h         enable output of HTTP headers\n"
	         "         -i         enable impatient mode (minicrawler exits few seconds earlier if it doesn't make enough progress)\n"
	         "         -p         output also URLs that timed out and a reason of it\n"
	         "         -A STRING  custom user agent (max 255 bytes)\n"
	         "         -w STRING  write this custom header to all requests (max 4095 bytes)\n"
	         "         -c         convert content to text format (with UTF-8 encoding)\n"
	         "         -8         convert from page encoding to UTF-8\n"
	         "         -DMILIS    set delay time in miliseconds when downloading more pages from the same IP (default is 100 ms)\n"
	         "         -S         disable SSL/TLS support\n"
	         "         -g         accept gzip encoding\n"
	         "         -6         resolve host to IPv6 address only\n"
	         "         -b STRING  cookies in the netscape/mozilla file format (max 20 cookies)\n"
	         "\n   urloptions:\n"
	         "         -C STRING  parameter which replaces '%%' in the custom header\n"
	         "         -P STRING  HTTP POST parameters\n"
	         "         -X STRING  custom request HTTP method, no validation performed (max 15 bytes)\n"
	         "\n", VERSION);
}

/** nacte url z prikazove radky do struktur
 */
struct surl *initurls(int argc, char *argv[])
{
	struct surl *url, *curl, *purl;
	char *post = NULL, *p, *q;
	long options = 0;
	char customheader[4096];
	char customagent[256];
	struct cookie cookies[COOKIESTORAGESIZE];
	int ccnt = 0, i = 0;

	url = (struct surl *)malloc(sizeof(struct surl));
	memset(url, 0, sizeof(struct surl));
	curl = url;

	for (int t = 1; t < argc; ++t) {

		// options
		if(!strcmp(argv[t], "-d")) {settings.debug=1;continue;}
		if(!strcmp(argv[t], "-S")) {options |= 1<<SURL_OPT_NONSSL; continue;}
		if(!strcmp(argv[t], "-h")) {settings.writehead=1;continue;}
		if(!strcmp(argv[t], "-i")) {settings.impatient=1;continue;}
		if(!strcmp(argv[t], "-p")) {settings.partial=1;continue;}
		if(!strcmp(argv[t], "-c")) {options |= 1<<SURL_OPT_CONVERT_TO_TEXT | 1<<SURL_OPT_CONVERT_TO_UTF8; continue;}
		if(!strcmp(argv[t], "-8")) {options |= 1<<SURL_OPT_CONVERT_TO_UTF8; continue;}
		if(!strcmp(argv[t], "-g")) {options |= 1<<SURL_OPT_GZIP; continue;}
		if(!strncmp(argv[t], "-t", 2)) {settings.timeout=atoi(argv[t]+2);continue;}
		if(!strncmp(argv[t], "-D", 2)) {settings.delay=atoi(argv[t]+2);debugf("Delay time: %d\n",settings.delay);continue;}
		if(!strncmp(argv[t], "-w", 2)) {safe_cpy(customheader, argv[t+1], I_SIZEOF(customheader)); t++; continue;}
		if(!strncmp(argv[t], "-A", 2)) {str_replace(customagent, argv[t+1], "%version%", VERSION); t++; continue;}
		if(!strncmp(argv[t], "-b", 2)) {
			p = argv[t+1];
			while (p[0] != '\0' && ccnt < COOKIESTORAGESIZE) {
				q = strchrnul(p, '\n');
				cookies[ccnt].name = malloc(q-p);
				cookies[ccnt].value = malloc(q-p);
				cookies[ccnt].domain = malloc(q-p);
				cookies[ccnt].path = malloc(q-p);
				sscanf(p, "%s\t%d\t%s\t%d\t%d\t%s\t%s", cookies[ccnt].domain, &cookies[ccnt].host_only, cookies[ccnt].path, &cookies[ccnt].secure, &cookies[ccnt].expire, cookies[ccnt].name, cookies[ccnt].value);
				p = (q[0] == '\n') ? q + 1 : q;
				ccnt++;
			}
			t++;
			continue;
		}
		if(!strcmp(argv[t], "-6")) {options |= 1<<SURL_OPT_IPV6; continue;}

		// urloptions
		if(!strcmp(argv[t], "-P")) {
			post = malloc(strlen(argv[t+1]) + 1);
			memcpy(post, argv[t+1], strlen(argv[t+1]) + 1);
			t++;
			debugf("[%d] POST: %s\n",i,post);
			continue;
		}
		if(!strncmp(argv[t], "-C", 2)) {
			if (customheader[0]) {
				str_replace(curl->customheader, customheader, "%", argv[t+1]);
			}
			t++;
			continue;
		}
		if(!strcmp(argv[t], "-X")) {safe_cpy(curl->method, argv[t+1], I_SIZEOF(curl->method)); t++; continue;}

		strcpy(curl->customagent, customagent);
		if (!curl->customheader[0]) {
			strcpy(curl->customheader, customheader);
		}
		curl->options = options;
		init_url(curl, argv[t], i++, post, cookies, ccnt);
		post = NULL;
		purl = curl;
		curl = (struct surl *)malloc(sizeof(struct surl));
		purl->next = curl;
	}

	free(curl);
	purl->next = NULL;

	for (int t = 0; t < ccnt; t++) {
		free(cookies[t].name);
		free(cookies[t].value);
		free(cookies[t].domain);
		free(cookies[t].path);
	}

	return url;
}

