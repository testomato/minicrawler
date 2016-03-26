Minicrawler
===========

Minicrawler parses URLs, executes HTTP requests while handling cookies, network connection management and SSL/TLS protocols. By default it follows redirect locations and returns a full response, final URL, parsed cookied and more. It is designed to handle *many* request in parallel in a *single thread* by opening a socket for each connection. The whole Minicrawler suite is licensed under the [AGPL license](license.txt).

## URL Parser Library (libminicrawler-urlparser)

[WHATWG URL Standard](https://url.spec.whatwg.org/) compliant parsing library written in C. It is fast and has only one external dependency – libicu.
The library is licensed under the [AGPL license](license.txt).

### Usage

```c
#include <minicrawler/minicrawler-urlparser.h>

/**
 * First argument input URL, second (optional) base URL
 */
int main(int argc, char *argv[]) {
	if (argc < 2) {
		return 2;
	}

	char *input = argv[1];
	char *base = NULL;
	if (argc > 2) {
		base = argv[2];
	}
	
	mcrawler_parser_url url, *base_url = NULL;

	if (base) {
		base_url = (mcrawler_parser_url *)malloc(sizeof(mcrawler_parser_url));
		if (mcrawler_parser_parse(base_url, base, NULL) == MCRAWLER_PARSER_FAILURE) {
			printf("Invalid base URL\n");
			return 1;
		}
	}

	if (mcrawler_parser_parse(&url, input, base_url) == MCRAWLER_PARSER_FAILURE) {
		printf("Invalid URL\n");
		return 1;
	}

	printf("Result: %s\n", mcrawler_parser_serialize(&url, 0));
	return 0;
}
```

More in [test/urlparser.c](test/urlparser.c).


## Minicrawler Library (libminicrawler) Usage

```c
#include <stdio.h>
#include <minicrawler/minicrawler.h>

static void onfinish(mcrawler_url *url, void *arg) {
    printf("%d: Status: %d\n", url->index, url->status);
}

void main() {
    mcrawler_url url[2];
    mcrawler_url *urls[] = {&url[0], &url[1], NULL};
    mcrawler_settings settings;
    memset(&url[0], 0, sizeof(mcrawler_url));
    memset(&url[1], 0, sizeof(mcrawler_url));
    mcrawler_init_url(&url[0], "http://example.com");
    url[0].index = 0;
    mcrawler_init_url(&url[1], "http://example.com");
    url[1].index = 1;
    mcrawler_init_settings(&settings);
    mcrawler_go(urls, &settings, &onfinish, NULL);
}
```

## Minicrawler Binary Usage

`minicrawler [options] [urloptions] url [[url2options] url2]...`

### Options

```
   options:
         -6         resolve host to IPv6 address only
         -8         convert from page encoding to UTF-8
         -A STRING  custom user agent (max 255 bytes)
         -b STRING  cookies in the netscape/mozilla file format (max 20 cookies)
         -c         convert content to text format (with UTF-8 encoding)
         -DMILIS    set delay time in miliseconds when downloading more pages from the same IP (default is 100 ms)
         -g         accept gzip encoding
         -h         enable output of HTTP headers
         -i         enable impatient mode (minicrawler exits few seconds earlier if it doesn't make enough progress)
         -pSTRING   password for HTTP authentication (basic or digest, max 31 bytes)
         -S         disable SSL/TLS support
         -tSECONDS  set timeout (default is 5 seconds)
         -u STRING  username for HTTP authentication (basic or digest, max 31 bytes)
         -v         verbose output (to stderr)
         -w STRING  write this custom header to all requests (max 4095 bytes)

   urloptions:
         -C STRING  parameter which replaces '%' in the custom header
         -P STRING  HTTP POST parameters
         -X STRING  custom request HTTP method, no validation performed (max 15 bytes)
```

### Output header

Minicrawler prepends its own header into the output with the following meaning

 * **URL**: Requested URL
 * **Redirected-To**: Final absolute URL
 * **Redirect-info**: Info about each redirect
 * **Status**: HTTP Status of final response (negative in case of error)
   * `-10` Invalid input
   * `-9`, `-8` DNS error
   * `-7`, `-6` Connection error
   * `-5` SSL/TLS error
   * `-4`, `-3` Error during sending a HTTP request
   * `-2` Error during receiving a HTTP response
   * `-1` Decoding or converting error
 * **Content-length**: Length of the downloaded content in bytes
 * **Timeout**: Reason of timeout in case of timeout
 * **Error-msg**: Error message in case of error (negative Status)
 * **Content-type**: Correct content type of outputed content
 * **WWW-Authenticate**: WWW-Authenticate header
 * **Cookies**: Number of cookies followed by that number of lines of parsed cookies in [Netscape/Mozilla file format](http://www.cookiecentral.com/faq/#3.5)
 * **Downtime**: Length of an interval between time of the first connection and time of the last received byte; time of the start of the first connection
 * **Timing**: Timing of request (DNS lookup, Initial connection, SSL, Request, Waiting, Content download, Total)
 * **Index**: Index of URL from command line

## Dependencies

 * Asynchronous hostname resolving - [c-ares](http://c-ares.haxx.se/)
 * Gzip decoding - [zlib](http://zlib.net/)
 * TLS/SSL - [OpenSSL](https://www.openssl.org/)
 * Unicode processing - [ICU](http://site.icu-project.org/)

## Build

Tested platforms: Debian Linux, Red Hat Linux, OS X.

Install following dependencies (including header files, i.e. dev packages):
 * c-ares
 * zlib1g
 * icu
 * OpenSSL (optional)

On Linux with apt-get run `apt-get install libc-ares-dev zlib1g-dev libicu-dev libssl-dev`

On OS X with homebrew run `brew install c-ares zlib icu openssl`

Then run
```bash
./autogen.sh
./configure [--without-ssl]
make
[make check]
sudo make install
```
