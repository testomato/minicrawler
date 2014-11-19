minicrawler
===========

Minicrawler executes HTTP requests while handling cookies, network connection management and SSL/TLS protocols. By default it follows redirect locations and returns a full response, final URL, parsed cookied and more. It is designed to handle *many* request in parallel in a *single thread* by opening a socket for each connection. Minicrawler is licensed under the [AGPL license](license.txt).

## Usage

```
#include <minicrawler/minicrawler.h>

static void onfinish(mcrawler_url *url, void *arg) {
	printf("%d: Status: %d\n", url->index, url->status);
}

void main() {
	mcrawler_url url;
	mcrawler_url *urls[] = {&url, NULL};
	mcrawler_settings settings;
	memset(&url, 0, sizeof(mcrawler_url));
	mcrawler_init_url(&url, "http://example.com");
	mcrawler_init_settings(&settings);
	mcrawler_go(urls, &settings, &onfinish, NULL);
}
```

## Command line API

### Options

```
Usage:   minicrawler [options] [urloptions] url [[url2options] url2]...

Where
   options:
         -d         enable debug messages (to stderr)
         -tSECONDS  set timeout (default is 5 seconds)
         -h         enable output of HTTP headers
         -i         enable impatient mode (minicrawler exits few seconds earlier if it doesn't make enough progress)
         -p         output also URLs that timed out and a reason of it
         -A STRING  custom user agent (max 256 bytes)
         -w STRING  write this custom header to all requests (max 4096 bytes)
         -c         convert content to text format (with UTF-8 encoding)
         -8         convert from page encoding to UTF-8
         -DMILIS    set delay time in miliseconds when downloading more pages from the same IP (default is 100 ms)
         -S         disable SSL/TLS support
         -g         accept gzip encoding
         -6         resolve host to IPv6 address only
         -b STRING  cookies in the netscape/mozilla file format (max 20 cookies)

   urloptions:
         -C STRING  parameter which replaces '%' in the custom header
         -P STRING  HTTP POST parameters
         -X STRING  custom request HTTP method, no validation performed (max 15 bytes)
```
Options can be get by calling minicrawler without any options.


### Output headers

Minicrawler puts its own headers into an output with the following meaning

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
 * **Cookies**: Number of cookies followed by that number of lines of parsed cookies in Netscape/Mozilla file format
 * **Downtime**: Length of an interval between time of the first connection and time of the last received byte; time of the start of the first connection
 * **Timing**: Timing of request (DNS lookup, Initial connection, SSL, Request, Waiting, Content download, Total)
 * **Index**: Index of URL from command line

## 3rd party libraries

 * asynchronous hostname resolving - [c-ares](http://c-ares.haxx.se/)
 * gzipped content - [zlib](http://zlib.net/)
 * URL parsing and resolving - [uriparser](http://uriparser.sourceforge.net/)
 * TLS/SSL - [OpenSSL](https://www.openssl.org/)

## Build

Tested platforms: Debian Linux, OS X

Install following dependencies (including header files):
 * c-ares
 * zlib1g
 * uriparser
 * OpenSSL (optional)

With apt-get: `apt-get install libc-ares-dev zlib1g-dev liburiparser-dev libssl-dev`
With [homebrew](http://brew.sh/): `brew install c-ares zlib uriparser openssl`

Then run
```
./autogen.sh
./configure
make
sudo make install
```
