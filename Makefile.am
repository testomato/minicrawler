## No default includes
DEFAULT_INCLUDES = 

lib_LTLIBRARIES = libminicrawler-url.la libminicrawler.la

libminicrawler_url_la_SOURCES = src/url/parse.c src/url/serialize.c src/url/api.c src/url/alloc.c
libminicrawler_url_la_LDFLAGS = -version-info 1:0:0

libminicrawler_la_SOURCES = src/crawler.c src/cert.c src/conv.c src/converthtml2text.c src/entities.c src/inflate.c src/time.c src/malloc.c src/base64.c src/digcalc.c src/cookies.c src/tpl/tpl.c src/serialize.c src/memory.c $(libminicrawler_url_la_SOURCES)
libminicrawler_la_LDFLAGS = -version-info 2:0:0

bin_PROGRAMS = minicrawler

minicrawler_SOURCES = src/main.c src/cli.c $(libminicrawler_la_SOURCES)
minicrawler_CFLAGS = $(AM_CFLAGS)

check_PROGRAMS = test/url

test_url_SOURCES = test/url.c test/json/json.c $(libminicrawler_url_la_SOURCES)
test_url_CFLAGS = $(AM_CFLAGS)
test_url_LDFLAGS = -lm
#test_url_LDADD = libminicrawler-url.la

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TESTS = test/run

pkginclude_HEADERS = src/url/minicrawler-url.h src/h/minicrawler.h
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libminicrawler.pc libminicrawler-url.pc

dist_doc_DATA = README.md
