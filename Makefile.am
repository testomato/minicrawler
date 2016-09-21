## No default includes
DEFAULT_INCLUDES = 

minicrawlerincludedir = $(includedir)/libminicrawler-@MINICRAWLER_API_VERSION@/minicrawler
minicrawlerinclude_HEADERS = src/url/minicrawler-url.h src/h/minicrawler.h

libminicrawler_url_sources = src/url/parse.c src/url/serialize.c src/url/api.c src/url/alloc.c
libminicrawler_sources = src/crawler.c src/cert.c src/conv.c src/converthtml2text.c src/entities.c src/inflate.c src/time.c src/malloc.c src/base64.c src/digcalc.c src/cookies.c src/tpl/tpl.c src/serialize.c src/memory.c src/auth.c src/http1.c src/http2.c src/debug.c $(libminicrawler_url_sources)
minicrawler_sources = src/main.c src/cli.c $(libminicrawler_sources)

lib_LTLIBRARIES = libminicrawler/libminicrawler-url-@MINICRAWLER_API_VERSION@.la libminicrawler/libminicrawler-@MINICRAWLER_API_VERSION@.la

libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_SOURCES = $(libminicrawler_url_sources)
libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_LDFLAGS = -version-info $(MINICRAWLER_LT_VERSION)
libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_MCRAWLER
libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden

libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_SOURCES =  $(libminicrawler_sources)
libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_LDFLAGS = -version-info $(MINICRAWLER_LT_VERSION)
libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_MCRAWLER
libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden

bin_PROGRAMS = minicrawler@MINICRAWLER_API_VERSION@

minicrawler@MINICRAWLER_API_VERSION@_SOURCES = $(minicrawler_sources)
minicrawler@MINICRAWLER_API_VERSION@_CFLAGS = $(AM_CFLAGS)

check_PROGRAMS = test/url

test_url_SOURCES = test/url.c test/json/json.c $(libminicrawler_url_sources)
test_url_CFLAGS = $(AM_CFLAGS)
test_url_LDFLAGS = -lm
#test_url_LDADD = libminicrawler-url.la

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TESTS = test/run

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libminicrawler/libminicrawler-$(MINICRAWLER_API_VERSION).pc libminicrawler/libminicrawler-url-$(MINICRAWLER_API_VERSION).pc

DISTCLEANFILES = $(pkgconfig_DATA)

EXTRA_DIST = $(TESTS) test/urltestdata.json libminicrawler.pc.in libminicrawler-url.pc.in

minicrawler_docdir = $(docdir)-@MINICRAWLER_API_VERSION@
dist_minicrawler_doc_DATA = README.md

install-exec-hook:
	cd $(DESTDIR)$(bindir) && $(LN_S) -f minicrawler@MINICRAWLER_API_VERSION@$(EXEEXT) minicrawler$(EXEEXT)
