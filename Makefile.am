## No default includes
DEFAULT_INCLUDES =

## Compiler/link hardening (issue #20). Applied on top of the user's CFLAGS.
## FORTIFY_SOURCE needs an optimization level; the autoconf default is -O2.
HARDENING_CFLAGS = -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2
AM_CFLAGS = $(HARDENING_CFLAGS)
AM_CXXFLAGS = -std=c++14 $(HARDENING_CFLAGS)
## Full RELRO for every link target (libraries and the binary).
AM_LDFLAGS = -Wl,-z,relro,-z,now

minicrawlerincludedir = $(includedir)/libminicrawler-@MINICRAWLER_API_VERSION@/minicrawler
minicrawlerinclude_HEADERS = src/url/minicrawler-url.h src/h/minicrawler.h

libminicrawler_url_sources = src/url/parse.cc src/url/serialize.c src/url/api.c src/url/alloc.c
libminicrawler_sources = src/crawler.c src/cert.c src/conv.c src/converthtml2text.c src/entities.c src/inflate.c src/time.c src/malloc.c src/base64.c src/digcalc.c src/cookies.c src/tpl/tpl.c src/serialize.c src/memory.c src/auth.c src/http1.c src/http2.c src/debug.c src/buf.c src/api.c $(libminicrawler_url_sources)
minicrawler_sources = src/main.c src/cli.c $(libminicrawler_sources)

lib_LTLIBRARIES = libminicrawler/libminicrawler-url-@MINICRAWLER_API_VERSION@.la libminicrawler/libminicrawler-@MINICRAWLER_API_VERSION@.la

libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_SOURCES = $(libminicrawler_url_sources)
libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(MINICRAWLER_LT_VERSION)
libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_MCRAWLER
libminicrawler_libminicrawler_url_@MINICRAWLER_API_VERSION@_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden

libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_SOURCES =  $(libminicrawler_sources)
libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(MINICRAWLER_LT_VERSION)
libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_MCRAWLER
libminicrawler_libminicrawler_@MINICRAWLER_API_VERSION@_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden

bin_PROGRAMS = minicrawler@MINICRAWLER_API_VERSION@

minicrawler@MINICRAWLER_API_VERSION@_SOURCES = $(minicrawler_sources)
minicrawler@MINICRAWLER_API_VERSION@_CFLAGS = $(AM_CFLAGS) -fPIE
minicrawler@MINICRAWLER_API_VERSION@_LDFLAGS = $(AM_LDFLAGS) -pie

check_PROGRAMS = test/url test/unit

test_url_SOURCES = test/url.c test/json/json.c $(libminicrawler_url_sources)
test_url_CFLAGS = $(AM_CFLAGS)
test_url_LDFLAGS = $(AM_LDFLAGS) -lm
#test_url_LDADD = libminicrawler-url.la

# Regression / unit tests for libminicrawler internals (issues #5–#19).
test_unit_SOURCES = test/unit.c $(libminicrawler_sources)
test_unit_CFLAGS = $(AM_CFLAGS)

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TESTS = test/run test/unit

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libminicrawler/libminicrawler-$(MINICRAWLER_API_VERSION).pc libminicrawler/libminicrawler-url-$(MINICRAWLER_API_VERSION).pc

DISTCLEANFILES = $(pkgconfig_DATA)

EXTRA_DIST = $(TESTS) test/urltestdata.json libminicrawler.pc.in libminicrawler-url.pc.in

minicrawler_docdir = $(docdir)-@MINICRAWLER_API_VERSION@
dist_minicrawler_doc_DATA = README.md
