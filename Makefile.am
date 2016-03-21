## No default includes
DEFAULT_INCLUDES = 

lib_LTLIBRARIES = libminicrawler-urlparser.la libminicrawler.la

libminicrawler_urlparser_la_SOURCES = src/url/parse.c
libminicrawler_urlparser_la_LDFLAGS = -version-info 1:0:0

libminicrawler_la_SOURCES = src/crawler.c src/cert.c src/conv.c src/converthtml2text.c src/entities.c src/inflate.c src/time.c src/malloc.c src/base64.c src/digcalc.c src/cookies.c src/tpl/tpl.c src/serialize.c src/memory.c $(libminicrawler_urlparser_la_SOURCES)
libminicrawler_la_LDFLAGS = -version-info 2:0:0

bin_PROGRAMS = minicrawler
minicrawler_SOURCES = src/main.c src/cli.c $(libminicrawler_la_SOURCES)
minicrawler_CFLAGS = $(AM_CFLAGS)

pkginclude_HEADERS = src/url/minicrawler-urlparser.h src/h/minicrawler.h
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libminicrawler.pc libminicrawler-urlparser.pc

dist_doc_DATA = README.md
