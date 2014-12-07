## No default includes
DEFAULT_INCLUDES = 

lib_LTLIBRARIES = libminicrawler.la
libminicrawler_la_SOURCES = src/crawler.c src/cert.c src/conv.c src/converthtml2text.c src/entities.c src/inflate.c src/time.c src/malloc.c src/base64.c
libminicrawler_la_LDFLAGS = -version-info 1:0:0
pkginclude_HEADERS = src/h/minicrawler.h

bin_PROGRAMS = minicrawler
minicrawler_SOURCES = src/main.c src/cli.c $(libminicrawler_la_SOURCES)
minicrawler_CFLAGS = $(AM_CFLAGS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libminicrawler.pc

dist_doc_DATA = README.md
