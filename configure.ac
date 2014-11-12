AC_PREREQ([2.69])
AC_INIT([minicrawler], [3.0~alpha], [admins@wikidi.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/h/config.h])
AC_CONFIG_SRCDIR([src/crawler.c])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([cares], [ares_init], [], AC_MSG_ERROR([please install c-ares]))
AC_CHECK_LIB([crypto], [ERR_get_error], [], AC_MSG_ERROR([please install OpenSSL]))
AC_CHECK_LIB([ssl], [SSL_new], [], AC_MSG_ERROR([please install OpenSSL]))
AC_CHECK_LIB([uriparser], [uriParseUriA], [], AC_MSG_ERROR([please install uriparser]))
AC_CHECK_LIB([z], [inflate], [], AC_MSG_ERROR([please install zlib]))

# Checks for header files.
AC_CHECK_HEADERS([limits.h])
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNC([clock_gettime], [], AC_CHECK_FUNC([gettimeofday], [], AC_MSG_ERROR([clock_gettime or gettimeofday needed to measure time])))
AC_CHECK_FUNCS([mempcpy strchrnul clock_gettime gettimeofday])
#AC_CHECK_FUNCS([bzero memchr memmove mempcpy memset select socket strcasecmp strchr strerror strpbrk strstr strtol])

AC_CONFIG_FILES([Makefile libminicrawler.pc])
AC_OUTPUT
