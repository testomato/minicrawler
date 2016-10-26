AC_PREREQ([2.69])
AC_INIT([minicrawler], [5.0.2], [admins@wikidi.com])
AC_SUBST([MINICRAWLER_API_VERSION], [5])
# 1. Update the version information only immediately before a public release of your software. More frequent updates are unnecessary, and only guarantee that the current interface number gets larger faster.
# 2. If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# 3. If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# 4. If any interfaces have been added since the last public release, then increment age.
# 5. If any interfaces have been removed or changed since the last public release, then set age to 0.
AC_SUBST([MINICRAWLER_LT_VERSION], [5:2:0])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/h/config.h])
AC_CONFIG_SRCDIR([src/crawler.c])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
if test "${ac_cv_prog_cc_c99}" = "no"; then
	AC_MSG_ERROR([your compiler does not support ISO Standard C 99])
fi
AC_PROG_LIBTOOL
AC_PROG_AWK

# Checks for libraries.
AC_CHECK_LIB([cares], [ares_init], [], AC_MSG_ERROR([please install c-ares dev files]))
AC_CHECK_LIB([z], [inflate], [], AC_MSG_ERROR([please install zlib dev files]))
AC_CHECK_LIB([icuuc], [uidna_nameToASCII_52], [],
	AC_CHECK_LIB([icuuc], [uidna_nameToASCII_53], [],
		AC_CHECK_LIB([icuuc], [uidna_nameToASCII_54], [],
			AC_CHECK_LIB([icuuc], [uidna_nameToASCII_55], [],
				AC_CHECK_LIB([icuuc], [uidna_nameToASCII_56], [],
					AC_CHECK_LIB([icuuc], [uidna_nameToASCII_57], [], AC_MSG_ERROR([please install libicu dev files])))))))
AC_SEARCH_LIBS([iconv], [iconv], [], AC_MSG_ERROR([please install iconv dev files]))
AC_ARG_WITH([ssl],
			[AS_HELP_STRING([--without-ssl], [disable support for https])],
			[],
			[with_ssl=check])
AS_IF([test "${with_ssl}" != "no"],
			[AC_CHECK_LIB([crypto], [ERR_get_error], [], AC_MSG_ERROR([please install OpenSSL dev files or use option --without-ssl]))
			AC_CHECK_LIB([ssl], [SSL_new], [], AC_MSG_ERROR([please install OpenSSL dev files or use option --without-ssl]))])
AC_ARG_WITH([http2],
			[AS_HELP_STRING([--without-http2], [disable support for http2])],
			[],
			[with_http2=check])
AS_IF([test "${with_ssl} ${with_http2}" == "check check"],
			[AC_CHECK_LIB([nghttp2], [nghttp2_session_client_new], [], AC_MSG_ERROR([please install nghttp2 dev files or use option --without-http2]))])

# CA bundle & CA path
AC_ARG_WITH([ca-bundle],
			[AC_HELP_STRING([--with-ca-bundle=FILE], [path to a file containing CA certificates])],
			[want_ca="$withval"],
			[want_ca="no"])
AS_IF([test "x$want_ca" != "xno"],
			[AC_DEFINE_UNQUOTED([CA_BUNDLE], ["$want_ca"], [Location of default ca bundle])
			AC_MSG_RESULT([CA bundle: $want_ca])])
AC_ARG_WITH([ca-path],
			[AC_HELP_STRING([--with-ca-path=DIR], [path to a directory containing CA certificates])],
			[want_capath="$withval"],
			[want_capath="no"])
AS_IF([test "x$want_capath" != "xno"],
			[AC_DEFINE_UNQUOTED([CA_PATH], ["$want_capath"], [Location of default ca path])
			AC_MSG_RESULT([CA path: $want_capath])])

# Checks for header files.
AC_CHECK_HEADERS([limits.h sys/types.h sys/select.h])
##AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stddef.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNC([clock_gettime], [], AC_CHECK_FUNC([gettimeofday], [], AC_MSG_ERROR([clock_gettime or gettimeofday needed to measure time])))
AC_CHECK_FUNCS([mempcpy strchrnul clock_gettime gettimeofday timegm SSL_get0_param nghttp2_http2_strerror nghttp2_session_callbacks_set_error_callback])
##AC_CHECK_FUNCS([memmove memset select socket strcasecmp strchr strerror strpbrk strstr strtol stpcpy])

AC_CONFIG_FILES([Makefile integration-tests/Makefile libminicrawler/libminicrawler-$MINICRAWLER_API_VERSION.pc:libminicrawler.pc.in libminicrawler/libminicrawler-url-$MINICRAWLER_API_VERSION.pc:libminicrawler-url.pc.in])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_OUTPUT
