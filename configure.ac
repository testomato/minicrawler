AC_PREREQ([2.69])
AC_INIT([minicrawler], [5.2.6], [info@testomato.com])
AC_SUBST([MINICRAWLER_API_VERSION], [5])
# 1. Update the version information only immediately before a public release of your software. More frequent updates are unnecessary, and only guarantee that the current interface number gets larger faster.
# 2. If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# 3. If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# 4. If any interfaces have been added since the last public release, then increment age.
# 5. If any interfaces have been removed or changed since the last public release, then set age to 0.
AC_SUBST([MINICRAWLER_LT_VERSION], [5:18:0])
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
AC_PROG_CXX
if test "${ac_cv_prog_cxx_cxx14}" = "no"; then
	AC_MSG_ERROR([your compiler does not support standard C++14])
fi
AC_PROG_LIBTOOL
AC_PROG_AWK

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([cares], [ares_init], [], AC_MSG_ERROR([Unable to find c-ares dev files! apt install libcares-dev]))
AC_CHECK_LIB([z], [inflate], [], AC_MSG_ERROR([Unable to find zlib dev files! apt install zlib1g-dev]))
AC_CHECK_LIB([icuuc], [uidna_nameToASCII_63], [],
    AC_CHECK_LIB([icuuc], [uidna_nameToASCII_64], [],
        AC_CHECK_LIB([icuuc], [uidna_nameToASCII_65], [],
            AC_CHECK_LIB([icuuc], [uidna_nameToASCII_66], [],
                AC_CHECK_LIB([icuuc], [uidna_nameToASCII_67], [],
                    AC_CHECK_LIB([icuuc], [uidna_nameToASCII_68], [],
                        AC_CHECK_LIB([icuuc], [uidna_nameToASCII_69], [],
                            AC_CHECK_LIB([icuuc], [uidna_nameToASCII_70], [],
                                AC_CHECK_LIB([icuuc], [uidna_nameToASCII_71], [],
                                    AC_CHECK_LIB([icuuc], [uidna_nameToASCII_72], [],
                                        AC_CHECK_LIB([icuuc], [uidna_nameToASCII_73], [],
                                            AC_CHECK_LIB([icuuc], [uidna_nameToASCII_74], [],
                                                AC_MSG_WARN([Unable to find libicuuc library! apt install libicu-dev!])
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    )
)
AC_SEARCH_LIBS([iconv], [iconv], [], AC_MSG_ERROR([Unable to find iconv dev files! apt install libiconv-dev]))

AC_ARG_WITH([ssl],
			[AS_HELP_STRING([--without-ssl], [disable support for https])],
			[],
			[with_ssl=check])

# configre with libssl
AS_IF([test "${with_ssl}" != "no"], [
       AC_CHECK_LIB([crypto], [ERR_get_error], [],
            AC_MSG_ERROR([please install OpenSSL dev files or use option --without-ssl]))
       AC_CHECK_LIB([ssl], [SSL_new], [
            LIBS="-lssl $LIBS"
            AC_DEFINE([HAVE_LIBSSL], [1], [Define if you have the ssl library (-lssl).])
            AC_CHECK_FUNCS([SSL_get0_param SSL_CTX_set_alpn_protos])
            AC_CHECK_DECLS([SSL_get_max_proto_version], [], [], [[#include <openssl/ssl.h>]])
            ],
            AC_MSG_ERROR([please install OpenSSL dev files or use option --without-ssl]))])

AC_ARG_WITH([http2],
			[AS_HELP_STRING([--without-http2], [disable support for http2])],
			[],
			[with_http2=check])

# nghttp is needed?
AS_IF([test "${with_ssl} ${with_http2}" == "check check"], [
       AC_CHECK_LIB([nghttp2], [nghttp2_session_client_new], [
            LIBS="-lnghttp2 $LIBS"
            AC_DEFINE([HAVE_LIBNGHTTP2], [1], [Define if you have the nghttp2 library (-lnghttp2).])
            AC_CHECK_FUNCS([nghttp2_http2_strerror nghttp2_session_callbacks_set_error_callback nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation])
            AC_CHECK_DECLS([NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL],
                     [], [], [[#include <nghttp2/nghttp2.h>]])
            ],
            AC_MSG_ERROR([please install nghttp2 dev files or use option --without-http2]))
])

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

# debug
AC_ARG_WITH([debug],
			[AC_HELP_STRING([--with-debug], [build with support for debug output])],
			[],
			[want_debug=no])
AS_IF([test "x$want_debug" != xno],
			[AC_DEFINE([HAVE_DEBUG], [1], [Build with debug])])

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
AC_CHECK_FUNCS([mempcpy strchrnul clock_gettime gettimeofday timegm])
##AC_CHECK_FUNCS([memmove memset select socket strcasecmp strchr strerror strpbrk strstr strtol stpcpy])

AC_CONFIG_FILES([Makefile integration-tests/Makefile libminicrawler/libminicrawler-$MINICRAWLER_API_VERSION.pc:libminicrawler.pc.in libminicrawler/libminicrawler-url-$MINICRAWLER_API_VERSION.pc:libminicrawler-url.pc.in])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_OUTPUT
