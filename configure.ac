AC_PREREQ([2.68])
AC_INIT([dnst-processing], [0.1.0], [willem@nlnetlabs.nl])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_SRCDIR([src/atlas2dnst.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

AC_CHECK_LIB([getdns], [getdns_context_set_listen_addresses],,
       [AC_MSG_ERROR([Missing dependency: getdns >= 1.1.0 ])],)

AC_CHECK_HEADERS([bsd/string.h])
AC_CHECK_FUNC([strlcpy], [], [AC_SEARCH_LIBS([strlcpy], [bsd])])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AH_BOTTOM([
#define _XOPEN_SOURCE
#define LIBBSD_OBERLAY

#ifdef HAVE_BSD_STRING_H
# include <bsd/string.h>
#else
# include <string.h>
#endif


])
AC_OUTPUT

