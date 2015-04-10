dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(sni-proxy, 1.0)

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()
AC_PROG_CC_C99
LT_INIT()
AX_CFLAGS_WARN_ALL

AC_C_CONST
AC_TYPE_SIZE_T
AC_PROG_CC

AC_SEARCH_LIBS([ev_run], [ev], [], [
  AC_MSG_ERROR([unable to find the libev])
])

AC_CONFIG_SUBDIRS(ucl)
AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT

