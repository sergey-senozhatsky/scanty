AC_PREREQ([2.68])

AC_INIT([SCANTY], [0.0.1], [sergey.senozhatsky@gmail.com])

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign tar-pax dist-xz subdir-objects])

AC_LANG([C++])
AC_PROG_CXX
AM_SILENT_RULES([yes])
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG([0.9])

PKG_CHECK_MODULES([JSON_C], [json-c], [], [])
AX_PTHREAD()

AC_CONFIG_FILES([
	Makefile
	libscanty/Makefile
	plugin/Makefile
	db/Makefile
	client/Makefile
])

AC_OUTPUT
