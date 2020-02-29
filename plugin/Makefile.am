FLAGS=$(shell $(CXX) -print-file-name=plugin)

AM_CXXFLAGS = -fno-rtti -I$(top_srcdir)/include -fno-common -I$(FLAGS)/include
LIBS =
lib_LTLIBRARIES = libscanty.la
libscanty_la_LIBADD = $(top_builddir)/libscanty/libscantycommon.la

libscanty_la_SOURCES = decl_tree_ssa.cpp \
		       plugin_main.cpp
