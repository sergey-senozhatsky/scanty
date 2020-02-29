AM_CXXFLAGS = -I$(top_srcdir)/include -fPIC -fno-common $(JSON_C_CFLAGS) $(PTHREAD_CFLAGS)
LIBS = $(JSON_C_LIBS) -lpthread

lib_LTLIBRARIES = libscantycommon.la
libscantycommon_la_SOURCES = configuration.cpp \
			     logger.cpp \
			     decl_tree.cpp \
			     protocol.cpp \
			     transport.cpp
