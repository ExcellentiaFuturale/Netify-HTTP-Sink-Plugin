AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I ../m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include $(LIBNETIFYD_CFLAGS) $(LIBCURL_CFLAGS)

lib_LTLIBRARIES = libnetify-sink-http.la

libnetify_sink_http_la_SOURCES = nsp-plugin.cpp
libnetify_sink_http_la_LIBADD = $(LIBNETIFYD_LIBS) $(LIBCURL_LIBS)
