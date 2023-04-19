AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I ../m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include $(LIBNETIFYD_CFLAGS)

lib_LTLIBRARIES = libnetify-sink-post.la

libnetify_sink_post_la_SOURCES = nsp-plugin.cpp
