bin_PROGRAMS=sni-proxy
sni_proxy_SOURCES=	sni-proxy.c \
					util.c	\
					listener.c \
					ringbuf.c \
					proxy.c

sni_proxy_LDADD=	$(top_builddir)/ucl/src/libucl.la
sni_proxy_CFLAGS=	-I$(top_srcdir)/ucl/include