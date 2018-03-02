lib_LTLIBRARIES = libnf_pktgen.la libnf10_pktgen.la libsume_pktgen.la
# noinst_LIBRARIES = libnf10_pktgen.a

libnf_pktgen_la_CFLAGS = -I$(top_srcdir)/include -D_GNU_SOURCE
libnf_pktgen_la_SOURCES = nf2.h  nf2util.c  nf2util.h  nf_pktgen.c \
	reg_defines.h  util.c  util.h reg_defines_packet_generator.h

libnf10_pktgen_la_CFLAGS = -I$(top_srcdir)/include -D_GNU_SOURCE -DHAVE_LONG_LONG -g -O3
libnf10_pktgen_la_LDFLAGS =  -lm -lpcap -lpthread
libnf10_pktgen_la_SOURCES =  util.c ringbuffers.c lists.c global.c nf10_pktgen.c \
							 util.h lists.h ringbuffer.h global.h 

libsume_pktgen_la_CFLAGS = -Wall -I$(top_srcdir)/include -D_GNU_SOURCE -DHAVE_LONG_LONG -ggdb -O0
libsume_pktgen_la_LDFLAGS = -lm -lpcap -lpthread
libsume_pktgen_la_SOURCES = util.c global.c sume_pktgen.c \
							util.h global.h
