bin_PROGRAMS = pkt_gen pkt_cap blueswitch_test timestamp

pkt_gen_LDADD = -L../src -lsume_pktgen
pkt_gen_CFLAGS = -I$(top_srcdir)/include -D_GNU_SOURCE  -O3
pkt_gen_SOURCES = pkt_gen.c 

pkt_cap_LDADD = -L../src -lsume_pktgen
pkt_cap_CFLAGS = -I$(top_srcdir)/include -O3 
pkt_cap_SOURCES = pkt_cap.c


blueswitch_test_LDADD = -L../src -lsume_pktgen
blueswitch_test_CFLAGS = -I$(top_srcdir)/include -O3 
blueswitch_test_SOURCES = blueswitch_test.c

timestamp_LDADD = -L../src -lsume_pktgen -lgsl -lgslcblas -lm
timestamp_CFLAGS = -I$(top_srcdir)/include -g3 -ggdb -O0 
timestamp_SOURCES = timestamp.c
