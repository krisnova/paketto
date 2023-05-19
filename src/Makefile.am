# Copyright (C) 2002 Doxpara
# Licensed under the BSD License.

EXTRA_DIST = config.h libipq.h libipq.a ip_queue_64.h base64.h g711.h

AM_CFLAGS = @CFLAGS@ @DXP_LIBNET_FLAGS@ @DXP_PCAP_FLAGS@ @DXP_TC_FLAGS@ -I@DXP_GHT_FLAGS@ -pthread
LIBS = @DXP_LIBNET_LIBS@ @DXP_PCAP_LIBS@ @DXP_TC_LIBS@ @DXP_IOCCOM_LIBS@ @DXP_GHT_LIBS@ @LIBS@ -lpthread

lib_LTLIBRARIES = libpaketto.la
libpaketto_la_SOURCES = libpaketto.c pk_scan.c base64.c

scanrand2_SOURCES = scanrand2.c
scanrand2_LDADD = libpaketto.la

homer_SOURCES = homer.c
homer_LDADD   = libipq.a libpaketto.la 

donut_SOURCES = donut.c
donut_LDADD   = libipq.a libpaketto.la

ackmon_SOURCES = ackmon.c
ackmon_LDADD   = libpaketto.la

packet2sql_SOURCES = packet2sql.c
packet2sql_LDADD = libpaketto.la

lc2_SOURCES = lc2.c
lc2_LDADD = libpaketto.la

tincan_SOURCES = tincan.c g711.c
tincan_LDADD = libpaketto.la

finx_SOURCES = finx.c
finx_LDADD = libpaketto.la

paratrace2_SOURCES = paratrace2.c
paratrace2_LDADD = libpaketto.la

miname_SOURCES = miname.c
miname_LDADD = libpaketto.la

prox_SOURCES = prox.c
prox_LDADD = libpaketto.la

nodistdir = ""
#sbin_PROGRAMS = lc scanapi

#bin_PROGRAMS  = phentropy demo1 demo2 demo3 demo4 demo5 demo6 demo7 demo8 demo9
bin_PROGRAMS = scanrand2 homer donut ackmon packet2sql lc2 finx tincan paratrace2 miname prox

include_HEADERS = libpaketto.h pk_scan.h pk_serv.h base64.h

#man_MANS = lc.1 paratrace.1 phentropy.1 scanrand.1
