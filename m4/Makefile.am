# Copyright (C) 2002 Doxpara
# Licensed under the BSD license
#
# Most of this stuff was taken from David Sugar's <dyfet@ostel.com>
# way of doing things :)

M4 = dxp_pcap.m4 dxp_libnet.m4 dxp_libtc.m4 dxp_ioccom.m4 dxp_libght.m4

SOURCES = $(M4)

../aclocal.m4: $(M4)
	cd .. ; $(ACLOCAL) -I m4

all-local:	../aclocal.m4

