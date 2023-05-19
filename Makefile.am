SUBDIRS = src config
DIST_SUBDIRS = src config m4 
EXTRA_DIST = reconfig README libnet-1.0.2a-pk1.tar.gz libpcap-0.8.1.tar.gz libtomcrypt.tar.gz TODO docs docs/lc_logs.txt docs/scanrand_logs.txt docs/minewt_logs.txt docs/paratrace_logs.txt libghthash-0.5.2.tar.gz

# We don't do "make clean" in libnet and libpcap during "make clean" mainly because there
# is no clean-hook, but also because they probably don't want us to undo what's probably
# a good build of libnet and libpcap.

dist-hook:
	rm -rf Libnet-1.0.2a
	rm -rf libpcap-0.8.1
	rm -rf libtomcrypt
	rm -rf libghthash-0.5.2

