dnl Copyright (C) 2002 Doxpara
dnl Licensed under the BSD license.

# Ok, the way this works is we have a table of popular locations for
# the pcap libraries and headers to be installed in, then we call
# DXP_CHECK_PCAP for each one of those library/header location pairs.
# Hopefully one call will succeed, we call AC_MSG_RESULT, and exit the
# for loop.  Otherwise we'll exhaust the search table, dxp_libpcap
# will be set to no, and we bomb out with an error message.
#
# If we find pcap, we set CFLAGS and LDFLAGS which gets AC_SUBSTed
# later on during automake into src/Makefile.am which results in
# src/Makefile.  Then the user types "make" and everything just works.

AC_DEFUN([DXP_CHECK_PCAP],[
	_cflags="$CFLAGS"
	_ldflags="$LDFLAGS"	

	DXP_PCAP_FLAGS="-I${dxp_pcap_inc}"
	if test ! -z "$dxp_pcap_builddir"; then
		DXP_PCAP_FLAGS="$DXP_PCAP_FLAGS -I$dxp_pcap_builddir"
	fi
	DXP_PCAP_LIBS="-L${dxp_pcap_lib} -lpcap"
	CFLAGS="$CFLAGS $DXP_PCAP_FLAGS"
	LDFLAGS="$LDFLAGS $DXP_PCAP_LIBS"

	AC_TRY_LINK([#include <pcap.h>], [
		int main(void) {
			printf("%i : %i", PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR);
			return 0;
		}],[
			dxp_libpcap=yes
			AC_MSG_RESULT(yes (includes: $dxp_pcap_inc, libs: $dxp_pcap_lib))
		],[
			# Didn't find it... reset the compiler settings for the next try
			CFLAGS="${_cflags}"
			LDFLAGS="${_ldflags}"
			DXP_PCAP_FLAGS=""
			DXP_PCAP_LIBS=""
		]	
	)
])

AC_DEFUN([DXP_PCAP],[
	AC_ARG_WITH([pcap-builtin],
	[  --with-pcap-builtin     use builtin libpcap],
	[dxp_pcap_builtin="$withval"],[dxp_pcap_builtin="yes"]
	)

	AC_ARG_WITH([pcap-lib],
	[  --with-pcap-lib=DIR     define location of libpcap library files],
	[dxp_pcap_lib="$withval"],[dxp_pcap_lib=/usr/lib]
	)

	AC_ARG_WITH([pcap-inc],
	[  --with-pcap-inc=DIR     define location of libpcap header files],
	[dxp_pcap_inc="$withval"],[dxp_pcap_inc=/usr/include]
	)

	dxp_pcap_builddir="$PWD"
	cd "$srcdir"

# Like a lot of other things, Windows gets its own behavior since we have
# a windows-specific dependency.
	case "$host" in
	*-*-mingw32*)
		if ! test -f wpdpack_3_0_beta.zip; then
			wget http://winpcap.polito.it/install/bin/wpdpack_3_0_beta.zip
		fi
		if ! test -f wpdpack_3_0_beta.zip; then
			echo "Could not retrieve Winpcap developer's pack from the polito site.  Please"
			echo "download http://winpcap.polito.it/install/bin/wpdpack_3_0_beta.zip and copy it"
			echo "to the paketto root directory, then run configure again."
			exit 1
		fi
		if ! test -d wpdpack; then
			unzip wpdpack_3_0_beta.zip
		fi
		DXP_PCAP_FLAGS="-I$srcdir/wpdpack/Include"
		DXP_PCAP_LIBS="-L$srcdir/wpdpack/Lib -lpacket"
		dxp_pcap_mingw="yes"
		;;
	esac

	if test "$dxp_pcap_mingw" != "yes"; then
	echo -n "checking if builtin libpcap is already built... "
	if test -s libpcap-0.8.1/libpcap.a; then
		echo yes
		dxp_libpcap=yes
		if test "$dxp_pcap_builtin" = "yes"; then
			dxp_pcap_lib="$srcdir/libpcap-0.8.1"
			dxp_pcap_inc="$srcdir/libpcap-0.8.1 -I$srcdir/libpcap-0.8.1/bpf"
		fi
	else
		echo no
		if test "$dxp_pcap_builtin" = "yes"; then
			echo "*** Building libpcap dependency ***"
			rm -rf libpcap-0.8.1
			gzip -d -c - < libpcap-0.8.1.tar.gz | tar xvf -
			cd libpcap-0.8.1
			./configure
			if type -p gmake >/dev/null 2>&1; then
				gmake
			else
				make
			fi
			cd ..
		fi

		# Just check to make sure they were built properly...
		dxp_pcap_lib="$srcdir/libpcap-0.8.1"
		dxp_pcap_inc="$srcdir/libpcap-0.8.1 -I$srcdir/libpcap-0.8.1/bpf"
		DXP_CHECK_PCAP
		if test "$dxp_libpcap" != "yes"; then
			echo "builtin libpcap build failed... bailing out"
			exit 1
		fi
	fi # if libpcap is already built

	# Haven't found anything yet
	#dxp_libpcap=no

	AC_MSG_CHECKING([for libpcap])

	# defaults: /usr/lib and /usr/include, or the builtin directory if
	# --with-pcap-builtin was given
	DXP_CHECK_PCAP

	if test $dxp_libpcap != yes; then
		# RedHat 7.3
		dxp_pcap_lib=/usr/lib; dxp_pcap_inc=/usr/include/pcap 
		DXP_CHECK_PCAP
	fi
	if test $dxp_libpcap != yes; then
		# Installed from source
		dxp_pcap_lib=/usr/local/lib; dxp_pcap_inc=/usr/local/include/pcap
		DXP_CHECK_PCAP
	fi
	if test $dxp_libpcap != yes; then
		# Maybe someone's being clever and installing the header by hand
		dxp_pcap_lib=/usr/local/lib; dxp_pcap_inc=/usr/local/include
		DXP_CHECK_PCAP
	fi
	if test $dxp_libpcap != yes; then
		echo "libpcap is required to compile minewt.  Get it from"
		echo "http://www.tcpdump.org/"
		exit 1
	fi
	cd "$dxp_pcap_builddir"
	fi # ! test -z $dxp_pcap_mingw
])
		
AC_SUBST(DXP_PCAP_FLAGS)
AC_SUBST(DXP_PCAP_LIBS)
