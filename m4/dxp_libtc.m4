dnl Copyright (C) 2002 Doxpara
dnl Licensed under the BSD license.

AC_DEFUN([DXP_CHECK_TC],[
	_cflags="$CFLAGS"
	_ldflags="$LDFLAGS"	

	DXP_TC_FLAGS="-I${dxp_tc_inc}"
	if test ! -z "$dxp_tc_builddir"; then
		DXP_TC_FLAGS="$DXP_TC_FLAGS -I$dxp_tc_builddir"
	fi
	DXP_TC_LIBS="-L${dxp_tc_lib} -ltomcrypt"
	CFLAGS="$CFLAGS $DXP_TC_FLAGS"
	LDFLAGS="$LDFLAGS $DXP_TC_LIBS"

	AC_TRY_LINK([#include <mycrypt.h>], [
		int main(void) {
			prng_state prng;
			ecc_key mykey;	
			register_prng(&yarrow_desc);
			ecc_make_key(24, &prng, find_prng("yarrow"), &mykey);
			return 0;
			}
		}],[
			dxp_libtc=yes
			AC_MSG_RESULT(yes (includes: $dxp_tc_inc, libs: $dxp_tc_lib))
		],[
			# Didn't find it... reset the compiler settings for the next try
			CFLAGS="${_cflags}"
			LDFLAGS="${_ldflags}"
			DXP_TC_FLAGS=""
			DXP_TC_LIBS=""
		]	
	)
g])

AC_DEFUN([DXP_TC],[

	AC_ARG_WITH([tc-inc],
	[  --with-tc-inc=DIR     define location of tomcrypt header files],
	[dxp_tc_inc="$withval"],[dxp_tc_inc=/usr/include]
	)
	
	dxp_tc_builddir=$PWD
	cd "$srcdir"

	echo -n "checking if builtin libtomcrypt is already built... "
	if test -s libtomcrypt/libtomcrypt.a; then
		echo yes
	else
		echo no
			echo "*** Building libtomcrypt dependency ***"
			rm -rf libtomcrypt
			gzip -d -c libtomcrypt.tar.gz | tar xvf -
			cd libtomcrypt
			# override gcc name in the cross-compile case
			if echo "$host" | grep -q mingw32; then
				CC="$CC" make -e
			else
				if type -p gmake; then
					gmake
				else
					make
				fi
			fi
			cd ..
		fi
	dxp_tc_lib="$dxp_tc_builddir/libtomcrypt"
	dxp_tc_inc="$dxp_tc_builddir/libtomcrypt -I$srcdir/libtomcrypt"
			
	# Just check to make sure they were built properly...

	AC_MSG_CHECKING([for libtomcrypt])
	DXP_CHECK_TC

	if test "$dxp_libtc" != "yes"; then
		echo "builtin libtomcrypt build failed... (not) bailing out"
		DXP_PCAP_FLAGS="-I${dxp_tc_inc}"
		DXP_PCAP_LIBS="-L${dxp_tc_lib} -ltomcrypt"
		#exit 1
	fi
])

AC_SUBST(DXP_TC_FLAGS)
AC_SUBST(DXP_TC_LIBS)
