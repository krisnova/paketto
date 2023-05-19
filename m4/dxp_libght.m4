dnl Copyright (C) 2002 Doxpara
dnl Licensed under the BSD license.

AC_DEFUN([DXP_CHECK_GHT],[
	_cflags="$CFLAGS"
	_ldflags="$LDFLAGS"	

	DXP_GHT_FLAGS="-I${dxp_ght_inc}"
	if test ! -z "$dxp_ght_builddir"; then
		DXP_GHT_FLAGS="$DXP_GHT_FLAGS -I$dxp_ght_builddir"
	fi
	DXP_GHT_LIBS="-L${dxp_ght_lib} -ltomcrypt"
	CFLAGS="$CFLAGS $DXP_GHT_FLAGS"
	LDFLAGS="$LDFLAGS $DXP_GHT_LIBS"

	AC_TRY_LINK([#include <ght_hash_table.h>], [
		int main(void) {
			ght_hash_table_t foo;
			return 0;
			}
		}],[
			dxp_libght=yes
			AC_MSG_RESULT(yes (includes: $dxp_ght_inc, libs: $dxp_ght_lib))
		],[
			# Didn't find it... reset the compiler settings for the next try
			CFLAGS="${_cflags}"
			LDFLAGS="${_ldflags}"
			DXP_GHT_FLAGS=""
			DXP_GHT_LIBS=""
		]	
	)
g])

AC_DEFUN([DXP_GHT],[

	AC_ARG_WITH([ght-inc],
	[  --with-ght-inc=DIR     define location of tomcrypt header files],
	[dxp_ght_inc="$withval"],[dxp_ght_inc=/usr/include]
	)
	
	dxp_ght_builddir=$PWD
	cd "$srcdir"

	echo -n "checking if builtin libghthash-0.5.2 is already built... "
	if test -s libghthash-0.5.2/src/libghthash.la; then
		echo yes
	else
		echo no
			echo "*** Building libghthash-0.5.2 dependency ***"
			rm -rf libghthash-0.5.2
			gzip -d -c libghthash-0.5.2.tar.gz | tar xvf -
			cd libghthash-0.5.2
			./configure
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
	dxp_ght_lib="$dxp_ght_builddir/libghthash-0.5.2/src/"
	dxp_ght_inc="$dxp_ght_builddir/libghthash-0.5.2/src -I$srcdir/libghthash-0.5.2/src"
			
	# Just check to make sure they were built properly...

	AC_MSG_CHECKING([for libghthash-0.5.2])
	DXP_CHECK_GHT

	if test "$dxp_libght" != "yes"; then
		echo "builtin libghthash-0.5.2 build failed... (not) bailing out"
		DXP_GHT_FLAGS="-I${dxp_ght_inc}"
		DXP_GHT_LIBS="-L${dxp_ght_lib} $dxp_ght_builddir/libghthash-0.5.2/src/libghthash.la"
		#exit 1
	fi
])

AC_SUBST(DXP_GHT_FLAGS)
AC_SUBST(DXP_GHT_LIBS)
