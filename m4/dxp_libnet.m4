dnl Copyright (C) 2002 Doxpara
dnl Licensed under the BSD License

# We need a few things to compile with libnet:
#
# 1) The location of libnet-config.  Unfortunately, `libnet-config
#    --cflags` does not output a -I/usr/wherever statement, so
#    we have to also determine...
#
# 2) The base directory of the libnet headers, which looks like this:
#    ${includedir}/libnet.h
#    ${includedir}/libnet/libnet-asn1.h
#    ${includedir}/libnet/libnet-functions.h
#
# 3) The location of the libnet library, which should be
#    ${includedir}/../lib.
#
# Note that if the user requests not to build with the builtin libnet
# and we cannot find libnet-config, we exit.

AC_DEFUN(DXP_LIBNET,[
	AC_ARG_WITH([libnet-bin],
	[  --with-libnet-bin=DIR   define location of libnet-config],
	[dxp_libnet_bin="$withval"],[dxp_libnet_bin=/usr/lib]
	)

	AC_ARG_WITH([libnet-builtin],
	[  --with-builtin-libnet   use builtin libnet],
	[dxp_libnet_builtin="$withval"],[dxp_libnet_builtin=yes]
	)

	dxp_libnet_builddir="$PWD"
	cd "$srcdir"

# Check for mingw (real or cross-compile) since we have a windows-specific
# behavior for that.  We set a flag which skips over the logic to figure
# out what to do in UNIXy platforms if we do find mingw.
	case "$host" in
	*-*-mingw32*)
		if ! test -f libnet-1.0.2f.zip; then
			wget http://www.securitybugware.org/libnetnt/libnet-1.0.2f.zip
		fi
		if ! test -f libnet-1.0.2f.zip; then
			echo "Could not download Jitsu's libnet/win32 port.  Please download"
			echo "http://www.securitybugware.org/libnetnt/libnet-1.0.2f.zip and copy it to the"
			echo "root paketto directory, then run configure again."
		fi
		if ! test -d libnet-1.0.2f; then
			unzip libnet-1.0.2f.zip
			echo "There might be a few errors here if you're on a case-insensitive machine..."
			# We need to do some fixups on Jitsu's package, since
			# we may be compiling on a case-sensitive machine and
			# his package sometimes refers to its own files in the
			# wrong case...
			cd libnet-1.0.2f
			cd include
			# Double brackets in the grep argument because
			# that's how you escape brackets going through
			# m4, like this autoconf fragment is.
			for i in $(find . -maxdepth 1 | grep '[[A-Z]]'); do 
				ln -s $i $(echo $i | awk '{ print tolower($[1]) }') # the weird awk syntax is also there to escape stuff through m4
			done
			cd NET
			for i in $(find . -maxdepth 1| grep '[[A-Z]]'); do
				ln -sf $i $(echo $i | awk '{ print tolower($[1]) }')
			done
			cd ..
			fromdos *.h
			fromdos *.H
			cd ../lib/windows
			ln -s LibnetNT.a libnetNT.a
			cd ../../..
		fi
		
		# Unfortunately, Jitsu doesn't provide a libnet-config
		# with his distribution, so we'll just hard code the
		# values here.  It's not like there's a lot of variants
		# in windows land...
		DXP_LIBNET_FLAGS="-DLIBNET_LIL_ENDIAN -I$srcdir/libnet-1.0.2f/include"
		DXP_LIBNET_LIBS="-L$srcdir/libnet-1.0.2f/lib/windows -lnetNT"
		dxp_libnet_mingw="yes"
		;;
	esac

	if test "$dxp_libnet_mingw" != "yes"; then
	echo -n "Checking if builtin libnet is already built... "
	if test -s Libnet-1.0.2a/lib/libnet.a; then
		echo yes
		dxp_libnet_builtin_libnet_already_built=yes
	else
		echo no
		dxp_libnet_builtin_libnet_already_built=no
	fi

	if test "$dxp_libnet_builtin" = "yes"; then
		dxp_libnet_config_path="$srcdir/Libnet-1.0.2a"
		if test "$dxp_libnet_builtin_libnet_already_built" = no; then
			echo "*** Building libnet dependency ***"
			rm -rf Libnet-1.0.2a
			gzip -d -c - < libnet-1.0.2a-pk1.tar.gz | tar xvf -
			cd Libnet-1.0.2a
			./configure
			if type -p gmake >/dev/null 2>&1; then
				gmake
			else
				make
			fi
			cd ..
		fi
	else
		dxp_libnet_config_path="$dxp_libnet_bin:/usr/bin:/usr/local/bin:/opt/bin"
	fi

	_path="$PATH"
	PATH="$PATH:Libnet-1.0.2a"
	AC_PATH_PROG(dxp_libnet_config, libnet-config, no, [$dxp_libnet_config_path])
	if test $dxp_libnet_config = no; then
		echo "Could not find libnet-config in the path: $dxp_libnet_config_path."
		echo "libnet is required to compile minewt.  Get it from: "
		echo "http://www.packetfactory.net/libnet/"
		exit 1
	fi
	if test "$dxp_libnet_builtin" = "yes"; then
		DXP_LIBNET_FLAGS="`libnet-config --defines` -I$srcdir/Libnet-1.0.2a/include"
		DXP_LIBNET_LIBS="-lnet -L$srcdir/Libnet-1.0.2a/lib"
	else
		# FIXME depending on dirname is probably bad...
		dxp_libnet_root="$(dirname $dxp_libnet_config_path)/.."
		DXP_LIBNET_FLAGS="`libnet-config --defines -I$dxp_libnet_root/include/libnet`"
		DXP_LIBNET_LIBS="-lnet -L$dxp_libnet_root/lib"
	fi
	PATH="$_path"
	fi # ! test -z "$dxp_libnet_mingw"
	cd "$dxp_libnet_builddir"
])

AC_SUBST(DXP_LIBNET_FLAGS)
AC_SUBST(DXP_LIBNET_LIBS)

