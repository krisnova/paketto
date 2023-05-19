dnl Copyright (C) 2002 Doxpara
dnl Licensed under the BSD License

AC_DEFUN(DXP_IOCCOM, [
	DXP_IOCCOM_LIBS=""
	AC_CHECK_HEADERS([sys/ioccom.h], 
	if test `uname` = 'SunOS'; then
		DXP_IOCCOM_LIBS='-lsocket -lnsl -lresolv'
	fi
	)
	AC_SUBST([DXP_IOCCOM_LIBS])
])
