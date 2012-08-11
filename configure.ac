#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([ticketer], [0.1], [neko2k@beige-box.com])

AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_GNU_SOURCE

AC_CONFIG_SRCDIR([ticketer.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall])
# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_C_BIGENDIAN( 
  AC_DEFINE(ENDIAN_BIG, 1, [machine is bigendian]), 
  AC_DEFINE(ENDIAN_LITTLE, 1, [machine is littleendian]), 
  AC_MSG_ERROR(unknown endianess), 
  AC_MSG_ERROR(universial endianess not supported) 
) 

dnl use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
Configuration:
	ticketer version     : ${PACKAGE_VERSION}
	LDFLAGS              : ${LDFLAGS}
	CFLAGS               : ${CFLAGS}

Type make to build ticketer, and make install to install it."
