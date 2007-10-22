#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([gnome-certauth], [0.3], [http://code.google.com/p/gnome-certauth/issues/list])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([gnome-certauth/gca-certificate-source.c])
AC_CONFIG_HEADER([config.h])

# Honour aclocal flags
# Honor aclocal flags
ACLOCAL="$ACLOCAL $ACLOCAL_FLAGS"

# These checks are fast and most likely to fail, so do them first
# Checks for packages
LIBBONOBO_RV=2.0
GNUTLS_RV=1.2
NSS_RV=3.11
ORBIT_RV=2.0

GNOME_CERTAUTH_MODULES="libbonobo-2.0 >= $LIBBONOBO_RV nss >= $NSS_RV gnutls >= $GNUTLS_RV"
AC_SUBST(GNOME_CERTAUTH_MODULES)

PKG_CHECK_MODULES(GNOME_CERTAUTH, [$GNOME_CERTAUTH_MODULES])
AC_SUBST(GNOME_CERTAUTH_CFLAGS)
AC_SUBST(GNOME_CERTAUTH_LIBS)
AC_DEFINE(HAVE_NSS, 1, [Define if NSS is found])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PATH_PROG(ORBIT_IDL, orbit-idl-2)
AM_PROG_LIBTOOL

# Make libtool use --silent when --silent is passed to make
changequote(,)dnl
LIBTOOL="${LIBTOOL} \$(shell echo \"\$(MFLAGS)\" | awk '/^[^ ]*s/ { print \"--silent\" }')"
changequote([,])dnl

# Checks for libraries.

# Checks for header files.
AC_MSG_CHECKING([for CORBA include paths])
BONOBO_IDL_FLAGS="-I$(pkg-config --variable=idldir libbonobo-2.0) -I$(pkg-config --variable=idldir bonobo-activation-2.0)"
AC_MSG_RESULT($BONOBO_IDL_FLAGS)
AC_SUBST(BONOBO_IDL_FLAGS)

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([
Makefile
gnome-certauth.spec
gnome-certauth-0.0.pc
gnome-certauth/Makefile
idl/Makefile
])
AC_OUTPUT
