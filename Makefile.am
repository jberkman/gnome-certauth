#
# This is a non-recursive automake file.
#
# The style was inspired by Robert Collins, as mentioned here:
#
#     http://sources.redhat.com/ml/automake/2001-08/msg00061.html
#
# And the original Recursive Make Considered Harmful:
#
#     http://www.pcug.org.au/~millerp/rmch/recu-make-cons-harm.html
#

AUTOMAKE_OPTIONS := subdir-objects
ACLOCAL_AMFLAGS = # -I m4 -I macros

NULL :=

bin_PROGRAMS :=
sbin_PROGRAMS :=
noinst_PROGRAMS :=
check_PROGRAMS :=

sbin_SCRIPTS :=

dist_sbin_SCRIPTS :=
dist_noinst_SCRIPTS :=
dist_pkglibexec_SCRIPTS :=

lib_LTLIBRARIES :=

nobase_dist_pkgdata_DATA :=
dist_noinst_DATA := 
noinst_DATA :=

noinst_HEADERS :=
gcaincludedir := $(includedir)/gnome-certauth-0.0/gnome-certauth
gcainclude_HEADERS :=

TESTS :=

AM_CPPFLAGS :=

EXTRA_DIST := Makefile.am.subdir gnome-certauth-0.0.pc.in gnome-certauth.spec gnome-certauth.spec.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA := gnome-certauth-0.0.pc

pkglibexecdir = $(libexecdir)/$(PACKAGE)

SUBDIRS =

include_subdirs :=				\
	gnome-certauth				\
	idl

DIST_SUBDIRS := $(SUBDIRS) $(include_subdirs)

BUILT_SOURCES :=
CLEANFILES :=
DISTCLEANFILES := $(pkgconfig_DATA)

include gnome-certauth/Makefile.inc
include idl/Makefile.inc

update-makefiles:
	@for dir in $(include_subdirs) ; do \
		echo " cp $(top_srcdir)/Makefile.am.subdir $(top_srcdir)/$$dir/Makefile.am" ; \
		cp "$(top_srcdir)/Makefile.am.subdir" "$(top_srcdir)/$$dir/Makefile.am" || exit 1 ; \
	done
