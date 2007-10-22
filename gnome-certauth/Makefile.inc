# -*- Makefile -*-

lib_LTLIBRARIES += libgnome-certauth.la

GCA_CORBA_GENERATED_C =					  \
	gnome-certauth/CertificateAuthentication-common.c \
	gnome-certauth/CertificateAuthentication-skels.c  \
	gnome-certauth/CertificateAuthentication-stubs.c

GCA_CORBA_GENERATED_H = \
	gnome-certauth/CertificateAuthentication.h

$(GCA_CORBA_GENERATED_C) : $(GCA_CORBA_GENERATED_H)

GCA_MARSHAL_GENERATED_H = # gnome-certauth/gca-marshal.h
GCA_MARSHAL_GENERATED_C = # gnome-certauth/gca-marshal.c

gcainclude_HEADERS +=				    \
	gnome-certauth/CertificateAuthentication.h  \
	gnome-certauth/gca-certificate-source.h	    \
	gnome-certauth/gca-certificate-listener.h   \
	gnome-certauth/gca-nss.h		    \
	gnome-certauth/gca-nss-certificate-source.h

libgnome_certauth_la_SOURCES :=			    \
	$(gcainclude_HEADERS)			    \
	$(GCA_MARSHAL_GENERATED_H)		    \
	$(GCA_MARSHAL_GENERATED_H)		    \
	$(GCA_CORBA_GENERATED_C)		    \
	gnome-certauth/gca-certificate-source.c	    \
	gnome-certauth/gca-certificate-listener.c   \
	gnome-certauth/gca-nss.c		    \
	gnome-certauth/gca-nss-certificate-source.c \
	gnome-certauth/gca-util.c		    \
	gnome-certauth/gca-util.h

libgnome_certauth_la_CFLAGS := $(GNOME_CERTAUTH_CFLAGS)
libgnome_certauth_la_LIBADD := $(GNOME_CERTAUTH_LIBS)

COMPILE_IDL := $(ORBIT_IDL) $(BONOBO_IDL_FLAGS)

dist_noinst_DATA += gnome-certauth/gca-marshal.list

$(GCA_CORBA_GENERATED_H): idl/CertificateAuthentication.idl gnome-certauth/Makefile.inc
	-@mkdir idl/tmp
	$(COMPILE_IDL) --output-dir=idl/tmp $<
	@for file in $(notdir $(GCA_CORBA_GENERATED_H) $(GCA_CORBA_GENERATED_C)) ; do		\
		if ! cmp idl/tmp/$$file gnome-certauth/$$file >/dev/null 2>/dev/null ; then	\
			echo "mv -f idl/tmp/$$file gnome-certauth/$$file";			\
			mv -f idl/tmp/$$file gnome-certauth/$$file ;			\
		fi										\
	done
	@rm -rf idl/tmp

$(GCA_MARSHAL_C): gnome-certauth/gca-marshal.list gnome-certauth/Makefile.inc
	@glib-genmarshal --body --prefix=gca_marshal $< > $@.tmp
	@if ! cmp $@.tmp $@ >/dev/null 2>/dev/null ; then		     \
		echo "glib-genmarshal --body --prefix=gca_marshal $< > $@" ; \
		mv $@.tmp $@ ;						     \
	fi
	@rm -f $@.tmp

$(GCA_MARSHAL_H): gnome-certauth/gca-marshal.list gnome-certauth/Makefile.inc
	@glib-genmarshal --header --prefix=gca_marshal $< > $@.tmp
	@if ! cmp $@.tmp $@ >/dev/null 2>/dev/null ; then		       \
		echo "glib-genmarshal --header --prefix=gca_marshal $< > $@" ; \
		mv $@.tmp $@ ;						       \
	fi
	@rm -f $@.tmp

#BUILT_SOURCES +=					  \
#	gnome-certauth/CertificateAuthentication-common.c \
#	gnome-certauth/CertificateAuthentication-skels.c  \
#	gnome-certauth/CertificateAuthentication-stubs.c  \
#	gnome-certauth/CertificateAuthentication.h

CLEANFILES +=						  \
	gnome-certauth/CertificateAuthentication-common.c \
	gnome-certauth/CertificateAuthentication-skels.c  \
	gnome-certauth/CertificateAuthentication-stubs.c  \
	gnome-certauth/CertificateAuthentication.h

gnome-certauth/all: libgnome-certauth.la
gnome-certauth/clean: clean
