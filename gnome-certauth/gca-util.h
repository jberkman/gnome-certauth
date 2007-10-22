#ifndef GCA_UTIL_H
#define GCA_UTIL_H

#include <gnome-certauth/CertificateAuthentication.h>

#include <gnutls/gnutls.h>

#ifdef HAVE_NSS
#include <prtypes.h>
#include <seccomon.h>
#endif /* HAVE_NSS */

#include <sys/types.h>
#include <unistd.h>

GNOME_CertificateAuthentication_Data *_gca_datum_to_corba (GNOME_CertificateAuthentication_Data *corba, const gnutls_datum_t *data);

gnutls_datum_t *_gca_corba_to_datum (gnutls_datum_t *datum, const GNOME_CertificateAuthentication_Data *corba);
gnutls_datum_t *_gca_corba_to_datum_copy (gnutls_datum_t *datum, const GNOME_CertificateAuthentication_Data *corba);

#ifdef HAVE_NSS
SECItem *_gca_datum_to_item (SECItem *item, const gnutls_datum_t *datum);
SECItem *_gca_datum_to_item_copy (PRArenaPool *arena, SECItem *item, const gnutls_datum_t *datum);
#if 0
gnutls_datum_t *_gca_item_to_datum (gnutls_datum_t *datum, const SECItem *item);
#endif /* 0 */
gnutls_datum_t *_gca_item_to_datum_copy (gnutls_datum_t *datum, const SECItem *item);
#endif /* HAVE_NSS */

#if 1
#define GCA_TRACE(s, ...) fprintf (stderr, "%d:%s:%s():%d "s"\n", getpid(), __FILE__, __PRETTY_FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define GCA_TRACE(s, ...)
#endif

#define GCA_TRACEMSG(s) GCA_TRACE("%s", (s))
#define GCA_ENTER GCA_TRACEMSG("ENTER")
#define GCA_EXIT GCA_TRACEMSG("EXIT")
#define GCA_HASLOCK GCA_TRACEMSG("HAS LOCK")
#define GCA_ALREADYLOCKED GCA_TRACEMSG("ALREADY LOCKED")

#endif /* GCA_UTIL_H */
