#include "config.h"

#include "gca-util.h"

#include <string.h>

GNOME_CertificateAuthentication_Data *
_gca_datum_to_corba (GNOME_CertificateAuthentication_Data *corba, const gnutls_datum_t *datum)
{
    corba->_length = datum->size;
    corba->_buffer = datum->data;
    corba->_release = FALSE;
    return corba;
}

gnutls_datum_t *
_gca_corba_to_datum (gnutls_datum_t *datum, const GNOME_CertificateAuthentication_Data *corba)
{
    datum->size = corba->_length;
    datum->data = corba->_buffer;
    return datum;
}

gnutls_datum_t *
_gca_corba_to_datum_copy (gnutls_datum_t *datum, const GNOME_CertificateAuthentication_Data *corba)
{
    datum->size = corba->_length;
    datum->data = gnutls_malloc (datum->size);
    memcpy (datum->data, corba->_buffer, datum->size);
    return datum;
}

#ifdef HAVE_NSS
SECItem *
_gca_datum_to_item (SECItem *item, const gnutls_datum_t *datum)
{
	item->data = datum->data;
	item->len = datum->size;
	return item;
}

SECItem *
_gca_datum_to_item_copy (PRArenaPool *arena, SECItem *item, const gnutls_datum_t *datum)
{
    item->data = (unsigned char *)PORT_ArenaAlloc (arena, datum->size);
    if (!item->data) return NULL;
    item->len = datum->size;
    item->type = siBuffer;
    PORT_Memcpy (item->data, datum->data, datum->size);
    return item;
}

#if 0
gnutls_datum_t *
_gca_item_to_datum (gnutls_datum_t *datum, SECItem *item)
{
	datum->data = item->data;
	datum->size = item->len;
	return datum;
}
#endif

gnutls_datum_t *
_gca_item_to_datum_copy (gnutls_datum_t *datum, const SECItem *item)
{
    datum->size = item->len;
    datum->data = g_malloc (item->len);
    memcpy (datum->data, item->data, item->len);
    return datum;
}
#endif
