#include "config.h"

#include "gca-certificate-source.h"

#include "gca-util.h"

#include <sys/types.h>
#include <unistd.h>

/* this file is 100% pure grade-a boilerplate */

static void
impl_GNOME_CertificateAuthentication_CertificateSource_requestCertificate (
    PortableServer_Servant servant,
    const GNOME_CertificateAuthentication_CertificateListener listener,
    const CORBA_long opid,
    const GNOME_CertificateAuthentication_DataList* reqCaRdn,
    CORBA_Environment *ev)
{
    BonoboObject *obj;
    gnutls_datum_t *cert_der = NULL;
    gnutls_datum_t *req_ca_rdn;
    GNOME_CertificateAuthentication_DataList cert_der_corba;
    GcaCertificateSource *source;
    int i;
    int nreqs;

    GCA_ENTER;

    obj = bonobo_object (servant);
    if (obj == NULL || !GCA_IS_CERTIFICATE_SOURCE (obj)) {
        g_warning ("Could not find listener from servant");
        GCA_EXIT;
        return;
    }
    
    source = GCA_CERTIFICATE_SOURCE (obj);
    
    nreqs = reqCaRdn->_length;
    req_ca_rdn = g_new0 (gnutls_datum_t, nreqs);
    for (i = 0; i < nreqs; i++) {
        _gca_corba_to_datum (&req_ca_rdn[i], &reqCaRdn->_buffer[i]);
    }

    cert_der_corba._length = 0;

    GCA_CERTIFICATE_SOURCE_GET_CLASS (source)->request_certificate (
        source,
        req_ca_rdn, nreqs,
        &cert_der, &cert_der_corba._length);

    cert_der_corba._buffer = GNOME_CertificateAuthentication_DataList_allocbuf (cert_der_corba._length);
    cert_der_corba._release = TRUE;
    for (i = 0; i < cert_der_corba._length; i++) {
        _gca_datum_to_corba (&cert_der_corba._buffer[i], &cert_der[i]);
    }

    GNOME_CertificateAuthentication_CertificateListener_notifyCertificatePresented (
        listener, opid, &cert_der_corba, ev);

    GNOME_CertificateAuthentication_DataList__freekids (&cert_der_corba, NULL);
    
    for (i = 0; i < cert_der_corba._length; i++) {
        g_free (cert_der[i].data);
    }
    g_free (cert_der);
    
    g_free (req_ca_rdn);
#if 0
    g_free (sign_algos);
#endif
    GCA_EXIT;
}

static void
impl_GNOME_CertificateAuthentication_CertificateSource_signData (
    PortableServer_Servant servant,
    const GNOME_CertificateAuthentication_CertificateListener listener,
    const CORBA_long opid,
    const GNOME_CertificateAuthentication_Data *certificate,
    const GNOME_CertificateAuthentication_Data *hashData,
    CORBA_Environment *ev)
{
    BonoboObject *obj;
    gnutls_datum_t cert;
    gnutls_datum_t hash;
    gnutls_datum_t signature = { 0, 0 };
    GNOME_CertificateAuthentication_Data corba_signature;
    GcaCertificateSource *source;
    int i;
    
    GCA_ENTER;

    obj = bonobo_object (servant);
    if (obj == NULL || !GCA_IS_CERTIFICATE_SOURCE (obj)) {
        g_warning ("Could not find listener from servant");
        GCA_EXIT;
        return;
    }
    
    source = GCA_CERTIFICATE_SOURCE (obj);
 
    GCA_CERTIFICATE_SOURCE_GET_CLASS (source)->sign_data (
        source,
        _gca_corba_to_datum (&cert, certificate),
        _gca_corba_to_datum (&hash, hashData),
        &signature);

    GNOME_CertificateAuthentication_CertificateListener_notifyDataSigned (
        listener, opid,
        _gca_datum_to_corba (&corba_signature, &signature),
        ev);

    g_free (signature.data);

    GCA_EXIT;
}

static void
gca_certificate_source_init (GcaCertificateSource *source)
{
    ;
}

static void
gca_certificate_source_class_init (GcaCertificateSourceClass *klass)
{
    klass->epv.requestCertificate = impl_GNOME_CertificateAuthentication_CertificateSource_requestCertificate;
    klass->epv.signData = impl_GNOME_CertificateAuthentication_CertificateSource_signData;
}

BONOBO_TYPE_FUNC_FULL (GcaCertificateSource,
                       GNOME_CertificateAuthentication_CertificateSource,
                       BONOBO_TYPE_OBJECT,
                       gca_certificate_source);
