#include "config.h"

#include "gca-nss-certificate-source.h"

#include "gca-nss.h"

/* all boilerplate again */

G_DEFINE_TYPE (GcaNssCertificateSource,
               gca_nss_certificate_source,
               GCA_TYPE_CERTIFICATE_SOURCE);

static void
gca_nss_certificate_source_request_certificate (GcaCertificateSource *source,
                                                const gnutls_datum_t *req_ca_rdn, int nreqs,
                                                gnutls_datum_t **cert_der_ret,
                                                int *cert_der_ret_length)
{
    gca_nss_request_certificate (req_ca_rdn, nreqs, cert_der_ret, cert_der_ret_length);
}

static void
gca_nss_certificate_source_sign_data (GcaCertificateSource *source,
                                      const gnutls_datum_t *certificate,
                                      const gnutls_datum_t *hash,
                                      gnutls_datum_t *signature_ret)
{
    gca_nss_sign_data (certificate, hash, signature_ret);
}

static void
gca_nss_certificate_source_init (GcaNssCertificateSource *source)
{

}

static void
gca_nss_certificate_source_class_init (GcaNssCertificateSourceClass *source_class)
{
    GcaCertificateSourceClass *cert_class = GCA_CERTIFICATE_SOURCE_CLASS (source_class);

    cert_class->request_certificate = gca_nss_certificate_source_request_certificate;
    cert_class->sign_data = gca_nss_certificate_source_sign_data;
}
