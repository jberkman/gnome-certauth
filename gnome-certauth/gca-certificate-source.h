#ifndef GCA_CERTIFICATE_SOURCE_H
#define GCA_CERTIFICATE_SOURCE_H

typedef struct _GcaCertificateSource GcaCertificateSource;

#include <bonobo/bonobo-object.h>
#include <gnome-certauth/CertificateAuthentication.h>
#include <gnome-certauth/gca-certificate-listener.h>
#include <gnutls/gnutls.h>

#define GCA_TYPE_CERTIFICATE_SOURCE         (gca_certificate_source_get_type ())
#define GCA_CERTIFICATE_SOURCE(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), GCA_TYPE_CERTIFICATE_SOURCE, GcaCertificateSource))
#define GCA_CERTIFICATE_SOURCE_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), GCA_TYPE_CERTIFICATE_SOURCE, GcaCertificateSourceClass))
#define GCA_IS_CERTIFICATE_SOURCE(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), GCA_TYPE_CERTIFICATE_SOURCE))
#define GCA_IS_CERTIFICATE_SOURCE_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), GCA_TYPE_CERTIFICATE_SOURCE))
#define GCA_CERTIFICATE_SOURCE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GCA_TYPE_CERTIFICATE_SOURCE, GcaCertificateSourceClass))

G_BEGIN_DECLS

typedef struct _GcaCertificateSourcePrivate GcaCertificateSourcePrivate;

struct _GcaCertificateSource {
    BonoboObject parent;

    GcaCertificateSourcePrivate *priv;
};

typedef struct {
    BonoboObjectClass parent;

    POA_GNOME_CertificateAuthentication_CertificateSource__epv epv;

    /* 
     * Implementation
     */
    void (*request_certificate) (GcaCertificateSource *source,
                                 const gnutls_datum_t *req_ca_rdn, int nreqs,
                                 gnutls_datum_t **cert_der_ret,
                                 int *cert_der_ret_length);

    void (*sign_data) (GcaCertificateSource *source,
                       const gnutls_datum_t *certificate,
                       const gnutls_datum_t *hash,
                       gnutls_datum_t *signature_ret);

    /* padding to waste memory */
    void (*_gca_cs_reserved0) (void);
    void (*_gca_cs_reserved1) (void);
    void (*_gca_cs_reserved2) (void);
    void (*_gca_cs_reserved3) (void);
    void (*_gca_cs_reserved4) (void);
    void (*_gca_cs_reserved5) (void);
} GcaCertificateSourceClass;

GType                 gca_certificate_source_get_type (void);

G_END_DECLS

#endif /* GCA_CERTIFICATE_SOURCE_H */
