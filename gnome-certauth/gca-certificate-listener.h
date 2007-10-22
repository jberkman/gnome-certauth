#ifndef GCA_CERTIFICATE_LISTENER_H
#define GCA_CERTIFICATE_LISTENER_H

typedef struct _GcaCertificateListener GcaCertificateListener;

#include <bonobo/bonobo-object.h>
#include <gnome-certauth/CertificateAuthentication.h>
#include <gnutls/gnutls.h>

#define GCA_TYPE_CERTIFICATE_LISTENER         (gca_certificate_listener_get_type ())
#define GCA_CERTIFICATE_LISTENER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), GCA_TYPE_CERTIFICATE_LISTENER, GcaCertificateListener))
#define GCA_CERTIFICATE_LISTENER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), GCA_TYPE_CERTIFICATE_LISTENER, GcaCertificateListenerClass))
#define GCA_IS_CERTIFICATE_LISTENER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), GCA_TYPE_CERTIFICATE_LISTENER))
#define GCA_IS_CERTIFICATE_LISTENER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), GCA_TYPE_CERTIFICATE_LISTENER))
#define GCA_CERTIFICATE_LISTENER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GCA_TYPE_CERTIFICATE_LISTENER, GcaCertificateListenerClass))

G_BEGIN_DECLS

typedef struct _GcaCertificateListenerPrivate GcaCertificateListenerPrivate;

struct _GcaCertificateListener {
    BonoboObject parent;

    GcaCertificateListenerPrivate *priv;
};

typedef struct {
    BonoboObjectClass parent;

    POA_GNOME_CertificateAuthentication_CertificateListener__epv epv;

    /* 
     * Implementation
     */
    void (*notify_certificate_presented) (GcaCertificateListener *listener,
                                          int opid,
                                          gnutls_datum_t *certificates,
                                          int ncerts);

    void (*notify_data_signed) (GcaCertificateListener *listener,
                                int opid,
                                gnutls_datum_t *signature);

    /* padding to waste memory */
    void (*_gca_cl_reserved0) (void);
    void (*_gca_cl_reserved1) (void);
    void (*_gca_cl_reserved2) (void);
    void (*_gca_cl_reserved3) (void);
    void (*_gca_cl_reserved4) (void);
    void (*_gca_cl_reserved5) (void);
} GcaCertificateListenerClass;

GType                 gca_certificate_listener_get_type (void);

void gca_certificate_listener_request_certificate (GcaCertificateListener *listener,
                                                   GNOME_CertificateAuthentication_CertificateSource source,
                                                   const gnutls_datum_t *req_ca_rdn_der,
                                                   int nreqs,
                                                   gnutls_datum_t **cert_der_ret,
                                                   int *cert_der_ret_length);

void gca_certificate_listener_sign_data (GcaCertificateListener *listener,
                                         GNOME_CertificateAuthentication_CertificateSource source,
                                         const gnutls_datum_t *cert_der,
                                         const gnutls_datum_t *hash,
                                         gnutls_datum_t *signature);

G_END_DECLS

#endif /* GCA_CERTIFICATE_LISTENER_H */
