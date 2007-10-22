#ifndef GCA_NSS_CERTIFICATE_SOURCE_H
#define GCA_NSS_CERTIFICATE_SOURCE_H

typedef struct _GcaNssCertificateSource GcaNssCertificateSource;

#include <gnome-certauth/gca-certificate-source.h>

#define GCA_TYPE_NSS_CERTIFICATE_SOURCE         (gca_nss_certificate_source_get_type ())
#define GCA_NSS_CERTIFICATE_SOURCE(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), GCA_TYPE_NSS_CERTIFICATE_SOURCE, GcaNssCertificateSource))
#define GCA_NSS_CERTIFICATE_SOURCE_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), GCA_TYPE_NSS_CERTIFICATE_SOURCE, GcaNssCertificateSource))
#define GCA_IS_NSS_CERTIFICATE_SOURCE(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), GCA_TYPE_NSS_CERTIFICATE_SOURCE))
#define GCA_IS_NSS_CERTIFICATE_SOURCE_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), GCA_TYPE_NSS_CERTIFICATE_SOURCE))
#define GCA_NSS_CERTIFICATE_SOURCE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), GCA_TYPE_NSS_CERTIFICATE_SOURCE, GcaNssCertificateSourceClass))

G_BEGIN_DECLS

typedef struct _GcaNssCertificateSourcePrivate GcaNssCertificateSourcePrivate;

typedef struct _GcaNssCertificateSource {
    GcaCertificateSource parent;

    GcaNssCertificateSourcePrivate *priv;
};

typedef struct {
    GcaCertificateSourceClass parent;

    /* padding to waste memory */
    void (*_gca_cs_reserved0) (void);
    void (*_gca_cs_reserved1) (void);
    void (*_gca_cs_reserved2) (void);
    void (*_gca_cs_reserved3) (void);
    void (*_gca_cs_reserved4) (void);
    void (*_gca_cs_reserved5) (void);
} GcaNssCertificateSourceClass;

GType                 gca_nss_certificate_source_get_type (void);

G_END_DECLS

#endif /* GCA_NSS_CERTIFICATE_SOURCE_H */
