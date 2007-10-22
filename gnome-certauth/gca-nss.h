#ifndef GCA_NSS_H
#define GCA_NSS_H

#include <gnutls/gnutls.h>

int gca_nss_request_certificate (const gnutls_datum_t *req_ca_rdn,
                                 int nreqs,
                                 gnutls_datum_t **cert_ret,
                                 int *cert_ret_length);

int gca_nss_sign_data (const gnutls_datum_t *cert,
                       const gnutls_datum_t *hash,
                       gnutls_datum_t *signature);

#endif /* GCA_NSS_H */
