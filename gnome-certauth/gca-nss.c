/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

/* Copyright (C) 2007 Novell, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/* The following is the mozilla license blurb, as the bodies of most
   of these functions were derived from the mozilla source. */

/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "gca-nss.h"

#ifdef HAVE_NSS
#include "gca-util.h"

#include <glib/gi18n.h>
#include <glib/gstrfuncs.h>

#include <nss.h>
#include <cert.h>
#include <pk11pub.h>
#include <pk11priv.h>
#include <secerr.h>
#include <prerror.h>
#include <prinit.h>
#include <keyhi.h>

/* this is mostly taken from nss... */

extern CERTCertificate *__CERT_DecodeDERCertificate (SECItem *derSignedCert, PRBool copyDER, char *nickname);

CERTDistNames *
get_dist_names (const gnutls_datum_t *req_ca_rdn, int nreqs)
{
	CERTDistNames *dnames = NULL;
	PRArenaPool *arena = NULL;
	int i;

	arena = PORT_NewArena (DER_DEFAULT_CHUNKSIZE);
	if (!arena) goto i_has_a_error;

	dnames = PORT_ArenaZNew (arena, CERTDistNames);
	if (!dnames) goto i_has_a_error;

	dnames->names = (SECItem *)PORT_ArenaAlloc (arena, nreqs * sizeof (SECItem));
	if (!dnames->names) goto i_has_a_error;

	dnames->arena = arena;
	dnames->head = NULL;
	dnames->nnames = nreqs;
	
	for (i = 0; i < nreqs; i++) {
		_gca_datum_to_item_copy (arena, &dnames->names[i], &req_ca_rdn[i]);
	}

	return dnames;

i_has_a_error:
	if (arena) {
		PORT_FreeArena (arena, PR_FALSE);
	}
	return NULL;

}
#endif /* HAVE_NSS */

int
gca_nss_request_certificate (const gnutls_datum_t *req_ca_rdn_der,
			     int nreqs,
			     gnutls_datum_t **cert_der_ret,
			     int *cert_der_ret_length)
{
#ifdef HAVE_NSS
	CERTCertNicknames *names = NULL;
	CERTCertificate *cert = NULL;
	CERTCertificateList *chain = NULL;
	CERTDistNames *caNames = NULL;
	SECKEYPrivateKey *privKey = NULL;
	SECStatus secStatus;
	int i;
	int ret;

	caNames = get_dist_names (req_ca_rdn_der, nreqs);
	if (!caNames) goto i_has_a_error;

	names = CERT_GetCertNicknames(CERT_GetDefaultCertDB(), 
				      SEC_CERT_NICKNAMES_USER, NULL);
	if (!names) goto i_has_a_error;

	for (i = 0; i < names->numnicknames; i++ ) {
		cert = PK11_FindCertFromNickname(names->nicknames[i],  NULL);
		if (!cert) {
			continue;
		}
			
		/* Only check unexpired certs */
		if (CERT_CheckCertValidTimes(cert, PR_Now(), PR_FALSE)
		    != secCertTimeValid ) {
			CERT_DestroyCertificate(cert);
			continue;
		}
			
		if (NSS_CmpCertChainWCANames(cert, caNames)
		    != SECSuccess) {
			CERT_DestroyCertificate(cert);
			continue;
		}

		privKey = PK11_FindKeyByAnyCert(cert, NULL);
		if (!privKey) {
			CERT_DestroyCertificate(cert);
			continue;
		}

		SECKEY_DestroyPrivateKey (privKey);
		break;
	} /* for loop */
	CERT_FreeNicknames(names);
	
	if (cert == NULL) {
		GCA_TRACEMSG("after all that... no cert");
		goto i_has_a_error;
	}

	chain = CERT_CertChainFromCert (cert, certUsageSSLClient, PR_TRUE);
	if (chain == NULL) {
		goto i_has_a_error;
	}

	*cert_der_ret_length = chain->len;
	*cert_der_ret = gnutls_malloc (sizeof (gnutls_datum_t) * chain->len);

	GCA_TRACE("returning %d certs!", chain->len);

	for (i = 0; i < chain->len; i++) {
		_gca_item_to_datum_copy (&(*cert_der_ret)[i], &chain->certs[i]);
	}

	ret = 0;
	goto done;	
	
i_has_a_error:
	ret = -1;

done:
	if (caNames) {
		CERT_FreeDistNames (caNames);
	}
	if (chain != NULL) {
		CERT_DestroyCertificateList (chain);
	}
	if (cert != NULL) {
		CERT_DestroyCertificate (cert);
	}

	return ret;
#else /* !HAVE_NSS */
        return 0;
#endif /* !HAVE_NSS */
}

int
gca_nss_sign_data (const gnutls_datum_t *cert_der,
		   const gnutls_datum_t *hash_data,
		   gnutls_datum_t *sig_data)
{
#ifdef HAVE_NSS
	CERTCertificate *cert;
	SECKEYPrivateKey *privKey;
	SECItem cert_item, hash_item, sig_item;
	SECStatus rv;

	cert = __CERT_DecodeDERCertificate (_gca_datum_to_item (&cert_item, cert_der),
                                            PR_FALSE, NULL);
	if (cert == NULL) {
		return -1;
	}

	privKey = PK11_FindKeyByAnyCert (cert, NULL);
	if (privKey == NULL) {
		return -1;
	}

	printf ("- Sign callback: %p %p %p\n", cert, hash_data, sig_data);

	sig_data->size = PK11_SignatureLen (privKey);
	sig_data->data = g_malloc (sig_data->size);

	rv = PK11_Sign (privKey,
			_gca_datum_to_item (&sig_item, sig_data),
			_gca_datum_to_item (&hash_item, hash_data));

	CERT_DestroyCertificate (cert);
	SECKEY_DestroyPrivateKey (privKey);

	if (rv != SECSuccess) {
		fprintf (stderr, " *** Error signing\n");
	} else {
		printf (" - Signing OK!\n");
	}

	return rv == SECSuccess ? 0 : -1;
#else /* !HAVE_NSS */
        return 0;
#endif /* !HAVE_NSS */
}
