#include "config.h"

#include "gca-certificate-listener.h"
#include "gca-util.h"

#include <bonobo/bonobo-exception.h>

#include <glib/gthread.h>

#include <stdio.h>

struct _GcaCertificateListenerPrivate {
    int last_opid;
    GSList *ops_list;
    GMutex *ops_lock;
};

/* this file is 100% pure grade-a boilerplate */
static BonoboObjectClass *parent_class = NULL;

typedef struct {
    int opid;
    GMutex *mutex;
    GCond *cond;
    gboolean returned;
} NotifyData;

/* notifydata must be locked */
static void
notify_data_signal (NotifyData *data)
{
    GCA_ENTER;
    data->returned = TRUE;
    GCA_TRACEMSG ("done; signaling...");
    g_cond_signal (data->cond);
    GCA_TRACEMSG ("...and unlocking...");
    g_mutex_unlock (data->mutex);
    GCA_EXIT;
    
}

/* notifydata must not be locked */
static void
notify_orbit_broken (gpointer cnx, gpointer user_data)
{
    NotifyData *data = user_data;
    GCA_ENTER;
    g_mutex_lock (data->mutex);
    GCA_HASLOCK;
    GCA_TRACE ("broken connection for op %d", data->opid);
    notify_data_signal (data);
    GCA_EXIT;
}

/* returns a locked notifydata */
static void
notify_data_init (GcaCertificateListener *listener, 
                  GNOME_CertificateAuthentication_CertificateSource source,
                  NotifyData *data)
{
    GCA_ENTER;
    data->mutex = g_mutex_new ();
    g_mutex_lock (data->mutex);
    GCA_HASLOCK;

    data->cond = g_cond_new ();
    data->returned = FALSE;

    ORBit_small_listen_for_broken (source, G_CALLBACK (notify_orbit_broken), data);

    g_mutex_lock (listener->priv->ops_lock);
    GCA_HASLOCK;
    data->opid = ++listener->priv->last_opid;
    listener->priv->ops_list = g_slist_prepend (listener->priv->ops_list, data);
    g_mutex_unlock (listener->priv->ops_lock);
    GCA_TRACE ("data initialized for op %d", data->opid);
    GCA_EXIT;
}

/* notifydata must be locked */
static void
notify_data_fini (GcaCertificateListener *listener,
                  GNOME_CertificateAuthentication_CertificateSource source,
                  NotifyData *data)
{
    GCA_ENTER;
    g_mutex_lock (listener->priv->ops_lock);
    GCA_HASLOCK;
    listener->priv->ops_list = g_slist_remove (listener->priv->ops_list, data);
    g_mutex_unlock (listener->priv->ops_lock);

    ORBit_small_unlisten_for_broken (source, G_CALLBACK (notify_orbit_broken));

    g_mutex_unlock (data->mutex);

    g_mutex_free (data->mutex);
    g_cond_free (data->cond);
    GCA_EXIT;
}

static gint
ops_list_compare_func (gconstpointer a, gconstpointer b)
{
    return ((const NotifyData *)a)->opid != GPOINTER_TO_INT (b);
}

/* ops_lock must not be locked */
static NotifyData *
listener_find_op_data (GcaCertificateListener *listener, int opid)
{
    GSList *item;
    NotifyData *data = NULL;
    GCA_ENTER;
    g_mutex_lock (listener->priv->ops_lock);
    GCA_HASLOCK;
    item = g_slist_find_custom (listener->priv->ops_list, GINT_TO_POINTER (opid),
                                ops_list_compare_func);
    if (item) {
        data = item->data;
    }
    g_mutex_unlock (listener->priv->ops_lock);
    GCA_EXIT;
    return data;
}

static NotifyData *
corba_find_op_data (PortableServer_Servant servant, int opid)
{
    BonoboObject *obj;
    GcaCertificateListener *listener;
    NotifyData *data;

    GCA_ENTER;
    obj = bonobo_object (servant);
    if (obj == NULL || !GCA_IS_CERTIFICATE_LISTENER (obj)) {
        g_warning ("Could not find listener from servant");
        GCA_EXIT;
        return NULL;
    }

    listener = GCA_CERTIFICATE_LISTENER (obj);
    GCA_TRACEMSG ("have listener, getting data...");

    data = listener_find_op_data (listener, opid);
    GCA_EXIT;
    return data;
}

typedef struct {
    NotifyData data;
    gnutls_datum_t **cert_der_ret;
    int *cert_der_ret_length;
} NotifyCertificatePresentedData;

static void
impl_GNOME_CertificateAuthentication_CertificateListener_notifyCertificatePresented (
    PortableServer_Servant servant,
    const CORBA_long opid,
    const GNOME_CertificateAuthentication_DataList* certificates,
    CORBA_Environment *ev)
{
    NotifyCertificatePresentedData *data;
    int i;
    
    GCA_ENTER;

    data = (NotifyCertificatePresentedData *)corba_find_op_data (servant, opid);

    if (!data) {
        GCA_TRACE ("could not find item for op %d", opid);
        GCA_EXIT;
        return;
    }

    g_mutex_lock (data->data.mutex);
    GCA_HASLOCK;

    GCA_TRACE ("locked data, copying %d certificates...", certificates->_length);

    *data->cert_der_ret_length = certificates->_length;
    *data->cert_der_ret = g_new0 (gnutls_datum_t, certificates->_length);

    for (i = 0; i < certificates->_length; i++) {
        _gca_corba_to_datum_copy (&(*data->cert_der_ret)[i], &certificates->_buffer[i]);
    }

    notify_data_signal (&data->data);
    GCA_EXIT;
}

void
gca_certificate_listener_request_certificate (GcaCertificateListener *listener,
                                              GNOME_CertificateAuthentication_CertificateSource source,
                                              const gnutls_datum_t *req_ca_rdn_der,
                                              int nreqs,
                                              gnutls_datum_t **cert_der_ret,
                                              int *cert_der_ret_length)
{
    CORBA_Environment ev;
    NotifyCertificatePresentedData data;
    GNOME_CertificateAuthentication_DataList corba_cas;
    int i;

    GCA_ENTER;

    notify_data_init (listener, source, &data.data);

    data.cert_der_ret = cert_der_ret;
    data.cert_der_ret_length = cert_der_ret_length;

    corba_cas._length = nreqs;
    corba_cas._buffer = GNOME_CertificateAuthentication_DataList_allocbuf (nreqs);
    corba_cas._release = TRUE;
    for (i = 0; i < nreqs; i++) {
        _gca_datum_to_corba (&corba_cas._buffer[i], &req_ca_rdn_der[i]);
    }

    GCA_TRACEMSG ("locked, making RPC...");

    CORBA_exception_init (&ev);

    GNOME_CertificateAuthentication_CertificateSource_requestCertificate (
        source, (GNOME_CertificateAuthentication_CertificateListener)BONOBO_OBJREF (listener),
        data.data.opid, &corba_cas, &ev);
    
    if (BONOBO_EX (&ev)) {
        GCA_TRACEMSG ("we got a corba error, bailing...");
    } else {
        GCA_TRACEMSG ("till locked, waiting for reply...");
        
        while (!data.data.returned) {
            g_cond_wait (data.data.cond, data.data.mutex);
        }

        GCA_TRACEMSG ("still locked, got a reply");
    }

    GCA_TRACE ("we are returning %d certs!", *cert_der_ret_length);

    notify_data_fini (listener, source, &data.data);

    GNOME_CertificateAuthentication_DataList__freekids (&corba_cas, NULL);
}

typedef struct {
    NotifyData data;
    gnutls_datum_t *signature;
} NotifyDataSignedData;

static void
impl_GNOME_CertificateAuthentication_CertificateListener_notifyDataSigned (
    PortableServer_Servant servant,
    const CORBA_long opid,
    const GNOME_CertificateAuthentication_Data* signature,
    CORBA_Environment *ev)
{
    NotifyDataSignedData *data;
    BonoboObject *obj;

    data = (NotifyDataSignedData *)corba_find_op_data (servant, opid);

    if (!data) {
        GCA_TRACE ("could not find item for op %d", opid);
        return;
    }

    g_mutex_lock (data->data.mutex);

    GCA_TRACE ("locked data, copying %d bytes of signed data...", signature->_length);
    _gca_corba_to_datum_copy (data->signature, signature);
    
    notify_data_signal (&data->data);   
}

void
gca_certificate_listener_sign_data (GcaCertificateListener *listener,
                                    GNOME_CertificateAuthentication_CertificateSource source,
                                    const gnutls_datum_t *cert_der,
                                    const gnutls_datum_t *hash,
                                    gnutls_datum_t *signature)
{
    CORBA_Environment ev;
    NotifyDataSignedData data;
    GNOME_CertificateAuthentication_Data corba_cert;
    GNOME_CertificateAuthentication_Data corba_hash;

    GCA_ENTER;

    notify_data_init (listener, source, &data.data);

    data.signature = signature;

    GCA_TRACEMSG ("locked, making RPC...");

    CORBA_exception_init (&ev);

    GNOME_CertificateAuthentication_CertificateSource_signData (
        source, (GNOME_CertificateAuthentication_CertificateListener)BONOBO_OBJREF (listener),
        data.data.opid,
        _gca_datum_to_corba (&corba_cert, cert_der),
        _gca_datum_to_corba (&corba_hash, hash),
        &ev);
    
    if (BONOBO_EX (&ev)) {
        GCA_TRACEMSG ("we got a corba error, bailing...");
    } else {
        GCA_TRACEMSG ("still locked, waiting for reply...");
        
        while (!data.data.returned) {
            g_cond_wait (data.data.cond, data.data.mutex);
        }

        GCA_TRACEMSG ("still locked, got a reply");
    }

    GCA_TRACE ("we are returning %d signed bytes!", signature->size);

    notify_data_fini (listener, source, &data.data);

    GCA_EXIT;
}

static void
gca_certificate_listener_init (GcaCertificateListener *listener)
{
    GCA_ENTER;
    listener->priv = g_new0 (GcaCertificateListenerPrivate, 1);
    listener->priv->ops_lock = g_mutex_new ();
    GCA_EXIT;
}

static void
gca_certificate_listener_dispose (GObject *object)
{
    GcaCertificateListener *listener = GCA_CERTIFICATE_LISTENER (object);
    GCA_ENTER;
    if (listener->priv) {
        g_mutex_free (listener->priv->ops_lock);
        listener->priv->ops_lock = NULL;

        g_free (listener->priv);
        listener->priv = NULL;
    }
    
    G_OBJECT_CLASS (parent_class)->dispose (object);
    GCA_EXIT;
}

static void
gca_certificate_listener_class_init (GcaCertificateListenerClass *klass)
{
    GCA_ENTER;
    parent_class = g_type_class_ref (BONOBO_TYPE_OBJECT);

    G_OBJECT_CLASS (klass)->dispose = gca_certificate_listener_dispose;

    klass->epv.notifyCertificatePresented = impl_GNOME_CertificateAuthentication_CertificateListener_notifyCertificatePresented;
    klass->epv.notifyDataSigned = impl_GNOME_CertificateAuthentication_CertificateListener_notifyDataSigned;
    GCA_EXIT;
}

BONOBO_TYPE_FUNC_FULL (GcaCertificateListener,
                       GNOME_CertificateAuthentication_CertificateListener,
                       BONOBO_TYPE_OBJECT,
                       gca_certificate_listener);
