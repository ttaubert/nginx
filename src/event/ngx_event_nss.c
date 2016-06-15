
/*
 * Copyright (C) Tim Taubert, Mozilla
 */

// certutil -A -n mycert -t ,, -i ~/server.crt -d sql:/Users/tim/nginx-test/nssdb
// openssl pkcs12 -export -in ~/server.crt -inkey ~/server.key -out ~/server.p12 -name "mycert"
// pk12util -i ~/server.p12 -d sql:/Users/tim/nginx-test/nssdb

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "private/pprio.h"
#include "nspr.h"
#include "nss.h"
#include "ssl.h"
#include "sslproto.h"
#include "pk11func.h"
#include "keyhi.h"

static void *ngx_nss_create_conf(ngx_cycle_t *cycle);
static char *ngx_nss_certificate_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_nss_exit(ngx_cycle_t *cycle);

ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ngx_chain_t * ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

ngx_int_t ngx_nss_set_version_range(ngx_ssl_t *ssl, ngx_uint_t protocols);

typedef struct {
    ngx_str_t        certdb;
} ngx_nss_conf_t;

static ngx_command_t  ngx_nss_commands[] = {

    { ngx_string("ssl_certificate_db"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_nss_certificate_db,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_nss_module_ctx = {
    ngx_string("nss"),
    ngx_nss_create_conf,
    NULL
};


ngx_module_t  ngx_nss_module = {
    NGX_MODULE_V1,
    &ngx_nss_module_ctx,                   /* module context */
    ngx_nss_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_nss_exit,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/*****************************************************************************/

// Initialize the module.
ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    printf(" >>> ngx_ssl_init [done]\n");

    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    return NGX_OK;
}

// Unload the module.
static void
ngx_nss_exit(ngx_cycle_t *cycle)
{
    NSS_Shutdown();
    PR_Cleanup();
}

/*****************************************************************************/

// Create an empty NGINX configuration object.
static void *
ngx_nss_create_conf(ngx_cycle_t *cycle)
{
    printf(" >>> ngx_nss_create_conf [done]\n");
    return ngx_pcalloc(cycle->pool, sizeof(ngx_nss_conf_t));
}

// Read the cert DB.
static char *
ngx_nss_certificate_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t        *value = cf->args->elts;
    printf(" >>> ngx_nss_certificate_db [done]\n");

    if (NSS_IsInitialized()) {
        return "is duplicate";
    }

    if (NSS_Initialize((const char *)value[1].data, "", "", "", NSS_INIT_READONLY) != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, cf->log, 0, "NSS_Initialize() failed");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

// Create a context.
ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
{
    printf(" >>> ngx_ssl_create [done]\n");

    if (!NSS_IsInitialized()) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "No ssl_certificate_db directive given");
        return NGX_ERROR;
    }

    if (NSS_SetDomesticPolicy() != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "NSS_SetDomesticPolicy() failed");
        return NGX_ERROR;
    }

    ssl->ctx = PR_NewTCPSocket();

    if (ssl->ctx == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "PR_NewTCPSocket() failed");
        return NGX_ERROR;
    }

    ssl->ctx = SSL_ImportFD(NULL, ssl->ctx);

    if (ssl->ctx == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "SSL_ImportFD() failed");
        return NGX_ERROR;
    }

    if (SSL_OptionSet(ssl->ctx, SSL_SECURITY, 1) != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "SSL_OptionSet(SSL_SECURITY) failed");
        return NGX_ERROR;
    }

    if (ngx_nss_set_version_range(ssl, protocols) != NGX_OK) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "ngx_nss_set_version_range() failed");
        return NGX_ERROR;
    }

    ssl->buffer_size = NGX_SSL_BUFSIZE;

    return NGX_OK;
}

ngx_int_t
ngx_nss_set_version_range(ngx_ssl_t *ssl, ngx_uint_t protocols)
{
    SSLVersionRange versions = { SSL_LIBRARY_VERSION_TLS_1_3, 0 };

    if (!protocols) {
        return NGX_OK;
    }

    // No SSLv2 support in NSS.
    if (protocols & NGX_SSL_SSLv2) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "No SSLv2 support");
        return NGX_ERROR;
    }

    // The TLS v1.3 spec section C.4 states that 'Implementations MUST NOT send
    // or accept any records with a version less than { 3, 0 }'. Thus NSS does
    // not allow version ranges including both SSLv3 and TLSv1.3.
    if ((protocols & NGX_SSL_SSLv3) && (protocols & NGX_SSL_TLSv1_3)) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "TLSv1.3 servers do not support SSLv3");
        return NGX_ERROR;
    }

    if (protocols & NGX_SSL_SSLv3) {
        versions.min = SSL_LIBRARY_VERSION_3_0;
    }
    if (protocols & NGX_SSL_TLSv1) {
        versions.min = ngx_min(versions.min, SSL_LIBRARY_VERSION_TLS_1_0);
        versions.max = SSL_LIBRARY_VERSION_TLS_1_0;
    }
    if (protocols & NGX_SSL_TLSv1_1) {
        versions.min = ngx_min(versions.min, SSL_LIBRARY_VERSION_TLS_1_1);
        versions.max = SSL_LIBRARY_VERSION_TLS_1_1;
    }
    if (protocols & NGX_SSL_TLSv1_2) {
        versions.min = ngx_min(versions.min, SSL_LIBRARY_VERSION_TLS_1_2);
        versions.max = SSL_LIBRARY_VERSION_TLS_1_2;
    }
    if (protocols & NGX_SSL_TLSv1_3) {
        versions.min = ngx_min(versions.min, SSL_LIBRARY_VERSION_TLS_1_3);
        versions.max = SSL_LIBRARY_VERSION_TLS_1_3;
    }

    if (SSL_VersionRangeSet(ssl->ctx, &versions) != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "SSL_VersionRangeSet() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

// Clean up a context.
void
ngx_ssl_cleanup_ctx(void *data)
{
    printf(" >>> ngx_ssl_cleanup_ctx [done]\n");
    ngx_ssl_t *ssl = data;
    PR_Close(ssl->ctx);
}

// Import certificates.
ngx_int_t
ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *certs,
    ngx_array_t *keys, ngx_array_t *passwords)
{
    printf(" >>> ngx_ssl_certificates [done]\n");
    ngx_str_t   *cert, *key;
    ngx_uint_t   i;

    cert = certs->elts;
    key = keys->elts;

    for (i = 0; i < certs->nelts; i++) {
        if (ngx_ssl_certificate(cf, ssl, &cert[i], &key[i], passwords) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

// Import a single certificate.
ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key, ngx_array_t *passwords)
{
    CERTCertificate *nssCert;
    SECKEYPrivateKey *nssKey;

    printf(" >>> ngx_ssl_certificate [cert=%s, key=%s]\n", cert->data, key->data);

    nssCert = PK11_FindCertFromNickname((const char *)cert->data, NULL);
    if (nssCert == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "PK11_FindCertFromNickname() failed");
        return NGX_ERROR;
    }

    nssKey = PK11_FindKeyByAnyCert(nssCert, NULL);
    if (nssKey == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "PK11_FindKeyByAnyCert() failed");
        return NGX_ERROR;
    }

    if (SSL_ConfigServerCert(ssl->ctx, nssCert, nssKey, NULL, 0) != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "SSL_ConfigServerCert() failed");
        return NGX_ERROR;
    }

    SECKEY_DestroyPrivateKey(nssKey);
    CERT_DestroyCertificate(nssCert);

    return NGX_OK;
}

ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    printf(" >>> ngx_ssl_trusted_certificate [done]\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    printf(" >>> ngx_ssl_crl [done]\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    printf(" >>> ngx_ssl_dhparam [done]\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
{
    printf(" >>> ngx_ssl_ecdh_curve [done]\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout)
{
    printf(" >>> ngx_ssl_session_cache [done]\n");

    if (SSL_ConfigServerSessionIDCache(0, 0, 0, NULL) != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "SSL_ConfigServerSessionIDCache() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
{
    printf(" >>> ngx_ssl_session_ticket_keys [done]\n");
    return NGX_OK;
}

/*****************************************************************************/

ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c, ngx_uint_t flags)
{
    ngx_ssl_connection_t  *sc;
    PRFileDesc            *tcp_sock;

    printf(" >>> ngx_ssl_create_connection [done]\n");
    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    tcp_sock = PR_ImportTCPSocket(c->fd);

    if (tcp_sock == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PR_ImportTCPSocket() failed");
        return NGX_ERROR;
    }

    sc->ssl_fd = SSL_ImportFD(ssl->ctx, tcp_sock);

    if (sc->ssl_fd == NULL) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_ImportFD() failed");
        return NGX_ERROR;
    }

    SSL_ResetHandshake(sc->ssl_fd, !(flags & NGX_SSL_CLIENT));

    c->ssl = sc;

    return NGX_OK;
}

ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    printf(" >>> ngx_ssl_shutdown [done]\n");

    if (PR_Shutdown(c->ssl->ssl_fd, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PR_Shutdown() failed");
        return NGX_ERROR;
    }

    PR_Close(c->ssl->ssl_fd);

    c->ssl = NULL;

    return NGX_OK;
}

/*****************************************************************************/

ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    printf(" >>> ngx_ssl_handshake [done]\n");

    if (SSL_ForceHandshake(c->ssl->ssl_fd) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_ForceHandshake() failed with error %d: %s", err, PR_ErrorToName(err));
        return NGX_ERROR;
    }

    c->ssl->handshaked = 1;

    c->recv = ngx_ssl_recv;
    c->send = ngx_ssl_write;
    c->recv_chain = ngx_ssl_recv_chain;
    c->send_chain = ngx_ssl_send_chain;

    return NGX_OK;
}

ngx_chain_t *
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int          n;
    printf(" >>> ngx_ssl_send_chain [done]\n");

    // rv = PR_Writev(ssl_sock, iovs, numIOVs, PR_INTERVAL_NO_TIMEOUT); TODO

    while (in) {
        if (ngx_buf_special(in->buf)) {
            in = in->next;
            continue;
        }

        n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            return in;
        }

        in->buf->pos += n;

        if (in->buf->pos == in->buf->last) {
            in = in->next;
        }
    }

    return in;
}

ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
{
    u_char     *last;
    ssize_t     n, bytes, size;
    ngx_buf_t  *b;

    printf(" >>> ngx_ssl_recv_chain [done]\n");

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {
        size = b->end - last;

        if (limit) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        n = ngx_ssl_recv(c, last, size);

        if (n > 0) {
            last += n;
            bytes += n;

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == NGX_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}

ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    printf(" >>> ngx_ssl_recv [done]\n");

    int n = PR_Read(c->ssl->ssl_fd, buf, size);

    if (n < 0) {
        const PRErrorCode err = PR_GetError();
        printf("error: PR_Read error %d: %s\n", err, PR_ErrorToName(err));
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PR_Read() failed with n=%d", n);
    } else {
        printf(" >>>   read <%s>\n", buf);
    }

    return n;
}

ssize_t
ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    printf(" >>> ngx_ssl_write [done]\n");

    int n = PR_Write(c->ssl->ssl_fd, data, size);

    if (n < 0) {
        const PRErrorCode err = PR_GetError();
        printf("error: PR_Read error %d: %s\n", err, PR_ErrorToName(err));
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "PR_Read() failed with n=%d", n);
    } else {
        printf(" >>>   wrote <%s>\n", data);
    }

    return n;
}

/*****************************************************************************/

RSA *
ngx_ssl_rsa512_key_callback(ngx_ssl_conn_t *ssl_conn, int is_export,
    int key_length)
{
    printf(" >>> ngx_ssl_rsa512_key_callback\n");
    return NULL;
}

ngx_array_t *
ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file)
{
    printf(" >>> ngx_ssl_read_password_file\n");
    return NULL;
}

ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    printf(" >>> ngx_ssl_client_certificate\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    printf(" >>> ngx_ssl_session_cache_init\n");
    return NGX_OK;
}

void
ngx_ssl_remove_cached_session(/*SSL_CTX*/void *ssl, ngx_ssl_session_t *sess)
{
    printf(" >>> ngx_ssl_remove_cached_session\n");
}

ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    printf(" >>> ngx_ssl_set_session\n");
    return NGX_OK;
}

/*SSL_SESSION*/void *ngx_ssl_get_session(/*SSL*/void *ssl)
{
    printf(" >>> ngx_ssl_get_session\n");
    return NULL;
}

void ngx_ssl_free_session(/*SSL_SESSION*/void *ses)
{
    printf(" >>> ngx_ssl_free_session\n");
}

ngx_int_t
ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name)
{
    printf(" >>> ngx_ssl_check_host\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_protocol\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_cipher_name\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_session_id\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_session_reused\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_server_name\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_raw_certificate\n");
    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_certificate\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_subject_dn\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_issuer_dn\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_serial_number\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_fingerprint\n");
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    printf(" >>> ngx_ssl_get_client_verify\n");
    return NGX_OK;
}

void
ngx_ssl_free_buffer(ngx_connection_t *c)
{
    printf(" >>> ngx_ssl_free_buffer\n");
}

void ngx_cdecl
ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
{
    u_char      *p, *last;
    va_list      args;
    u_char       errstr[NGX_MAX_CONF_ERRSTR] = { 0 };

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    printf(" >>> ngx_ssl_error [%s]\n", errstr);
    ngx_log_error(level, log, err, "SSL/NSS: %s", errstr);
}

ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
    ngx_str_t *responder, ngx_uint_t verify)
{
    printf(" >>> ngx_ssl_stapling\n");
    return NGX_OK;
}

ngx_int_t
ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{
    printf(" >>> ngx_ssl_stapling_resolver\n");
    return NGX_OK;
}

const char *X509_verify_cert_error_string(long n) { return NULL; };
long SSL_get_verify_result(const /*SSL*/void *ssl) { return X509_V_OK; }
/*SSL_SESSION*/void *SSL_get0_session(const /*SSL*/void *ssl) { return NULL; }
X509 *SSL_get_peer_certificate(const /*SSL*/void *s) { return NULL; }
void X509_free(X509 *cert) { }
/*SSL_SESSION*/void *d2i_SSL_SESSION(/*SSL_SESSION*/void **a,
                                     unsigned char **pp,
                                     long length) { return NULL; }
int i2d_SSL_SESSION(/*SSL_SESSION*/void *in, unsigned char **pp) { return 0; }
int SSL_CTX_set_cipher_list(/*SSL_CTX*/void *ctx, const char *str) { return 0; }
unsigned long SSL_CTX_set_options(/*SSL_CTX*/void *ctx, unsigned long op) { return 0; }
void SSL_CTX_set_tmp_rsa_callback(/*SSL_CTX*/void *ctx,
    RSA *(*tmp_rsa_callback)(/*SSL*/void *ssl, int is_export, int keylength)) { }
