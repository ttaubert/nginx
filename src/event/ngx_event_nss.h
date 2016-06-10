
/*
 * Copyright (C) Tim Taubert, Mozilla
 */


#ifndef _NGX_EVENT_NSS_H_INCLUDED_
#define _NGX_EVENT_NSS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "prio.h"

#define NGX_SSL_BUFFER   1
#define NGX_SSL_CLIENT   2
#define NGX_SSL_BUFSIZE  16384
#define NGX_SSL_MAX_SESSION_SIZE  4096

#define NGX_SSL_SSLv2    0x0002
#define NGX_SSL_SSLv3    0x0004
#define NGX_SSL_TLSv1    0x0008
#define NGX_SSL_TLSv1_1  0x0010
#define NGX_SSL_TLSv1_2  0x0020
#define NGX_SSL_TLSv1_3  0x0040

#define NGX_SSL_NO_SCACHE            -2
#define NGX_SSL_NONE_SCACHE          -3
#define NGX_SSL_NO_BUILTIN_SCACHE    -4
#define NGX_SSL_DFLT_BUILTIN_SCACHE  -5

#define ngx_ssl_session_t       void
#define ngx_ssl_conn_t          void


typedef struct {
    PRFileDesc                 *ctx;
    ngx_log_t                  *log;
    size_t                      buffer_size;
} ngx_ssl_t;

typedef struct {
    PRFileDesc                 *ssl_fd;

    /**********************************************/

    ngx_ssl_conn_t             *connection;

    ngx_int_t                   last;
    ngx_buf_t                  *buf;
    size_t                      buffer_size;

    ngx_connection_handler_pt   handler;

    ngx_event_handler_pt        saved_read_handler;
    ngx_event_handler_pt        saved_write_handler;

    unsigned                    handshaked:1;
    unsigned                    renegotiation:1;
    unsigned                    buffer:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    handshake_buffer_set:1;
} ngx_ssl_connection_t;

typedef void X509;
typedef void RSA;

ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);
ngx_int_t ngx_ssl_certificates(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *certs, ngx_array_t *keys, ngx_array_t *passwords);
ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key, ngx_array_t *passwords);
ngx_int_t ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers);

ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
RSA *ngx_ssl_rsa512_key_callback(ngx_ssl_conn_t *ssl_conn, int is_export,
    int key_length);
ngx_array_t *ngx_ssl_read_password_file(ngx_conf_t *cf, ngx_str_t *file);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);
ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout);
ngx_int_t ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_array_t *paths);
ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);

void ngx_ssl_remove_cached_session(/*SSL_CTX*/void *ssl, ngx_ssl_session_t *sess);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
/*SSL_SESSION*/void *ngx_ssl_get_session(/*SSL*/void *ssl);
void ngx_ssl_free_session(/*SSL_SESSION*/void *ses);

#define ngx_ssl_verify_error_optional(n) (true)
ngx_int_t ngx_ssl_check_host(ngx_connection_t *c, ngx_str_t *name);

ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_reused(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_server_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_fingerprint(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);

ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
void ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);

# define X509_V_OK 0
# define SSL_OP_CIPHER_SERVER_PREFERENCE                 0x00400000U
const char *X509_verify_cert_error_string(long n);
long SSL_get_verify_result(const /*SSL*/void *ssl);
/*SSL_SESSION*/void *SSL_get0_session(const /*SSL*/void *ssl);
X509 *SSL_get_peer_certificate(const /*SSL*/void *s);
void X509_free(X509 *cert);
/*SSL_SESSION*/void *d2i_SSL_SESSION(/*SSL_SESSION*/void **a,
                                     unsigned char **pp,
                                     long length);
int i2d_SSL_SESSION(/*SSL_SESSION*/void *in, unsigned char **pp);
int SSL_CTX_set_cipher_list(/*SSL_CTX*/void *ctx, const char *str);
unsigned long SSL_CTX_set_options(/*SSL_CTX*/void *ctx, unsigned long op);
void SSL_CTX_set_tmp_rsa_callback(/*SSL_CTX*/void *ctx,
    RSA *(*tmp_rsa_callback)(/*SSL*/void *ssl, int is_export, int keylength));

#endif /* _NGX_EVENT_NSS_H_INCLUDED_ */
