
/*
 * Copyright (C) Tim Taubert, Mozilla
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ssl.h"
#include "sslproto.h"


// Cipher suite attributes.
#define SSL_eNULL 0x01
#define SSL_aNULL 0x02

typedef enum {
    ngx_nss_cipher_action_permanently_disable = 0, /* !CIPHER */
    ngx_nss_cipher_action_subtract,                /* -CIPHER */
    ngx_nss_cipher_action_enable,                  /*  CIPHER */
    ngx_nss_cipher_action_reorder                  /* +CIPHER */
} ngx_nss_cipher_action_e;

typedef struct {
    PRUint16 id;
    const char *name;
    PRInt32 attr;
} ngx_nss_cipher_info_t;

// The list of available cipher suites. Order doesn't matter, NSS currently
// doesn't allow reordering cipher suites, and so the order is hardcoded.
const ngx_nss_cipher_info_t cipher_suites[] = {
    { TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "ECDHE-ECDSA-AES128-GCM-SHA256", 0 },
    { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "ECDHE-RSA-AES128-GCM-SHA256", 0 },
    { TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        "ECDHE-ECDSA-CHACHA20-POLY1305", 0 },
    { TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        "ECDHE-RSA-CHACHA20-POLY1305", 0 },
    { TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "ECDHE-ECDSA-AES256-GCM-SHA384", 0 },
    { TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "ECDHE-RSA-AES256-GCM-SHA384", 0 }
};

size_t num_cipher_suites = sizeof(cipher_suites) / sizeof(cipher_suites[0]);


// Disable all implemented cipher suites.
void
ngx_nss_disable_all_ciphers(ngx_ssl_t *ssl)
{
    const PRUint16 *cipherSuites = SSL_ImplementedCiphers;

    for (int i = 0; i < SSL_NumImplementedCiphers; i++) {
        PRUint16 suite = cipherSuites[i];
        if (SSL_CipherPrefSet(ssl->ctx, suite, SSL_NOT_ALLOWED) != SECSuccess) {
            ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0,
                "Failed to disable suite '%d'", suite);
        }
    }
}

// Initialize cipher suite actions.
void
ngx_nss_init_actions(ngx_ssl_t *ssl, ngx_nss_cipher_action_e *actions)
{
    SECStatus rv;
    SSLCipherSuiteInfo def;

    for (size_t i = 0; i < num_cipher_suites; i++) {
        rv = SSL_GetCipherSuiteInfo(cipher_suites[i].id, &def, sizeof(def));

        // Disable all cipher suites by default. Permanently disable
        // all cipher suites listed above, but not available in NSS.
        actions[i] = (rv == SECSuccess) ?
            ngx_nss_cipher_action_subtract :
            ngx_nss_cipher_action_permanently_disable;
    }
}


// Update a cipher suite action.
void
ngx_nss_update_cipher_action(ngx_nss_cipher_action_e *actions, size_t index,
    ngx_nss_cipher_action_e action)
{
    // NSS currently doesn't support cipher suite reordering.
    if (action == ngx_nss_cipher_action_reorder) {
        return;
    }

    // Update the action as long as the suite isn't permanently disabled.
    if (actions[index] != ngx_nss_cipher_action_permanently_disable) {
        actions[index] = action;
    }
}


// Set available cipher suites.
ngx_int_t
ngx_ssl_ciphers(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers)
{
    ngx_nss_cipher_action_e actions[SSL_NumImplementedCiphers];
    ngx_nss_cipher_action_e action;

    char *list = (char *)ciphers->data;
    char *cipher = list;

    printf(" >>> ngx_ssl_ciphers [done]\n");

    // Disable all cipher suites.
    ngx_nss_disable_all_ciphers(ssl);

    // Initialize cipher suite actions.
    ngx_nss_init_actions(ssl, actions);

    while (list && strlen(list)) {
        while ((*cipher) && (isspace(*cipher))) {
            ++cipher;
        }

        // Default to enable a cipher, if listed.
        action = ngx_nss_cipher_action_enable;

        switch (*cipher) {

        case '+':
            // Cipher ordering is not yet supported by NSS.
            action = ngx_nss_cipher_action_reorder;
            cipher++;
            break;
        case '-':
            // Disable the given cipher.
            action = ngx_nss_cipher_action_subtract;
            cipher++;
            break;
        case '!':
            // Permanently disable the given cipher.
            action = ngx_nss_cipher_action_permanently_disable;
            cipher++;
            break;
        default:
            // Enable the given cipher.
            break;
        }

        if ((list = strchr(cipher, ':'))) {
            *list++ = '\0';
        }

        if (!strcmp(cipher, "@STRENGTH")) {
            ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0,
                "NSS does not support @STRENGTH as reordering ciphers is \
                 currently not implemented");
            return NGX_ERROR;
        }

        // TODO
        if (!strcmp(cipher, "DEFAULT")) {
            if ((char *)ciphers->data < cipher) {
                ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0,
                    "'DEFAULT' must be the first cipher string, if specified");
                return NGX_ERROR;
            }

            if (action != ngx_nss_cipher_action_enable) {
                ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0,
                    "'DEFAULT' cannot have a modifier prefix");
                return NGX_ERROR;
            }

            for (size_t i = 0; i < num_cipher_suites; i++) {
                // DEFAULT = ALL:!aNULL:!eNULL
                if (!(cipher_suites[i].attr & (SSL_eNULL | SSL_aNULL))) {
                    ngx_nss_update_cipher_action(actions, i, action);
                }
            }
        }

        if (!strcmp(cipher, "ALL")) {
            for (size_t i = 0; i < num_cipher_suites; i++) {
                // Update all encrypted cipher suites.
                if (!(cipher_suites[i].attr & SSL_eNULL)) {
                    ngx_nss_update_cipher_action(actions, i, action);
                }
            }
        }

        if (!strcmp(cipher, "COMPLEMENTOFALL")) {
            for (size_t i = 0; i < num_cipher_suites; i++) {
                // Update all unencrypted cipher suites.
                if (!(cipher_suites[i].attr & SSL_eNULL)) {
                    ngx_nss_update_cipher_action(actions, i, action);
                }
            }
        }

        printf(" >>>   cipher=<%s>\n", cipher);

        // TODO support @SECLEVEL=n
        // TODO support SHA1+DES

        if (list) {
            cipher = list;
        }
    }

    // Enable a single cipher. TODO
    if (SSL_CipherPrefSet(ssl->ctx, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, SSL_ALLOWED) != SECSuccess) {
        ngx_ssl_error(NGX_LOG_ALERT, ssl->log, 0, "SSL_CipherPrefSet() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}
