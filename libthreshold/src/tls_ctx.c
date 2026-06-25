#include "tls_ctx.h"
#include "config.h"
#include <stdio.h>
#include <openssl/err.h>

static SSL_CTX *g_ssl_ctx = NULL;

int tls_ctx_init(void) {
    threshold_config_t *cfg = config_get();

    /* TLS 1.2+ 客户端方法 */
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        fprintf(stderr, "[threshold] SSL_CTX_new failed\n");
        return -1;
    }

    /* 最低版本 */
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);

    /* ─── 加载 CA 证书（验证服务端证书）─── */
    if (cfg->ca_cert_path[0] != '\0') {
        if (SSL_CTX_load_verify_locations(g_ssl_ctx, cfg->ca_cert_path, NULL) == 1) {
            /* CA 加载成功，启用服务端证书验证 */
            SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
            fprintf(stderr, "[threshold] TLS: server cert verification enabled (CA=%s)\n",
                    cfg->ca_cert_path);
        } else {
            /* CA 加载失败，降级为不验证 */
            fprintf(stderr, "[threshold] WARN: failed to load CA cert: %s\n",
                    cfg->ca_cert_path);
            ERR_print_errors_fp(stderr);
            SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        }
    } else {
        /* 没有配置 CA 路径，降级为不验证 */
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        fprintf(stderr, "[threshold] TLS: no CA cert configured, server verification disabled\n");
    }

    /* ─── 加载客户端证书 + 私钥（mTLS，向服务端证明身份）─── */
    int mtls_ok = 0;

    if (cfg->client_cert_path[0] != '\0' && cfg->client_key_path[0] != '\0') {
        /* 加载客户端证书 */
        if (SSL_CTX_use_certificate_file(g_ssl_ctx, cfg->client_cert_path,
                                         SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "[threshold] WARN: failed to load client cert: %s\n",
                    cfg->client_cert_path);
            ERR_print_errors_fp(stderr);
            goto no_client_cert;
        }

        /* 加载客户端私钥 */
        if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, cfg->client_key_path,
                                         SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "[threshold] WARN: failed to load client key: %s\n",
                    cfg->client_key_path);
            ERR_print_errors_fp(stderr);
            goto no_client_cert;
        }

        /* 验证私钥和证书是否匹配 */
        if (SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
            fprintf(stderr, "[threshold] WARN: client cert and key do not match\n");
            ERR_print_errors_fp(stderr);
            goto no_client_cert;
        }

        mtls_ok = 1;
        fprintf(stderr, "[threshold] TLS: mTLS enabled (cert=%s)\n",
                cfg->client_cert_path);

    no_client_cert:
        if (!mtls_ok) {
            /* 证书加载失败，继续（降级为单向 TLS） */
            fprintf(stderr, "[threshold] TLS: falling back to one-way TLS\n");
        }
    } else {
        fprintf(stderr, "[threshold] TLS: no client cert configured, one-way TLS\n");
    }

    return 0;
}

SSL *tls_connect(int fd) {
    if (!g_ssl_ctx) return NULL;

    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) return NULL;

    SSL_set_fd(ssl, fd);

    /* 设置 SNI（Server Name Indication） */
    threshold_config_t *cfg = config_get();
    SSL_set_tlsext_host_name(ssl, cfg->proxy_host);

    /* 执行 TLS 握手 */
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "[threshold] TLS handshake failed: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

void tls_ctx_cleanup(void) {
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}