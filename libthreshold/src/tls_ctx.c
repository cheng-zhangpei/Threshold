#include "tls_ctx.h"
#include "config.h"
#include <stdio.h>
#include <openssl/err.h>

static SSL_CTX *g_ssl_ctx = NULL;

int tls_ctx_init(void) {
    threshold_config_t *cfg = config_get();

    /* TLS 1.2+ 瀹㈡埛绔柟娉?*/
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        fprintf(stderr, "[threshold] SSL_CTX_new failed\n");
        return -1;
    }

    /* 鏈€浣庣増鏈?*/
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);

    /* 鍔犺浇 CA 璇佷功锛堢敤浜庨獙璇佹湇鍔＄璇佷功锛?*/
    if (SSL_CTX_load_verify_locations(g_ssl_ctx, cfg->ca_cert_path, NULL) != 1) {
        fprintf(stderr, "[threshold] Failed to load CA cert: %s\n",
                cfg->ca_cert_path);
        /* 鍘熷瀷闃舵锛氬姞杞藉け璐ヤ笉闃绘柇锛屼粎璀﹀憡 */
        /* 鐢熶骇闃舵搴旇繑鍥?-1 */
    }

    /* 寮€鍚湇鍔＄璇佷功楠岃瘉 */
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);

    return 0;
}

SSL *tls_connect(int fd) {
    if (!g_ssl_ctx) return NULL;

    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) return NULL;

    SSL_set_fd(ssl, fd);

    /* 璁剧疆 SNI锛圫erver Name Indication锛?/
    threshold_config_t *cfg = config_get();
    SSL_set_tlsext_host_name(ssl, cfg->proxy_host);

    /* 鎵ц TLS 鎻℃墜 */
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "[threshold] TLS handshake failed: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}
