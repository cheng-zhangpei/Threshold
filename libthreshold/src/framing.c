#include "framing.h"
#include "protocol.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  /* htonl / ntohl */

/* 鍐呴儴杈呭姪锛氱‘淇?SSL_read 璇绘弧 n 瀛楄妭 */
static int ssl_read_full(SSL *ssl, void *buf, int n) {
    int total = 0;
    while (total < n) {
        int r = SSL_read(ssl, (char *)buf + total, n - total);
        if (r <= 0) return -1;   /* 杩炴帴鍏抽棴鎴栭敊璇?*/
        total += r;
    }
    return 0;
}

int frame_send(SSL *ssl, const void *payload, uint32_t len) {
    /* 鍐?4 瀛楄妭闀垮害鍓嶇紑锛堝ぇ绔簭锛?*/
    uint32_t net_len = htonl(len);
    if (SSL_write(ssl, &net_len, 4) != 4)
        return -1;
    /* 鍐?payload */
    if (len > 0) {
        if (SSL_write(ssl, payload, (int)len) != (int)len)
            return -1;
    }
    return 0;
}

int frame_recv(SSL *ssl, uint8_t *status, void **payload, uint32_t *payload_len) {
    /* 璇?1 瀛楄妭 status */
    uint8_t st;
    if (ssl_read_full(ssl, &st, 1) != 0)
        return -1;
    *status = st;

    /* 璇?4 瀛楄妭闀垮害 */
    uint32_t net_len;
    if (ssl_read_full(ssl, &net_len, 4) != 0)
        return -1;
    uint32_t len = ntohl(net_len);

    /* 瀹夊叏妫€鏌?*/
    if (len > MAX_FRAME_PAYLOAD) {
        return -1;
    }

    /* 璇?payload */
    if (len > 0) {
        *payload = malloc(len);
        if (!*payload) return -1;
        if (ssl_read_full(ssl, *payload, (int)len) != 0) {
            free(*payload);
            *payload = NULL;
            return -1;
        }
    } else {
        *payload = NULL;
    }

    *payload_len = len;
    return 0;
}
