#include "handshake.h"
#include "device_uuid.h"
#include "config.h"
#include "framing.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

/*
 * 鎻℃墜鍖呬簩杩涘埗甯冨眬:
 *
 *  [0]     Magic0    (0x54)
 *  [1]     Magic1    (0x48)
 *  [2]     Version   (0x01)
 *  [3]     UUID_Len
 *  [4..]   UUID      (UUID_Len bytes)
 *  [4+L]   AddrFamily (1 byte)
 *  [5+L]   Port       (2 bytes BE)
 *  [7+L]   IP         (4 or 16 bytes, depending on family)
 */

/* ---- 瀹㈡埛绔晶锛氭瀯閫犲苟鍙戦€?---- */

int handshake_send(SSL *ssl, const handshake_packet_t *pkt) {
    uint8_t buf[256];
    int off = 0;

    /* Magic + Version */
    buf[off++] = HANDSHAKE_MAGIC_0;
    buf[off++] = HANDSHAKE_MAGIC_1;
    buf[off++] = HANDSHAKE_VERSION;

    /* UUID */
    buf[off++] = pkt->uuid_len;
    memcpy(buf + off, pkt->uuid, pkt->uuid_len);
    off += pkt->uuid_len;

    /* 鐩爣鍦板潃 */
    buf[off++] = pkt->addr_family;
    uint16_t net_port = htons(pkt->port);
    memcpy(buf + off, &net_port, 2);
    off += 2;

    if (pkt->addr_family == ADDR_FAMILY_IPV4) {
        /* IPv4: 4 bytes */
        inet_pton(AF_INET, pkt->ip, buf + off);
        off += 4;
    } else {
        /* IPv6: 16 bytes */
        inet_pton(AF_INET6, pkt->ip, buf + off);
        off += 16;
    }

    /* 閫氳繃甯у崗璁彂閫佹彙鎵嬪寘 */
    if (frame_send(ssl, buf, (uint32_t)off) != 0) {
        fprintf(stderr, "[threshold] handshake send failed\n");
        return -1;
    }

    /* 鎺ユ敹鎻℃墜鍝嶅簲锛堝彧鍏冲績 status 瀛楄妭锛屾棤 payload锛?*/
    uint8_t status;
    void *resp_payload = NULL;
    uint32_t resp_len = 0;
    if (frame_recv(ssl, &status, &resp_payload, &resp_len) != 0) {
        fprintf(stderr, "[threshold] handshake recv failed\n");
        return -1;
    }
    free(resp_payload);

    return (int)status;  /* STATUS_OK / BLOCKED / RATE_LIMITED */
}

/* ---- 鏈嶅姟绔晶锛氳В鏋?---- */

int handshake_parse(const void *data, uint32_t len, handshake_packet_t *out) {
    const uint8_t *p = (const uint8_t *)data;
    int off = 0;

    if (len < 4) return -1;

    /* Magic */
    if (p[off++] != HANDSHAKE_MAGIC_0) return -1;
    if (p[off++] != HANDSHAKE_MAGIC_1) return -1;
    /* Version */
    if (p[off++] != HANDSHAKE_VERSION) return -1;
    /* UUID */
    uint8_t uuid_len = p[off++];
    if (off + uuid_len > (int)len) return -1;
    memcpy(out->uuid, p + off, uuid_len);
    out->uuid[uuid_len] = '\0';
    out->uuid_len = uuid_len;
    off += uuid_len;

    /* 鍦板潃 */
    if (off + 3 > (int)len) return -1;
    out->addr_family = p[off++];
    memcpy(&out->port, p + off, 2);
    out->port = ntohs(out->port);
    off += 2;

    if (out->addr_family == ADDR_FAMILY_IPV4) {
        if (off + 4 > (int)len) return -1;
        inet_ntop(AF_INET, p + off, out->ip, sizeof(out->ip));
        off += 4;
    } else if (out->addr_family == ADDR_FAMILY_IPV6) {
        if (off + 16 > (int)len) return -1;
        inet_ntop(AF_INET6, p + off, out->ip, sizeof(out->ip));
        off += 16;
    } else {
        return -1;
    }

    return 0;
}
