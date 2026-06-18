#define _GNU_SOURCE
#include "hook.h"
#include "conn_table.h"
#include "tls_ctx.h"
#include "config.h"
#include "device_uuid.h"
#include "handshake.h"
#include "framing.h"
#include "protocol.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * 鍘熷鍑芥暟鎸囬拡锛堥€氳繃 dlsym(RTLD_NEXT, ...) 鑾峰彇锛? * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
static int      (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t  (*real_write)(int, const void *, size_t) = NULL;
static ssize_t  (*real_read)(int, void *, size_t) = NULL;
static ssize_t  (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t  (*real_recv)(int, void *, size_t, int) = NULL;
static int      (*real_close)(int) = NULL;

static int g_hooks_ready = 0;

/*
 * __attribute__((constructor)):
 * 鍦?.so 琚?dlopen (鍗?LD_PRELOAD 鍔犺浇) 鏃惰嚜鍔ㄦ墽琛岋紝
 * 姣?main() 鏇存棭銆傜敤浜庤В鏋愬師濮?libc 鍑芥暟鎸囬拡銆? */
__attribute__((constructor))
static void init_hooks(void) {
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_write   = dlsym(RTLD_NEXT, "write");
    real_read    = dlsym(RTLD_NEXT, "read");
    real_send    = dlsym(RTLD_NEXT, "send");
    real_recv    = dlsym(RTLD_NEXT, "recv");
    real_close   = dlsym(RTLD_NEXT, "close");

    conn_table_init();

    if (tls_ctx_init() != 0) {
        fprintf(stderr, "[threshold] TLS init failed, proxy disabled\n");
        return;
    }

    char uuid[MAX_UUID_LEN];
    device_uuid_get(uuid, sizeof(uuid));
    fprintf(stderr, "[threshold] Initialized, device UUID: %s\n", uuid);
    fprintf(stderr, "[threshold] Proxy target: %s:%d\n",
            config_get()->proxy_host, config_get()->proxy_port);

    g_hooks_ready = 1;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * 杈呭姪鍑芥暟
 * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/

/* 鍒ゆ柇鏄惁搴旇璺宠繃浠ｇ悊锛堢洿鎺ヨ蛋鍘熷杩炴帴锛?*/
static int should_bypass(const struct sockaddr *addr) {
    if (!g_hooks_ready) return 1;

    /* 鍙唬鐞?IPv4/IPv6 TCP 杩炴帴 */
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return 1;

    /* 鎺掗櫎杩炲悜 proxy 鑷韩鐨勮繛鎺ワ紙闃查€掑綊锛?*/
    threshold_config_t *cfg = config_get();
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        struct in_addr proxy_addr;
        inet_pton(AF_INET, cfg->proxy_host, &proxy_addr);
        if (sin->sin_addr.s_addr == proxy_addr.s_addr &&
            ntohs(sin->sin_port) == (uint16_t)cfg->proxy_port) {
            return 1;
        }
    }

    return 0;
}

/* 鏋勫缓 proxy 鍦板潃 */
static void build_proxy_addr(struct sockaddr_in *out) {
    threshold_config_t *cfg = config_get();
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port   = htons((uint16_t)cfg->proxy_port);
    inet_pton(AF_INET, cfg->proxy_host, &out->sin_addr);
}

/* 浠?sockaddr 鎻愬彇鐩爣淇℃伅濉叆鎻℃墜鍖?*/
static void fill_handshake(handshake_packet_t *pkt,
                           const struct sockaddr *addr) {
    memset(pkt, 0, sizeof(*pkt));

    /* UUID */
    device_uuid_get(pkt->uuid, sizeof(pkt->uuid));
    pkt->uuid_len = (uint8_t)strlen(pkt->uuid);

    /* 鐩爣鍦板潃 */
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        pkt->addr_family = ADDR_FAMILY_IPV4;
        pkt->port = ntohs(sin->sin_port);
        inet_ntop(AF_INET, &sin->sin_addr, pkt->ip, sizeof(pkt->ip));
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        pkt->addr_family = ADDR_FAMILY_IPV6;
        pkt->port = ntohs(sin6->sin6_port);
        inet_ntop(AF_INET6, &sin6->sin6_addr, pkt->ip, sizeof(pkt->ip));
    }
}

/*
 * 浠庣紦鍐插尯娑堣垂鏁版嵁锛堜緵 read/send hook 鍐呴儴浣跨敤锛? * 浠?entry 鐨?recv_buf 鎷疯礉鏈€澶?maxlen 瀛楄妭鍒?buf
 * 杩斿洖瀹為檯鎷疯礉瀛楄妭鏁? */
static int consume_recv_buf(conn_entry_t *entry, void *buf, size_t maxlen) {
    if (!entry->recv_buf || entry->recv_buf_pos >= entry->recv_buf_len) {
        /* 缂撳啿鍖虹┖锛岄渶瑕佸厛浠?TLS 璇讳竴涓抚 */
        free(entry->recv_buf);
        entry->recv_buf = NULL;
        entry->recv_buf_len = 0;
        entry->recv_buf_pos = 0;

        uint8_t status;
        void *payload = NULL;
        uint32_t payload_len = 0;

        if (frame_recv(entry->ssl, &status, &payload, &payload_len) != 0) {
            return -1;  /* 杩炴帴鍏抽棴鎴栭敊璇?*/
        }

        if (status == STATUS_BLOCKED) {
            free(payload);
            errno = ECONNREFUSED;
            return -1;
        }

        entry->recv_buf = (char *)payload;  /* frame_recv 宸?malloc */
        entry->recv_buf_len = payload_len;
        entry->recv_buf_pos = 0;
    }

    /* 浠庣紦鍐插尯鎷疯礉鏁版嵁 */
    uint32_t avail = entry->recv_buf_len - entry->recv_buf_pos;
    uint32_t to_copy = (uint32_t)(maxlen < avail ? maxlen : avail);

    memcpy(buf, entry->recv_buf + entry->recv_buf_pos, to_copy);
    entry->recv_buf_pos += to_copy;

    /* 鍏ㄩ儴娑堣垂瀹屽垯閲婃斁 */
    if (entry->recv_buf_pos >= entry->recv_buf_len) {
        free(entry->recv_buf);
        entry->recv_buf = NULL;
        entry->recv_buf_len = 0;
        entry->recv_buf_pos = 0;
    }

    return (int)to_copy;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * connect() hook 鈥?鏍稿績
 * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (should_bypass(addr)) {
        return real_connect(sockfd, addr, addrlen);
    }

    fprintf(stderr, "[threshold] connect() intercepted, fd=%d\n", sockfd);

    /* 1. 杩炴帴鍒?proxy server */
    struct sockaddr_in proxy_addr;
    build_proxy_addr(&proxy_addr);

    int ret = real_connect(sockfd, (struct sockaddr *)&proxy_addr,
                           sizeof(proxy_addr));
    if (ret != 0) {
        perror("[threshold] connect to proxy failed");
        return ret;
    }

    /* 2. 寤虹珛 TLS */
    SSL *ssl = tls_connect(sockfd);
    if (!ssl) {
        errno = ECONNREFUSED;
        return -1;
    }

    /* 3. 鍙戦€佹彙鎵嬪寘 */
    handshake_packet_t hs;
    fill_handshake(&hs, addr);

    int hs_status = handshake_send(ssl, &hs);
    if (hs_status != STATUS_OK) {
        fprintf(stderr, "[threshold] handshake rejected, status=%d\n", hs_status);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        errno = ECONNREFUSED;
        return -1;
    }

    /* 4. 淇濆瓨鍒拌繛鎺ヨ〃 */
    conn_table_set(sockfd, ssl, addr, addrlen);

    fprintf(stderr, "[threshold] Proxy established, target=%s:%d\n",
            hs.ip, hs.port);
    return 0;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * write() hook
 * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
ssize_t write(int fd, const void *buf, size_t count) {
    conn_entry_t *entry = conn_table_get(fd);
    if (!entry) {
        return real_write(fd, buf, count);
    }

    /* 甯у皝瑁?+ TLS 鍙戦€?*/
    if (frame_send(entry->ssl, buf, (uint32_t)count) != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)count;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * read() hook
 * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
ssize_t read(int fd, void *buf, size_t count) {
    conn_entry_t *entry = conn_table_get(fd);
    if (!entry) {
        return real_read(fd, buf, count);
    }

    int n = consume_recv_buf(entry, buf, count);
    if (n < 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)n;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * send() hook锛堥€昏緫鍚?write锛? * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    (void)flags;
    conn_entry_t *entry = conn_table_get(sockfd);
    if (!entry) {
        return real_send(sockfd, buf, len, flags);
    }
    if (frame_send(entry->ssl, buf, (uint32_t)len) != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)len;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * recv() hook锛堥€昏緫鍚?read锛? * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    (void)flags;
    conn_entry_t *entry = conn_table_get(sockfd);
    if (!entry) {
        return real_recv(sockfd, buf, len, flags);
    }
    int n = consume_recv_buf(entry, buf, len);
    if (n < 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)n;
}

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * close() hook
 * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
int close(int fd) {
    if (conn_table_is_proxied(fd)) {
        fprintf(stderr, "[threshold] close() intercepted, fd=%d\n", fd);
        conn_table_remove(fd);  /* SSL_shutdown + SSL_free + 娓呯悊缂撳啿鍖?*/
    }
    return real_close(fd);
}
