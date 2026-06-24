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
#include <sys/select.h>
#include <fcntl.h>
#include <sys/uio.h>

/* 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺? * 鍘熷鍑芥暟鎸囬拡锛堥€氳繃 dlsym(RTLD_NEXT, ...) 鑾峰彇锛? * 鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺?*/
static int      (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t  (*real_write)(int, const void *, size_t) = NULL;
static ssize_t  (*real_read)(int, void *, size_t) = NULL;
static ssize_t  (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t  (*real_recv)(int, void *, size_t, int) = NULL;
static ssize_t  (*real_sendto)(int, const void *, size_t, int,
                                const struct sockaddr *, socklen_t) = NULL;
static ssize_t  (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
static int      (*real_close)(int) = NULL;

static int g_hooks_ready = 0;
static __thread int g_in_io = 0;

// __attribute__((constructor)) 让编译器确保这个hook是在main入口之前运行的就和容器是一样的
__attribute__((constructor))
static void init_hooks(void) {
// 获取原始 libc 函数指针（connect、write、read、send、recv 等）
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_write   = dlsym(RTLD_NEXT, "write");
    real_read    = dlsym(RTLD_NEXT, "read");
    real_send    = dlsym(RTLD_NEXT, "send");
    real_recv    = dlsym(RTLD_NEXT, "recv");
    real_close   = dlsym(RTLD_NEXT, "close");
    real_sendto  = dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    // 初始化连接表
    conn_table_init();
    // 初始化tls配置
    if (tls_ctx_init() != 0) {
        fprintf(stderr, "[threshold] TLS init failed, proxy disabled\n");
        return;
    }

    char uuid[MAX_UUID_LEN];
    // 注册设备
    device_uuid_get(uuid, sizeof(uuid));
    fprintf(stderr, "[threshold] Initialized, device UUID: %s\n", uuid);
    fprintf(stderr, "[threshold] Proxy target: %s:%d\n",
            config_get()->proxy_host, config_get()->proxy_port);

    g_hooks_ready = 1;
}


static int should_bypass(const struct sockaddr *addr) {
    // 1. hooks 未就绪则绕过
    if (!g_hooks_ready) return 1;
    // 2. 只代理 IPv4/IPv6 TCP 连接
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return 1;
    // 3. 排除连接到代理服务器自身的请求（防止递归）
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

 /* 处理非阻塞 socket 的 /*
   * connect() 是 Linux 系统调用，作用是让一个 socket 连接到远程服务器。
   *
   * 参数说明：
   *   sockfd  - 文件描述符，就是系统给这个 socket 分配的编号（类似门牌号）
   *   addr    - 目标服务器的地址信息（IP + 端口），相当于你要拨打的电话号码
   *   addrlen - 地址结构体的长度（告诉内核这个地址结构占多少字节）
   *
   * 返回值：
   *   成功返回 0，失败返回 -1 并设置 errno（错误码）
   *
   * 我们要做的事情：
   *   应用程序想连接 "目标服务器"，但我们偷偷把连接重定向到 "代理服务器"，
   *   然后通过 TLS 加密隧道告诉代理服务器："帮我连到真正的目标"
   */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
 /*
     * 第一步：判断这个连接要不要走代理
     *
     * should_bypass() 检查几个条件：
     *   1. 如果代理模块还没初始化好 → 绕过，走原始连接
     *   2. 如果不是 TCP 连接（比如 UDP）→ 绕过
     *   3. 如果目标就是代理服务器自己 → 绕过（否则会死循环！）
     *      （就像你打电话让转接员帮你转接，结果转接到转接员自己，无限循环）
     */
    if (should_bypass(addr)) {
        return real_connect(sockfd, addr, addrlen);
    }

    fprintf(stderr, "[threshold] connect() intercepted, fd=%d\n", sockfd);

     /*
         * struct sockaddr_in 是 IPv4 地址的结构体，长这样：
         *
         *   struct sockaddr_in {
         *       sa_family_t    sin_family;  // 地址族，固定填 AF_INET（表示 IPv4）
         *       in_port_t      sin_port;    // 端口号
         *       struct in_addr sin_addr;    // IP 地址
         *   };
     */
    struct sockaddr_in proxy_addr;
    // 把代理服务器的 IP 和端口填入 proxy_addr
    // 现在数据报中的地址已经指向我们的地址了
    build_proxy_addr(&proxy_addr);
    /*
     * 真正调用原始的 connect()，连接代理服务器
     *
     * real_connect 就是我们通过 dlsym(RTLD_NEXT, "connect") 获取到的
     * glibc 原始 connect 函数指针
     *
     * 为什么要传 (struct sockaddr *)&proxy_addr？
     *   因为 connect() 的第二个参数类型是通用的 struct sockaddr*，
     *   但实际使用时需要传入具体的结构体（IPv4 用 sockaddr_in，
     *   IPv6 用 sockaddr_in6），所以需要强制类型转换
     */
     // 说白了就是直接指向对应的函数指针了
    int ret = real_connect(sockfd, (struct sockaddr *)&proxy_addr,
                           sizeof(proxy_addr));

 /* ====================================================================
     * 第三步：处理非阻塞 socket 的特殊情况
     * ==================================================================== */

    /*
     * connect() 返回值不为 0，说明连接没有立即成功
     *   非阻塞模式：
     *     connect() 会立刻返回，告诉你"还没通"
     *     你之后可以用 select/poll/epoll 来检查"接通了没"
     */
    if (ret != 0) {
           // EINPROGRESS的是非阻塞场景下
        if (errno == EINPROGRESS) {
            fprintf(stderr, "[threshold] connect EINPROGRESS, waiting...\n");
            fd_set wfds;
            FD_ZERO(&wfds);
            // 把我们的 socket 加入"可写"监视集合
            FD_SET(sockfd, &wfds);
            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            // 这个select其实就是和go里面很像，监控多个文件描述符看看有没有数据包到达
            int sel = select(sockfd + 1, NULL, &wfds, NULL, &tv);
             /*
             * select() 返回值：
             *   > 0 : 有事件发生（我们等到了！）
             *   = 0 : 超时（等了 5 秒还没动静）
             *   < 0 : 出错了（被信号中断等）
             */
            if (sel <= 0) {
                fprintf(stderr, "[threshold] connect to proxy timeout\n");
                errno = ETIMEDOUT;
                return -1;
            }
/*
 * select 说 socket 可写了，但不代表连接一定成功！
 *
 * 有可能连接失败了（比如对方拒绝连接），socket 也会变成可写
 * 所以必须用 getsockopt 检查"连接到底成功了没"
 *
 * getsockopt(SO_ERROR) 会获取 socket 的最后一个错误
 * 如果返回 0，说明没有错误，连接成功
 * 如果返回非 0，那个值就是错误码（比如 ECONNREFUSED = 连接被拒绝）
 */
            int sock_err = 0;
            socklen_t errlen = sizeof(sock_err);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sock_err, &errlen);
            if (sock_err != 0) {
                fprintf(stderr, "[threshold] connect to proxy failed after select: %s\n",
                        strerror(sock_err));
                errno = sock_err;
                return -1;
            }
            fprintf(stderr, "[threshold] connect to proxy completed\n");
            int flags = fcntl(sockfd, F_GETFL, 0);
            fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
        } else {
            perror("[threshold] connect to proxy failed");
            return ret;
        }
    }

    /* 2. 建立 TLS，我们之前已经建立了socket连接了，我们现在要做的事情就是在这条连接的基础上建立加密连接*/
    SSL *ssl = tls_connect(sockfd);
    if (!ssl) {
        errno = ECONNREFUSED;
        return -1;
    }

    /* 3. 发送握手包 */
     /*
         * 现在的情况：
         *   应用程序以为自己连的是 "目标服务器"
         *   实际上我们连的是 "代理服务器"
         *   代理服务器还不知道真正要连谁
         *
         * 所以需要发一个"握手包"，告诉代理服务器：
         *   "我是设备 UUID-xxxx，我想连 93.184.216.34 的 80 端口"
         *
         * 握手包的结构（二进制格式）：
         *   [0x54][0x48]  - 魔数，用于识别这是我们的协议
         *   [0x01]        - 协议版本号
         *   [UUID长度][UUID] - 设备唯一标识
         *   [地址族][端口][IP] - 真正要连接的目标
         */
     // 我们其实已经很明确了，握手的时候也就是建立连接的时候我们才会去将指纹附带上发送给我们的代理服务器
    handshake_packet_t hs;
    fill_handshake(&hs, addr);
     /*
     * handshake_send() 做两件事：
     *   1. 把握手包发送给代理服务器
     *   2. 接收代理服务器的响应（成功/被拒绝/频率限制）
     */
    int hs_status = handshake_send(ssl, &hs);
    if (hs_status != STATUS_OK) {
        fprintf(stderr, "[threshold] handshake rejected, status=%d\n", hs_status);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        errno = ECONNREFUSED;
        return -1;
    }

    /* 4. 保存到连接表 */
    conn_table_set(sockfd, ssl, addr, addrlen);

    fprintf(stderr, "[threshold] Proxy established, target=%s:%d\n",
            hs.ip, hs.port);
    // 现在连接是已经建立了
    return 0;
}
ssize_t write(int fd, const void *buf, size_t count) {
    conn_entry_t *entry = conn_table_get(fd);
    if (!entry || g_in_io) {
        return real_write(fd, buf, count);
    }

    g_in_io = 1;
    int ret = frame_send(entry->ssl, buf, (uint32_t)count);
    g_in_io = 0;

    if (ret != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)count;
}

/* ═══════════════════════════════════════════════════════════
 * read() hook
 * ═══════════════════════════════════════════════════════════ */
ssize_t read(int fd, void *buf, size_t count) {
    conn_entry_t *entry = conn_table_get(fd);
    if (!entry || g_in_io) {
        return real_read(fd, buf, count);
    }

    g_in_io = 1;
    int n = consume_recv_buf(entry, buf, count);
    g_in_io = 0;

    if (n < 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)n;
}

/* ═══════════════════════════════════════════════════════════
 * send() hook
 * ═══════════════════════════════════════════════════════════ */
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    (void)flags;
    conn_entry_t *entry = conn_table_get(sockfd);
    if (!entry || g_in_io) {
        return real_send(sockfd, buf, len, flags);
    }

    g_in_io = 1;
    int ret = frame_send(entry->ssl, buf, (uint32_t)len);
    g_in_io = 0;

    if (ret != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)len;
}

/* ═══════════════════════════════════════════════════════════
 * recv() hook
 * ═══════════════════════════════════════════════════════════ */
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    (void)flags;
    conn_entry_t *entry = conn_table_get(sockfd);
    if (!entry || g_in_io) {
        return real_recv(sockfd, buf, len, flags);
    }

    g_in_io = 1;
    int n = consume_recv_buf(entry, buf, len);
    g_in_io = 0;

    if (n < 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)n;
}

/* ═══════════════════════════════════════════════════════════
 * sendto() hook
 * ═══════════════════════════════════════════════════════════ */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    conn_entry_t *entry = conn_table_get(sockfd);
    if (!entry || g_in_io) {
        return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    g_in_io = 1;
    int ret = frame_send(entry->ssl, buf, (uint32_t)len);
    g_in_io = 0;

    if (ret != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)len;
}

/* ═══════════════════════════════════════════════════════════
 * sendmsg() hook
 * ═══════════════════════════════════════════════════════════ */
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    conn_entry_t *entry = conn_table_get(sockfd);
    if (!entry || g_in_io) {
        return real_sendmsg(sockfd, msg, flags);
    }

    size_t total = 0;
    for (int i = 0; i < (int)msg->msg_iovlen; i++) {
        total += msg->msg_iov[i].iov_len;
    }
    char *buf = malloc(total);
    size_t off = 0;
    for (int i = 0; i < (int)msg->msg_iovlen; i++) {
        memcpy(buf + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        off += msg->msg_iov[i].iov_len;
    }

    g_in_io = 1;
    int ret = frame_send(entry->ssl, buf, (uint32_t)total);
    g_in_io = 0;

    free(buf);
    if (ret != 0) {
        errno = ECONNRESET;
        return -1;
    }
    return (ssize_t)total;
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
