#ifndef LIBTHRESHOLD_CONN_TABLE_H
#define LIBTHRESHOLD_CONN_TABLE_H

#include <stdint.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

#define CONN_TABLE_MAX_FD   4096

typedef struct {
    int                      active;
    SSL                     *ssl;
    struct sockaddr_storage  orig_addr;     /* 搴旂敤鍘熸湰瑕佽繛鐨勫湴鍧€ */
    socklen_t                orig_addrlen;
    /* 璇荤紦鍐插尯锛堝瓨鏀炬湇鍔＄鍝嶅簲甯т腑瑙ｅ嚭鐨?payload锛?*/
    char                    *recv_buf;
    uint32_t                 recv_buf_len;  /* 缂撳啿鍖轰腑鏈夋晥瀛楄妭鏁?*/
    uint32_t                 recv_buf_pos;  /* 褰撳墠璇诲埌鐨勪綅缃?*/
} conn_entry_t;

/* 鍒濆鍖栬繛鎺ヨ〃锛堢▼搴忓惎鍔ㄦ椂璋冪敤涓€娆★級 */
void conn_table_init(void);

/* 鑾峰彇鏌愪釜 fd 鐨勬潯鐩紝涓嶅瓨鍦ㄨ繑鍥?NULL */
conn_entry_t *conn_table_get(int fd);

/* 娣诲姞鏉＄洰锛坈onnect 鎴愬姛鍚庤皟鐢級 */
int conn_table_set(int fd, SSL *ssl,
                   const struct sockaddr *orig_addr, socklen_t orig_addrlen);

/* 绉婚櫎鏉＄洰锛坈lose 鏃惰皟鐢級锛屼細 SSL_shutdown + SSL_free + 閲婃斁缂撳啿鍖?*/
void conn_table_remove(int fd);

/* 鍒ゆ柇鏌愪釜 fd 鏄惁琚垜浠唬鐞?*/
int conn_table_is_proxied(int fd);

#endif
