#include "conn_table.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/ssl.h>

static conn_entry_t g_table[CONN_TABLE_MAX_FD];
static pthread_mutex_t g_table_lock = PTHREAD_MUTEX_INITIALIZER;

void conn_table_init(void) {
    memset(g_table, 0, sizeof(g_table));
}

conn_entry_t *conn_table_get(int fd) {
    if (fd < 0 || fd >= CONN_TABLE_MAX_FD) return NULL;
    /* 璇绘搷浣滀笉鍔犻攣鈥斺€斾粎鍦ㄥ凡鐭?active 鐨勬儏鍐典笅璋冪敤锛?       鍗曚釜 fd 鐨勮鍐欑敱鍐呮牳淇濊瘉涓茶鍖?*/
    return g_table[fd].active ? &g_table[fd] : NULL;
}

int conn_table_set(int fd, SSL *ssl,
                   const struct sockaddr *orig_addr, socklen_t orig_addrlen) {
    if (fd < 0 || fd >= CONN_TABLE_MAX_FD) return -1;

    pthread_mutex_lock(&g_table_lock);
    conn_entry_t *e = &g_table[fd];
    e->active       = 1;
    e->ssl          = ssl;
    e->orig_addrlen = orig_addrlen;
    memcpy(&e->orig_addr, orig_addr, orig_addrlen);
    e->recv_buf     = NULL;
    e->recv_buf_len = 0;
    e->recv_buf_pos = 0;
    pthread_mutex_unlock(&g_table_lock);
    return 0;
}

void conn_table_remove(int fd) {
    if (fd < 0 || fd >= CONN_TABLE_MAX_FD) return;

    pthread_mutex_lock(&g_table_lock);
    conn_entry_t *e = &g_table[fd];
    if (e->active) {
        if (e->ssl) {
            SSL_shutdown(e->ssl);
            SSL_free(e->ssl);
            e->ssl = NULL;
        }
        free(e->recv_buf);
        e->recv_buf     = NULL;
        e->recv_buf_len = 0;
        e->recv_buf_pos = 0;
        e->active       = 0;
    }
    pthread_mutex_unlock(&g_table_lock);
}

int conn_table_is_proxied(int fd) {
    if (fd < 0 || fd >= CONN_TABLE_MAX_FD) return 0;
    return g_table[fd].active;
}
