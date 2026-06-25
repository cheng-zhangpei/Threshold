#ifndef LIBTHRESHOLD_TLS_CTX_H
#define LIBTHRESHOLD_TLS_CTX_H

#include <openssl/ssl.h>

/*
 * 鍒濆鍖栧叏灞€ TLS 涓婁笅鏂囷紙绋嬪簭鍚姩鏃惰皟鐢ㄤ竴娆★級
 * 鍔犺浇 CA 璇佷功锛岄厤缃?TLS 瀹㈡埛绔? * 鎴愬姛杩斿洖 0锛屽け璐ヨ繑鍥?-1
 */
int tls_ctx_init(void);

/*
 * 涓轰竴涓柊鐨?TCP fd 鍒涘缓 SSL 杩炴帴
 * 杩斿洖 SSL* 鎸囬拡锛岃皟鐢ㄨ€呴渶鎸佹湁瀹? * 澶辫触杩斿洖 NULL
 */
SSL *tls_connect(int fd);
void tls_ctx_cleanup(void);  // 新增

#endif
