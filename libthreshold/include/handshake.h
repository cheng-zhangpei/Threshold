#ifndef LIBTHRESHOLD_HANDSHAKE_H
#define LIBTHRESHOLD_HANDSHAKE_H

#include "protocol.h"
#include <openssl/ssl.h>

/*
 * 鏋勯€犳彙鎵嬪寘骞跺彂閫侊紙瀹㈡埛绔皟鐢級
 * 灏?handshake_packet_t 缂栫爜涓轰簩杩涘埗甯э紝閫氳繃 TLS 鍙戦€? * 鐒跺悗鎺ユ敹鏈嶅姟绔彙鎵嬪搷搴? *
 * 杩斿洖 STATUS_OK / STATUS_BLOCKED / STATUS_RATE_LIMITED
 * 澶辫触杩斿洖 -1
 */
int handshake_send(SSL *ssl, const handshake_packet_t *pkt);

/*
 * 浠庝簩杩涘埗鏁版嵁瑙ｆ瀽鎻℃墜鍖咃紙鏈嶅姟绔皟鐢紝棰勭暀锛? * 杩斿洖 0 鎴愬姛锛?1 瑙ｆ瀽澶辫触
 */
int handshake_parse(const void *data, uint32_t len, handshake_packet_t *out);

#endif
