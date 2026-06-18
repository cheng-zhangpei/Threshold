#ifndef LIBTHRESHOLD_FRAMING_H
#define LIBTHRESHOLD_FRAMING_H

#include <stdint.h>
#include <openssl/ssl.h>

/*
 * 甯у崗璁?
 *
 * 瀹㈡埛绔?鈫?鏈嶅姟绔?  [Length:4 BE] [Payload:Length bytes]
 * 鏈嶅姟绔?鈫?瀹㈡埛绔?  [Status:1] [Length:4 BE] [Payload:Length bytes]
 */

/*
 * 鍙戦€佷竴甯ф暟鎹?(瀹㈡埛绔?鈫?鏈嶅姟绔?
 * 鑷姩鍔?4 瀛楄妭闀垮害鍓嶇紑锛岄€氳繃 TLS 鍙戦€? * 杩斿洖 0 鎴愬姛锛?1 澶辫触
 */
int frame_send(SSL *ssl, const void *payload, uint32_t len);

/*
 * 鎺ユ敹涓€甯у搷搴?(鏈嶅姟绔?鈫?瀹㈡埛绔?
 * 璇诲彇 status(1瀛楄妭) + length(4瀛楄妭) + payload
 *
 * 鍙傛暟:
 *   ssl       - TLS 杩炴帴
 *   status    - 杈撳嚭: 鏈嶅姟绔繑鍥炵殑鐘舵€佺爜
 *   payload   - 杈撳嚭: 鎺ユ敹缂撳啿鍖?(璋冪敤鑰呰礋璐?malloc/free)
 *   payload_len - 杈撳嚭: payload 瀹為檯闀垮害
 *
 * 杩斿洖 0 鎴愬姛锛?1 澶辫触锛堣繛鎺ュ叧闂垨閿欒锛? */
int frame_recv(SSL *ssl, uint8_t *status, void **payload, uint32_t *payload_len);

#endif
