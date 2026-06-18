#ifndef LIBTHRESHOLD_PROTOCOL_H
#define LIBTHRESHOLD_PROTOCOL_H

#include <stdint.h>

/*
 * Mode 3 浜岃繘鍒跺崗璁畾涔? *
 * 浼犺緭灞? TLS over TCP
 * 搴旂敤灞? 鑷畾涔夊抚鍗忚
 *
 * 鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? * 鈹?鎻℃墜鍖?(杩炴帴寤虹珛鏃朵竴娆℃€у彂閫?                         鈹? * 鈹?  Magic(2) + Ver(1) + UUIDLen(1) + UUID + TargetAddr鈹? * 鈹溾攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? * 鈹?鎻℃墜鍝嶅簲 (鏈嶅姟绔?鈫?瀹㈡埛绔?                            鈹? * 鈹?  Status(1)                                         鈹? * 鈹溾攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? * 鈹?璇锋眰甯?(瀹㈡埛绔?鈫?鏈嶅姟绔?                              鈹? * 鈹?  Length(4 BE) + Payload(Length bytes)               鈹? * 鈹溾攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? * 鈹?鍝嶅簲甯?(鏈嶅姟绔?鈫?瀹㈡埛绔?                              鈹? * 鈹?  Status(1) + Length(4 BE) + Payload(Length bytes)   鈹? * 鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? */

/* 鎻℃墜鍖呴瓟鏁? "TH" */
#define HANDSHAKE_MAGIC_0       0x54    /* 'T' */
#define HANDSHAKE_MAGIC_1       0x48    /* 'H' */
#define HANDSHAKE_VERSION       0x01

/* 鍦板潃鏃?*/
#define ADDR_FAMILY_IPV4        0x01
#define ADDR_FAMILY_IPV6        0x02

/* 鐘舵€佺爜 */
#define STATUS_OK               0x00
#define STATUS_BLOCKED          0x01
#define STATUS_RATE_LIMITED     0x02

/* 闄愬埗 */
#define MAX_UUID_LEN            64
#define MAX_FRAME_PAYLOAD       (1024 * 1024)   /* 1MB */

/*
 * 鎻℃墜鍖呯粨鏋勶紙鍐呭瓨涓殑琛ㄧず锛屽簭鍒楀寲鏃舵墜鍔ㄧ紪鐮侊級
 */
typedef struct {
    char     uuid[MAX_UUID_LEN];
    uint8_t  uuid_len;
    uint8_t  addr_family;                       /* ADDR_FAMILY_IPV4 / IPV6 */
    uint16_t port;                              /* 涓绘満瀛楄妭搴?*/
    char     ip[46];                            /* "1.2.3.4" 鎴?IPv6 瀛楃涓?*/
} handshake_packet_t;

#endif /* LIBTHRESHOLD_PROTOCOL_H */
