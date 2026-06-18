#ifndef LIBTHRESHOLD_DEVICE_UUID_H
#define LIBTHRESHOLD_DEVICE_UUID_H

#include <stddef.h>

/*
 * 閲囬泦璁惧鍞竴鏍囪瘑
 * 浼樺厛绾? 鐜鍙橀噺 THRESHOLD_DEVICE_UUID > /etc/machine-id > 闅忔満鐢熸垚
 *
 * 鎴愬姛鍐欏叆 buf 骞惰繑鍥?0锛屽け璐ヨ繑鍥?-1
 */
int device_uuid_get(char *buf, size_t buflen);

#endif
