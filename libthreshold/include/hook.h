#ifndef LIBTHRESHOLD_HOOK_H
#define LIBTHRESHOLD_HOOK_H

/*
 * 澹版槑鎵€鏈夎 hook 鐨勭郴缁熻皟鐢? * 瀹為檯瀹炵幇鍦?hook.c 涓紝閫氳繃 LD_PRELOAD 瑕嗙洊 libc 鍘熷瀹炵幇
 *
 * hook 鐨勫嚱鏁?
 *   connect()   鈥?鏇挎崲鐩爣鍦板潃锛屽缓绔?TLS + 鎻℃墜
 *   write()     鈥?鎷︽埅鍐欏嚭鏁版嵁锛屽抚灏佽 + TLS 鍙戦€? *   read()      鈥?鎷︽埅璇诲叆锛屼粠甯х紦鍐插尯杩斿洖
 *   send()      鈥?鍚?write
 *   recv()      鈥?鍚?read
 *   close()     鈥?娓呯悊杩炴帴鐘舵€? */

#endif
