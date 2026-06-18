
/*
 * libthreshold.c — 共享库入口
 *
 * 本文件不是必须的（constructor 在 hook.c 中），
 * 但放一个集中入口方便后续扩展初始化逻辑。
 *
 * 编译产出: libthreshold.so
 * 使用方式: LD_PRELOAD=./libthreshold.so ./your_app
 */

#include <stdio.h>

/*
 * 所有初始化在 hook.c 的 __attribute__((constructor)) 中完成：
 *   1. dlsym 解析原始函数指针
 *   2. conn_table_init()
 *   3. tls_ctx_init()
 *   4. 采集设备 UUID
 *
 * 本文件保留为空壳，后续可扩展：
 *   - 日志级别控制
 *   - 信号处理
 *   - 统计信息输出
 */