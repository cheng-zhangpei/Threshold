/*
 * test_main.c 鈥?绠€鍗曠殑 TCP 瀹㈡埛绔紝瀹屽叏涓嶇煡閬撲唬鐞嗙殑瀛樺湪
 *
 * 鐢ㄦ硶:
 *   姝ｅ父缂栬瘧:  gcc -o test_client test_main.c
 *   姝ｅ父杩愯:  ./test_client 127.0.0.1 8080
 *   浠ｇ悊妯″紡:  LD_PRELOAD=./libthreshold.so ./test_client 127.0.0.1 8080
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    const char *target_ip = "127.0.0.1";
    int target_port = 8080;
    const char *http_path = "/api/test";

    if (argc >= 3) {
        target_ip   = argv[1];
        target_port = atoi(argv[2]);
    }
    if (argc >= 4) {
        http_path = argv[3];
    }

    printf("[test] Connecting to %s:%d\n", target_ip, target_port);

    /* 1. 鍒涘缓 socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    /* 2. 杩炴帴 */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)target_port);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    printf("[test] Connected!\n");

    /* 3. 鍙戦€?HTTP 璇锋眰 */
    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r"
        "\nConnection: close\r\n"
        "\r\n",
        http_path, target_ip, target_port);

    ssize_t sent = write(fd, request, strlen(request));
    printf("[test] Sent %zd bytes\n", sent);

    /* 4. 璇诲彇鍝嶅簲 */
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("[test] Received %zd bytes:\n%s\n", n, buf);
    } else {
        printf("[test] No response (n=%zd)\n", n);
    }

    /* 5. 鍏抽棴 */
    close(fd);
    printf("[test] Done\n");
    return 0;
}
