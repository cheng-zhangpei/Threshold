#include "device_uuid.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

/* 浠庢枃浠惰鍙栦竴琛岋紙鍘绘帀鎹㈣绗︼級 */
static int read_file_line(const char *path, char *buf, size_t buflen) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, buflen, f)) { fclose(f); return -1; }
    fclose(f);
    /* 鍘绘帀灏鹃儴鎹㈣ */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return (len > 0) ? 0 : -1;
}

/* 鐢熸垚涓€涓畝鏄撻殢鏈?UUID (闈炲姞瀵嗗畨鍏紝鍘熷瀷闃舵澶熺敤) */
static void generate_random_uuid(char *buf, size_t buflen) {
    srand((unsigned)(time(NULL) ^ getpid()));
    snprintf(buf, buflen,
        "%08x-%04x-%04x-%04x-%08x%04x",
        rand(), rand() & 0xFFFF, rand() & 0xFFFF,
        rand() & 0xFFFF, rand(), rand() & 0xFFFF);
}

int device_uuid_get(char *buf, size_t buflen) {
    /* 1. 鐜鍙橀噺浼樺厛 */
    threshold_config_t *cfg = config_get();
    if (cfg->device_uuid_override) {
        strncpy(buf, cfg->device_uuid_override, buflen - 1);
        buf[buflen - 1] = '\0';
        return 0;
    }

    /* 2. /etc/machine-id (systemd 绯荤粺閮芥湁) */
    if (read_file_line("/etc/machine-id", buf, buflen) == 0)
        return 0;

    /* 3. 澶囬€? /var/lib/dbus/machine-id */
    if (read_file_line("/var/lib/dbus/machine-id", buf, buflen) == 0)
        return 0;

    /* 4. 閮芥病鏈夛紝闅忔満鐢熸垚锛堝悗缁彲鎸佷箙鍖栧埌 ~/.threshold_uuid锛?*/
    generate_random_uuid(buf, buflen);
    return 0;
}
