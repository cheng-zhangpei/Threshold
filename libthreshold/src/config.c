#include "config.h"
#include <stdlib.h>
#include <string.h>

static threshold_config_t g_config;
static int g_loaded = 0;

void config_load(threshold_config_t *cfg) {
    const char *host = getenv("THRESHOLD_PROXY_HOST");
    const char *port = getenv("THRESHOLD_PROXY_PORT");
    const char *ca   = getenv("THRESHOLD_CA_CERT");
    const char *uuid = getenv("THRESHOLD_DEVICE_UUID");

    cfg->proxy_host         = host ? host : "127.0.0.1";
    cfg->proxy_port         = port ? atoi(port) : 9999;
    cfg->ca_cert_path       = ca   ? ca   : "certs/server.crt";
    cfg->device_uuid_override = uuid ? uuid : NULL;
}

threshold_config_t *config_get(void) {
    if (!g_loaded) {
        config_load(&g_config);
        g_loaded = 1;
    }
    return &g_config;
}
