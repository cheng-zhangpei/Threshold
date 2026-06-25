#include "config.h"
#include <stdlib.h>
#include <string.h>

static threshold_config_t g_config;
static int g_loaded = 0;

void config_load(threshold_config_t *cfg) {
    const char *host    = getenv(ENV_PROXY_HOST);
    const char *port    = getenv(ENV_PROXY_PORT);
    const char *ca      = getenv(ENV_CA_CERT);
    const char *uuid    = getenv(ENV_DEVICE_UUID);
    const char *ccert   = getenv(ENV_CLIENT_CERT);
    const char *ckey    = getenv(ENV_CLIENT_KEY);

    cfg->proxy_host           = host  ? host  : DEFAULT_PROXY_HOST;
    cfg->proxy_port           = port  ? atoi(port) : DEFAULT_PROXY_PORT;
    cfg->ca_cert_path         = ca    ? ca    : DEFAULT_CA_CERT;
    cfg->device_uuid_override = uuid  ? uuid  : NULL;
    cfg->client_cert_path     = ccert ? ccert : DEFAULT_CLIENT_CERT;
    cfg->client_key_path      = ckey  ? ckey  : DEFAULT_CLIENT_KEY;
}

threshold_config_t *config_get(void) {
    if (!g_loaded) {
        config_load(&g_config);
        g_loaded = 1;
    }
    return &g_config;
}