#ifndef LIBTHRESHOLD_CONFIG_H
#define LIBTHRESHOLD_CONFIG_H

// 环境变量名
#define ENV_PROXY_HOST       "THRESHOLD_PROXY_HOST"
#define ENV_PROXY_PORT       "THRESHOLD_PROXY_PORT"
#define ENV_DEVICE_UUID      "THRESHOLD_DEVICE_UUID"
#define ENV_CA_CERT          "THRESHOLD_CA_CERT"
#define ENV_CLIENT_CERT      "THRESHOLD_CLIENT_CERT"
#define ENV_CLIENT_KEY       "THRESHOLD_CLIENT_KEY"

// 默认值
#define DEFAULT_PROXY_HOST   "127.0.0.1"
#define DEFAULT_PROXY_PORT   9999
#define DEFAULT_CA_CERT      "./data/ca/ca.crt"
#define DEFAULT_CLIENT_CERT  ""  // 空则不提供客户端证书（降级为单向 TLS）
#define DEFAULT_CLIENT_KEY   ""

typedef struct {
    const char *proxy_host;
    int         proxy_port;
    const char *ca_cert_path;
    const char *device_uuid_override;
    const char *client_cert_path;    // 新增：客户端证书
    const char *client_key_path;     // 新增：客户端私钥
} threshold_config_t;

void config_load(threshold_config_t *cfg);
threshold_config_t *config_get(void);

#endif