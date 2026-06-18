#ifndef LIBTHRESHOLD_CONFIG_H
#define LIBTHRESHOLD_CONFIG_H

typedef struct {
    const char *proxy_host;
    int         proxy_port;
    const char *ca_cert_path;
    const char *device_uuid_override;   /* 鍙€夛細鎵嬪姩鎸囧畾 UUID */
} threshold_config_t;

/* 鍔犺浇閰嶇疆锛堜粠鐜鍙橀噺璇诲彇锛屾湁榛樿鍊硷級 */
void config_load(threshold_config_t *cfg);

/* 鑾峰彇鍏ㄥ眬閰嶇疆锛堥娆¤皟鐢ㄦ椂鑷姩鍔犺浇锛?*/
threshold_config_t *config_get(void);

#endif
