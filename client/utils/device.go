// client/device.go
package client

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// GetDeviceInfo 返回 deviceUUID 和 osType，优先使用配置值
func GetDeviceInfo(cfgUUID, cfgOSType string) (uuid, osType string) {
	if cfgUUID != "" {
		uuid = cfgUUID
	} else {
		uuid = getMachineUUID()
	}
	if cfgOSType != "" {
		osType = cfgOSType
	} else {
		osType = runtime.GOOS
	}
	return
}

// getMachineUUID 获取本机 UUID（Linux 用 dmidecode，Windows 用 wmic）
func getMachineUUID() string {
	// Linux
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	// Windows: 可调用 wmic csproduct get uuid
	// 原型阶段返回 fallback
	return "fallback-uuid-12345678"
}

// GetLocalIP 获取本机出口 IP（用于 ConnectionInit 的 ip 字段）
func GetLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
