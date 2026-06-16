// client/socks5/protocol.go
package socks5

import (
	"fmt"
	"io"
	"net"
)

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04

	repSuccess = 0x00
	repFailure = 0x01
)

// Handshake 处理 SOCKS5 握手，返回选中的认证方法
func Handshake(r io.Reader, w io.Writer) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if buf[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	// 只支持无认证（0x00）
	if _, err := w.Write([]byte{socks5Version, 0x00}); err != nil {
		return err
	}
	return nil
}

// ParseRequest 解析 CONNECT 请求，返回目标地址（字符串形式）
func ParseRequest(r io.Reader) (targetAddr string, err error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}
	if buf[1] != cmdConnect {
		return "", fmt.Errorf("unsupported command: %d", buf[1])
	}
	// buf[2] = RSV, 忽略
	atyp := buf[3]

	var host string
	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	// 读取端口（2 字节，大端序）
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return fmt.Sprintf("%s:%d", host, port), nil
}

// SendSuccessResponse 回复 SOCKS5 CONNECT 成功
func SendSuccessResponse(w io.Writer) error {
	// VER=5, REP=0x00, RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := w.Write([]byte{
		socks5Version, repSuccess, 0x00, atypIPv4,
		0x00, 0x00, 0x00, 0x00, // 0.0.0.0
		0x00, 0x00, // port 0
	})
	return err
}
