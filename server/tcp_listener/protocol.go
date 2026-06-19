package tcplistener

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// 二进制协议常量，与 libthreshold.so 保持一致
const (
	Magic0  byte = 0x54 // 'T'
	Magic1  byte = 0x48 // 'H'
	Version byte = 0x01

	AddrIPv4 byte = 0x01
	AddrIPv6 byte = 0x02

	StatusOK      byte = 0x00
	StatusBlocked byte = 0x01
	StatusLimited byte = 0x02

	MaxPayloadSize = 1 << 20 // 1MB
)

// Handshake 解析后的握手包
type Handshake struct {
	UUID       string
	AddrFamily byte
	Port       uint16
	IP         string
	Target     string // "ip:port"
}

// readFrame 读取客户端发来的帧: [4字节BE长度][payload]
// 用于读取握手包和后续请求帧（两者格式相同）
func readFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, fmt.Errorf("read frame length: %w", err)
	}
	if n > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read frame payload: %w", err)
	}
	return buf, nil
}

// writeRespFrame 写回响应帧: [status:1字节][4字节BE长度][payload]
// 与客户端 frame_recv() 的格式对应
func writeRespFrame(w io.Writer, status byte, payload []byte) error {
	if _, err := w.Write([]byte{status}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// parseHandshake 解析握手包二进制数据
//
// 布局:
//
//	Magic(2) + Version(1) + UUIDLen(1) + UUID(var)
//	+ AddrFamily(1) + Port(2 BE) + IP(4 or 16)
func parseHandshake(data []byte) (*Handshake, error) {
	if len(data) < 7 {
		return nil, fmt.Errorf("handshake too short: %d bytes", len(data))
	}
	off := 0

	// Magic
	if data[0] != Magic0 || data[1] != Magic1 {
		return nil, fmt.Errorf("bad magic: 0x%02x 0x%02x", data[0], data[1])
	}
	off = 2

	// Version
	if data[off] != Version {
		return nil, fmt.Errorf("unsupported version: %d", data[off])
	}
	off++

	// UUID
	uuidLen := int(data[off])
	off++
	if off+uuidLen > len(data) {
		return nil, fmt.Errorf("uuid overflows packet")
	}
	uuid := string(data[off : off+uuidLen])
	off += uuidLen

	// 地址族
	if off >= len(data) {
		return nil, fmt.Errorf("missing addr family")
	}
	family := data[off]
	off++

	// 端口
	if off+2 > len(data) {
		return nil, fmt.Errorf("missing port")
	}
	port := binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	// IP
	var ip string
	switch family {
	case AddrIPv4:
		if off+4 > len(data) {
			return nil, fmt.Errorf("ipv4 addr too short")
		}
		ip = net.IP(data[off : off+4]).String()
	case AddrIPv6:
		if off+16 > len(data) {
			return nil, fmt.Errorf("ipv6 addr too short")
		}
		ip = net.IP(data[off : off+16]).String()
	default:
		return nil, fmt.Errorf("unknown addr family: %d", family)
	}

	return &Handshake{
		UUID:       uuid,
		AddrFamily: family,
		Port:       port,
		IP:         ip,
		Target:     net.JoinHostPort(ip, fmt.Sprintf("%d", port)),
	}, nil
}
