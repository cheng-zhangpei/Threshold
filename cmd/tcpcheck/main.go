// tools/tcpcheck/main.go
package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
)

func main() {
	// 跳过证书验证，只测协议
	conn, err := tls.Dial("tcp", "127.0.0.1:9999", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Println("tls dial failed:", err)
		return
	}
	defer conn.Close()
	fmt.Println("TLS connected!")

	// 构造握手包
	uuid := []byte("test-device-uuid")
	hs := []byte{0x54, 0x48, 0x01, byte(len(uuid))}
	hs = append(hs, uuid...)
	hs = append(hs, 0x01)         // IPv4
	hs = append(hs, 0x1F, 0x90)   // port 8080
	hs = append(hs, 127, 0, 0, 1) // 127.0.0.1

	// 发送帧
	binary.Write(conn, binary.BigEndian, uint32(len(hs)))
	conn.Write(hs)
	fmt.Println("handshake sent")

	// 读握手响应: [status:1][length:4]
	var status byte
	binary.Read(conn, binary.BigEndian, &status)
	var respLen uint32
	binary.Read(conn, binary.BigEndian, &respLen)
	fmt.Printf("handshake response: status=0x%02x len=%d\n", status, respLen)

	if status != 0x00 {
		fmt.Println("handshake rejected!")
		return
	}
	fmt.Println("handshake OK!")

	// 发送 HTTP 请求帧
	httpReq := "GET /api/test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n"
	binary.Write(conn, binary.BigEndian, uint32(len(httpReq)))
	conn.Write([]byte(httpReq))
	fmt.Println("request sent")

	// 读响应帧
	binary.Read(conn, binary.BigEndian, &status)
	binary.Read(conn, binary.BigEndian, &respLen)
	fmt.Printf("response: status=0x%02x len=%d\n", status, respLen)

	if respLen > 0 {
		body := make([]byte, respLen)
		io.ReadFull(conn, body)
		fmt.Printf("--- response ---\n%s\n--- end ---\n", string(body))
	}
}
