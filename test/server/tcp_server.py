#!/usr/bin/env python3
import socket
import threading
import time

def handle_client(conn, addr):
    print(f"\n{'='*60}")
    print(f"[TCP] New connection from {addr[0]}:{addr[1]}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"[TCP] Received {len(data)} bytes: {data[:200]}...")
            # 回显 Pong
            response = f"Pong from TCP server at {time.time()}\n".encode()
            conn.send(response)
            print(f"[TCP] Sent Pong")
    except Exception as e:
        print(f"[TCP] Error: {e}")
    finally:
        conn.close()
        print(f"[TCP] Connection from {addr[0]}:{addr[1]} closed")
        print(f"{'='*60}\n")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9090))
    server.listen(5)
    print("TCP Pong server listening on port 9090")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    main()