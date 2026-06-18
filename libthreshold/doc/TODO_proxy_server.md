# TODO: 代理服务端开发

## 背景

libthreshold 客户端库（libthreshold.so）已完成，能通过 LD_PRELOAD 劫持任意 C 程序的 connect() 调用，
将流量重定向到代理服务器。但目前缺少代理服务端，导致所有被劫持的连接都会失败。

## 当前状态

- ✅ libthreshold.so 客户端库（已编译通过）
- ✅ 测试客户端 test_client（已验证 hook 生效）
- ✅ 测试证书生成脚本 certs/generate.sh
- ❌ 代理服务端（待开发）

## 代理服务端需要做的事

1. 监听端口（默认 9999），接受 TLS 连接
2. 解析客户端发来的握手包，提取：
   - 设备 UUID
   - 真实目标地址（IP + 端口）
3. 代客户端去连接真实目标
4. 双向转发数据
5. 连接关闭时清理资源

## 架构图

    你的应用 / curl / 任何C程序
         |
         v
    libthreshold.so (LD_PRELOAD 注入)
         |
         | 1. 拦截 connect()
         | 2. 连接代理服务器
         | 3. TLS 加密
         | 4. 发送握手包 (UUID + 目标地址)
         v
    代理服务端 (监听 :9999)
         |
         | 1. 解析握手包
         | 2. 连接真实目标
         | 3. 双向转发
         v
    真实目标服务器

## 协议参考

详见 doc.md 第 8 节 "协议设计（Mode 3）"

- 帧格式: [4字节长度 大端序][Payload]
- 握手包: Magic(0x54 0x48) + Version(0x01) + UUID长度 + UUID + 地址族 + 端口 + IP
- 握手响应: Status(0x00=OK / 0x01=BLOCKED / 0x02=RATE_LIMITED)

## 技术选型建议

- 推荐 Go 语言（项目名 libthreshold 暗示 Threshold 生态可能是 Go 技术栈）
- 或用 C 写一个简单的转发代理做测试验证

## 快速验证方法

代理服务端开发完成后，用以下命令测试：

    # 终端1：启动代理
    ./proxy_server --port 9999

    # 终端2：注入库，curl 测试
    LD_PRELOAD=./build/threshold.so curl http://httpbin.org/ip

    # 预期输出：正常返回目标页面内容，stderr 看到 hook 日志
