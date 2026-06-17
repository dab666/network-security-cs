# 阶段 1：DH 协商 + AES-256-GCM 加密通信

目标：

- TCP Socket 真实 C/S 通信
- Diffie-Hellman 协商出对称密钥
- 使用 AES-256-GCM 加密传输内容
- 支持密钥周期更新（需考虑身份认证与实时性）

本目录当前提供：

- 可编译运行的多线程 TCP 服务端/客户端通信骨架
- 后续将把 DH/AES-GCM 逻辑补齐并接入到收发流程

## 构建与运行

```bash
make
./bin/server --host 0.0.0.0 --port 9000
./bin/client --host 127.0.0.1 --port 9000 --message "hello"
```
