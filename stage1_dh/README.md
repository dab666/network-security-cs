# 阶段 1：DH 协商 + AES-256-GCM 加密通信

目标：

- TCP Socket 真实 C/S 通信
- Diffie-Hellman 协商出对称密钥
- 使用 AES-256-GCM 加密传输内容
- 支持密钥周期更新（需考虑身份认证与实时性）

本目录当前提供：

- TCP Socket 客户端/服务端通信
- DH 协商出会话密钥（256-bit）
- AES-256-GCM 加密传输（带完整性校验）
- 客户端可按次数触发周期性密钥更新（rekey）

## 构建与运行

```bash
make
./bin/server --host 0.0.0.0 --port 9000
./bin/client --host 127.0.0.1 --port 9000 --message "hello" --count 3 --rekey-every 1
```
